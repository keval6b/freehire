package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/jackc/pgx/v5"

	"github.com/strelov1/freehire/internal/api/accountmcp"
	"github.com/strelov1/freehire/internal/application/appevent"
	"github.com/strelov1/freehire/internal/application/jobtracking"
	"github.com/strelov1/freehire/internal/identity/auth/mcpoauth"
	"github.com/strelov1/freehire/internal/job/jobview"
	"github.com/strelov1/freehire/internal/platform/db"
	"github.com/strelov1/freehire/internal/search/search"
)

// accountMCPHandlers is the authenticated MCP server. Tools call the same
// services the HTTP handlers use, with the account id from the OAuth grant.
type accountMCPHandlers struct {
	oauth    *mcpoauth.Server
	search   *searchHandlers
	resume   *resumeHandlers
	tracking *trackingHandlers
	queries  *db.Queries
}

func (h *accountMCPHandlers) register(api fiber.Router, mw middleware) {
	if h == nil {
		return
	}
	// The limiter is mounted even when the authorization server is not
	// configured, so a misconfigured process still answers this path and the
	// public-read guard sees the same chain production uses. A missing server
	// never reaches a tool.
	next := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"unavailable"}`))
	}))
	if h.oauth != nil {
		next = accountMCPHTTP(h.oauth, accountmcp.Handler(h))
	}
	api.All("/mcp/account", agentSearchLimiter(mw.throttler), adaptor.HTTPHandler(next))
}

func (h *accountMCPHandlers) WhoAmI(ctx context.Context, userID int64) (any, error) {
	user, err := h.queries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": user.ID, "email": user.Email}, nil
}

func (h *accountMCPHandlers) Facets(ctx context.Context, _ int64, filters map[string][]string) (any, error) {
	if h.search == nil || h.search.facets == nil {
		return nil, errors.New("search is not available")
	}
	vals, err := assistantFilterArgs(filters).values()
	if err != nil {
		return nil, err
	}
	res, err := h.search.facets.FacetCounts(ctx, search.FacetParams{
		Filter: search.FilterFromValues(vals),
		Facets: facetAttributes(),
	})
	if err != nil {
		return nil, err
	}
	return facetView(res), nil
}

func (h *accountMCPHandlers) Search(ctx context.Context, _ int64, query string, limit int, filters map[string][]string) (any, error) {
	if h.search == nil || h.search.search == nil {
		return nil, errors.New("search is not available")
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 20 {
		limit = 20
	}
	vals, err := assistantFilterArgs(filters).values()
	if err != nil {
		return nil, err
	}
	res, err := h.search.search.Search(ctx, search.SearchParams{
		Query:  query,
		Filter: search.FilterFromValues(vals),
		Limit:  limit,
	})
	if err != nil {
		return nil, err
	}
	if err := h.search.hydrateDescriptions(ctx, res.Hits); err != nil {
		return nil, err
	}
	jobs := make([]jobview.Job, len(res.Hits))
	for i, hit := range res.Hits {
		hit.Description = formatDescription(hit.Description, "markdown")
		jobs[i] = hit.Job
	}
	return map[string]any{"total": res.Total, "jobs": jobs}, nil
}

func (h *accountMCPHandlers) Job(ctx context.Context, _ int64, slug string) (any, error) {
	if slug == "" {
		return nil, errors.New("slug is required")
	}
	row, err := h.queries.GetJobBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("no posting with slug %q", slug)
		}
		return nil, err
	}
	if !publishedToAgents(row) {
		return nil, fmt.Errorf("no posting with slug %q", slug)
	}
	view, err := jobview.FromRow(row)
	if err != nil {
		return nil, err
	}
	view.Description = formatDescription(view.Description, "markdown")
	return view, nil
}

func (h *accountMCPHandlers) Company(ctx context.Context, _ int64, slug string) (any, error) {
	if slug == "" {
		return nil, errors.New("slug is required")
	}
	company, err := h.queries.GetCompany(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("no company with slug %q", slug)
		}
		return nil, err
	}
	jobs, err := h.queries.ListJobsByCompany(ctx, db.ListJobsByCompanyParams{CompanySlug: slug, Limit: 10})
	if err != nil {
		return nil, err
	}
	views, err := jobview.FromRows(jobs)
	if err != nil {
		return nil, err
	}
	return map[string]any{"company": companyViewFrom(company), "jobs": views}, nil
}

func (h *accountMCPHandlers) MarketFit(ctx context.Context, _ int64, skills []string, filters map[string][]string) (any, error) {
	if h.resume == nil || h.resume.facets == nil {
		return nil, errors.New("search is not available")
	}
	skills = nonEmptyStrings(skills)
	if len(skills) == 0 {
		return nil, errors.New("skills is required")
	}
	if len(skills) > maxCoverageSkills {
		return nil, fmt.Errorf("too many skills (max %d)", maxCoverageSkills)
	}
	vals, err := assistantFilterArgs(filters).values()
	if err != nil {
		return nil, err
	}
	stripSkillParams(vals)
	v, err := h.resume.coverageFor(ctx, search.FilterFromValues(vals), skills, skills, nil, skills)
	if err != nil {
		return nil, err
	}
	v.CoherencePercent = 0
	return v, nil
}

func (h *accountMCPHandlers) Save(ctx context.Context, userID int64, slug string) (any, error) {
	return h.track(ctx, userID, slug, func() (jobtracking.Interaction, error) {
		return h.tracking.tracking.SaveJob(ctx, userID, slug)
	})
}

func (h *accountMCPHandlers) Unsave(ctx context.Context, userID int64, slug string) (any, error) {
	return h.track(ctx, userID, slug, func() (jobtracking.Interaction, error) {
		return h.tracking.tracking.Unsave(ctx, userID, slug)
	})
}

func (h *accountMCPHandlers) Apply(ctx context.Context, userID int64, slug string) (any, error) {
	return h.track(ctx, userID, slug, func() (jobtracking.Interaction, error) {
		return h.tracking.tracking.MarkApplied(ctx, userID, slug, appevent.SourceAssistant)
	})
}

func (h *accountMCPHandlers) Stage(ctx context.Context, userID int64, slug, stage, note string) (any, error) {
	return h.track(ctx, userID, slug, func() (jobtracking.Interaction, error) {
		var stagePtr, notePtr *string
		if stage != "" {
			stagePtr = &stage
		}
		if note != "" {
			notePtr = &note
		}
		return h.tracking.tracking.Track(ctx, userID, slug, stagePtr, notePtr, appevent.SourceAssistant)
	})
}

func (h *accountMCPHandlers) Note(ctx context.Context, userID int64, slug, note string) (any, error) {
	return h.Stage(ctx, userID, slug, "", note)
}

func (h *accountMCPHandlers) track(ctx context.Context, _ int64, slug string, act func() (jobtracking.Interaction, error)) (any, error) {
	if slug == "" {
		return nil, errors.New("slug is required")
	}
	if h.tracking == nil || h.tracking.tracking == nil {
		return nil, errors.New("job tracking is not available")
	}
	res, err := act()
	if err != nil {
		return nil, trackingToolError(slug, err)
	}
	return toResponse(res), nil
}

func (h *accountMCPHandlers) My(ctx context.Context, userID int64) (any, error) {
	if h.tracking == nil || h.tracking.tracking == nil {
		return nil, errors.New("job tracking is not available")
	}
	listing, err := h.tracking.tracking.ListTracked(ctx, userID, string(jobtracking.FilterBoard), 20, 0)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(listing.Items))
	for _, item := range listing.Items {
		row := map[string]any{
			"id": item.ID, "company": item.CompanySlug, "title": item.RoleTitle,
		}
		if item.Job != nil {
			row["slug"] = item.Job.PublicSlug
		}
		if item.Stage != nil {
			row["stage"] = *item.Stage
		}
		items = append(items, row)
	}
	return map[string]any{"jobs": items, "total": listing.Total()}, nil
}
