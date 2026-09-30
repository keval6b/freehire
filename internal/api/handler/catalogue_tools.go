package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/strelov1/freehire/internal/application/appevent"
	"github.com/strelov1/freehire/internal/application/jobtracking"
	"github.com/strelov1/freehire/internal/application/userjob"
	"github.com/strelov1/freehire/internal/job/jobview"
	"github.com/strelov1/freehire/internal/platform/db"
	"github.com/strelov1/freehire/internal/search/search"
)

// catalogueTools is the catalogue and the caller's own tracking, shared by the
// in-app assistant and the authenticated MCP server. One implementation, so the
// two cannot disagree about a posting or a bookmark. Tool registration stays
// with each surface: the assistant speaks to the in-app model, the MCP server
// to an external host.
type catalogueTools struct {
	search   *searchHandlers
	resume   *resumeHandlers
	tracking *trackingHandlers
	queries  *db.Queries
}

func (h *assistantHandlers) catalogue() catalogueTools {
	return catalogueTools{search: h.search, resume: h.resume, tracking: h.tracking, queries: h.queries}
}

func (h *accountMCPHandlers) catalogue() catalogueTools {
	return catalogueTools{search: h.search, resume: h.resume, tracking: h.tracking, queries: h.queries}
}

func (c catalogueTools) facets(ctx context.Context, filters assistantFilterArgs) (any, error) {
	if c.search == nil || c.search.facets == nil {
		return nil, errors.New("search is not available")
	}
	vals, err := filters.values()
	if err != nil {
		return nil, err
	}
	res, err := c.search.facets.FacetCounts(ctx, search.FacetParams{
		Filter: search.FilterFromValues(vals),
		Facets: facetAttributes(),
	})
	if err != nil {
		return nil, err
	}
	return facetView(res), nil
}

// searchJobs hits the same index the public search does and rehydrates each
// result's full description. An empty query has no relevance to rank by, so it
// browses the freshest first — the same rule the HTTP search applies.
func (c catalogueTools) searchJobs(ctx context.Context, query string, filters assistantFilterArgs, limit, offset int) (any, error) {
	if c.search == nil || c.search.search == nil {
		return nil, errors.New("search is not available")
	}
	vals, err := filters.values()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = assistantDefaultSearchLimit
	}
	limit = min(limit, assistantMaxSearchLimit)
	offset = max(offset, 0)

	var order []string
	if query == "" {
		order = []string{"posted_at:desc"}
	}
	res, err := c.search.search.Search(ctx, search.SearchParams{
		Query:  query,
		Filter: search.FilterFromValues(vals),
		Sort:   order,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, err
	}
	if err := c.search.hydrateDescriptions(ctx, res.Hits); err != nil {
		return nil, err
	}
	jobs := make([]jobview.Job, len(res.Hits))
	for i, hit := range res.Hits {
		hit.Description = formatDescription(hit.Description, "markdown")
		jobs[i] = hit.Job
	}
	return map[string]any{"total": res.Total, "limit": limit, "offset": offset, "jobs": jobs}, nil
}

// job reads one posting by its public slug. publishedOnly is the agent
// visibility predicate (open, canonical, not private): the remote MCP host
// republishes what it is handed, so a private posting must not reach it. The
// in-app assistant leaves it off, because that session is the person reading
// their own board.
func (c catalogueTools) job(ctx context.Context, slug string, publishedOnly bool) (any, error) {
	if slug == "" {
		return nil, errors.New("slug is required")
	}
	row, err := c.queries.GetJobBySlug(ctx, slug)
	if err != nil {
		if publishedOnly && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("no vacancy with slug %q", slug)
	}
	if publishedOnly && !publishedToAgents(row) {
		return nil, fmt.Errorf("no vacancy with slug %q", slug)
	}
	view, err := jobview.FromRow(row)
	if err != nil {
		return nil, err
	}
	view.Description = formatDescription(view.Description, "markdown")
	return view, nil
}

func (c catalogueTools) company(ctx context.Context, slug string) (any, error) {
	if slug == "" {
		return nil, errors.New("slug is required")
	}
	company, err := c.queries.GetCompany(ctx, slug)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("no company with slug %q", slug)
	}
	jobs, err := c.queries.ListJobsByCompany(ctx, db.ListJobsByCompanyParams{
		CompanySlug: slug,
		Limit:       assistantDefaultSearchLimit,
	})
	if err != nil {
		return nil, err
	}
	views, err := jobview.FromRows(jobs)
	if err != nil {
		return nil, err
	}
	return map[string]any{"company": companyViewFrom(company), "jobs": views}, nil
}

func (c catalogueTools) marketFit(ctx context.Context, skills []string, filters assistantFilterArgs) (any, error) {
	if c.resume == nil || c.resume.facets == nil {
		return nil, errors.New("search is not available")
	}
	skills = nonEmptyStrings(skills)
	if len(skills) == 0 {
		return nil, errors.New("skills is required — list the canonical slugs to measure")
	}
	if len(skills) > maxCoverageSkills {
		return nil, fmt.Errorf("too many skills (max %d)", maxCoverageSkills)
	}
	vals, err := filters.values()
	if err != nil {
		return nil, err
	}
	// The measured skills must not also filter the role, or coverage would be
	// 100% by construction — the same reason the HTTP endpoint strips them.
	stripSkillParams(vals)
	v, err := c.resume.coverageFor(ctx, search.FilterFromValues(vals), skills, skills, nil, skills)
	if err != nil {
		return nil, err
	}
	// Coherence is a CV-section metric; a flat skill list has no sections.
	v.CoherencePercent = 0
	return v, nil
}

func (c catalogueTools) saveJob(ctx context.Context, userID int64, slug string) (any, error) {
	return c.slugAction(ctx, userID, slug, func(ctx context.Context, userID int64, slug string) (jobtracking.Interaction, error) {
		return c.tracking.tracking.SaveJob(ctx, userID, slug)
	})
}

func (c catalogueTools) unsaveJob(ctx context.Context, userID int64, slug string) (any, error) {
	return c.slugAction(ctx, userID, slug, func(ctx context.Context, userID int64, slug string) (jobtracking.Interaction, error) {
		return c.tracking.tracking.Unsave(ctx, userID, slug)
	})
}

func (c catalogueTools) applyJob(ctx context.Context, userID int64, slug string) (any, error) {
	return c.slugAction(ctx, userID, slug, func(ctx context.Context, userID int64, slug string) (jobtracking.Interaction, error) {
		// The caller acts as the account, but the ledger records who observed
		// the application, and that was the agent.
		return c.tracking.tracking.MarkApplied(ctx, userID, slug, appevent.SourceAssistant)
	})
}

func (c catalogueTools) slugAction(ctx context.Context, userID int64, slug string, act func(context.Context, int64, string) (jobtracking.Interaction, error)) (any, error) {
	if slug == "" {
		return nil, errors.New("slug is required")
	}
	if c.tracking == nil || c.tracking.tracking == nil {
		return nil, errors.New("job tracking is not available")
	}
	res, err := act(ctx, userID, slug)
	if err != nil {
		return nil, trackingToolError(slug, err)
	}
	return toResponse(res), nil
}

func (c catalogueTools) trackJob(ctx context.Context, userID int64, slug string, stage, note *string) (any, error) {
	if slug == "" {
		return nil, errors.New("slug is required")
	}
	if stage == nil && note == nil {
		return nil, errors.New("nothing to change — pass a stage, a note, or both")
	}
	// Reject an invented stage here rather than letting the service's generic
	// error come back: the model needs to see the closed vocabulary to retry.
	if stage != nil && !userjob.ValidStage(*stage) {
		return nil, fmt.Errorf("unknown stage %q — valid stages are: %s", *stage, strings.Join(userjob.Stages, ", "))
	}
	if c.tracking == nil || c.tracking.tracking == nil {
		return nil, errors.New("job tracking is not available")
	}
	res, err := c.tracking.tracking.Track(ctx, userID, slug, stage, note, appevent.SourceAssistant)
	if err != nil {
		return nil, trackingToolError(slug, err)
	}
	return toResponse(res), nil
}

func (c catalogueTools) myJobs(ctx context.Context, userID int64, filter string, limit int) (any, error) {
	if c.tracking == nil || c.tracking.tracking == nil {
		return nil, errors.New("job tracking is not available")
	}
	if limit <= 0 {
		limit = assistantDefaultSearchLimit
	}
	limit = min(limit, assistantMaxSearchLimit)
	listing, err := c.tracking.tracking.ListTracked(ctx, userID, filter, int32(limit), 0)
	if errors.Is(err, jobtracking.ErrInvalidFilter) {
		return nil, fmt.Errorf("unknown filter %q — use all, viewed, saved, applied, board or dismissed", filter)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"filter": string(listing.Filter),
		"total":  listing.Total(),
		"jobs":   listing.Items,
	}, nil
}
