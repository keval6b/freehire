package handler

import (
	"context"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"

	"github.com/strelov1/freehire/internal/api/accountmcp"
	"github.com/strelov1/freehire/internal/application/jobtracking"
	"github.com/strelov1/freehire/internal/identity/auth/mcpoauth"
	"github.com/strelov1/freehire/internal/platform/db"
)

// accountMCPHandlers mounts the authenticated MCP server. The tools are this
// package's catalogueTools — the same functions the in-app assistant calls —
// registered here because the MCP package cannot import the handler.
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
		next = accountMCPHTTP(h.oauth, accountmcp.Handler(h.mount))
	}
	api.All("/mcp/account", agentSearchLimiter(mw.throttler), adaptor.HTTPHandler(next))
}

func (h *accountMCPHandlers) mount(server *accountmcp.Server) {
	c := h.catalogue()
	accountmcp.AddRead(server, "whoami", "Who am I", "The signed-in account: id and email.",
		func(ctx context.Context, userID int64, _ struct{}) (any, error) {
			return h.whoAmI(ctx, userID)
		})
	accountmcp.AddRead(server, "facets", "List filters", "Live filter vocabulary and counts. Call this before filtering a search.",
		func(ctx context.Context, _ int64, in mcpFilterInput) (any, error) {
			return c.facets(ctx, in.Filters)
		})
	accountmcp.AddRead(server, "search", "Search jobs", "Search open IT postings. Geography filters union. Returns previews; call job for one posting in full.",
		func(ctx context.Context, _ int64, in mcpSearchInput) (any, error) {
			return c.searchJobs(ctx, in.Query, in.Filters, in.Limit, 0)
		})
	accountmcp.AddRead(server, "job", "Read one job", "Read one posting in full by its public slug.",
		func(ctx context.Context, _ int64, in mcpSlugInput) (any, error) {
			return c.job(ctx, in.Slug, true)
		})
	accountmcp.AddRead(server, "company", "Read one employer", "Read one employer and a page of its open postings, by company slug.",
		func(ctx context.Context, _ int64, in mcpSlugInput) (any, error) {
			return c.company(ctx, in.Slug)
		})
	accountmcp.AddRead(server, "market_fit", "Score skills against the market", "What share of the filtered open vacancies list at least one of these skills, and which missing skills unlock the most.",
		func(ctx context.Context, _ int64, in mcpMarketInput) (any, error) {
			return c.marketFit(ctx, in.Skills, in.Filters)
		})
	accountmcp.AddWrite(server, "save", "Save a job", "Bookmark a vacancy. Idempotent.",
		func(ctx context.Context, userID int64, in mcpSlugInput) (any, error) {
			return c.saveJob(ctx, userID, in.Slug)
		})
	accountmcp.AddWrite(server, "unsave", "Unsave a job", "Remove a bookmark. Idempotent.",
		func(ctx context.Context, userID int64, in mcpSlugInput) (any, error) {
			return c.unsaveJob(ctx, userID, in.Slug)
		})
	accountmcp.AddWrite(server, "apply", "Mark applied", "Record that the account applied. This does not submit anything to the employer.",
		func(ctx context.Context, userID int64, in mcpSlugInput) (any, error) {
			return c.applyJob(ctx, userID, in.Slug)
		})
	accountmcp.AddWrite(server, "stage", "Set application stage", "Set the stage and, optionally, a note on a tracked vacancy.",
		func(ctx context.Context, userID int64, in mcpStageInput) (any, error) {
			return c.trackJob(ctx, userID, in.Slug, nonempty(in.Stage), nonempty(in.Note))
		})
	accountmcp.AddWrite(server, "note", "Set a note", "Store a free-text note against a tracked vacancy.",
		func(ctx context.Context, userID int64, in mcpNoteInput) (any, error) {
			return c.trackJob(ctx, userID, in.Slug, nil, nonempty(in.Note))
		})
	accountmcp.AddRead(server, "my", "List my jobs", "Vacancies this account has saved, applied to, or staged.",
		func(ctx context.Context, userID int64, _ struct{}) (any, error) {
			return c.myJobs(ctx, userID, string(jobtracking.FilterBoard), assistantMaxSearchLimit)
		})
}

func nonempty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (h *accountMCPHandlers) whoAmI(ctx context.Context, userID int64) (any, error) {
	user, err := h.queries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": user.ID, "email": user.Email}, nil
}

type mcpFilterInput struct {
	Filters assistantFilterArgs `json:"filters,omitempty"`
}

type mcpSearchInput struct {
	Query   string              `json:"q,omitempty"`
	Limit   int                 `json:"limit,omitempty"`
	Filters assistantFilterArgs `json:"filters,omitempty"`
}

type mcpSlugInput struct {
	Slug string `json:"slug"`
}

type mcpMarketInput struct {
	Skills  []string            `json:"skills"`
	Filters assistantFilterArgs `json:"filters,omitempty"`
}

type mcpStageInput struct {
	Slug  string `json:"slug"`
	Stage string `json:"stage,omitempty"`
	Note  string `json:"note,omitempty"`
}

type mcpNoteInput struct {
	Slug string `json:"slug"`
	Note string `json:"note"`
}
