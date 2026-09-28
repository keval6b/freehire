// Package accountmcp is the authenticated MCP server. Hosts connect with an
// OAuth grant; the tools act as that account. The public ChatGPT server
// (internal/api/mcpapp) and the OJCP server stay anonymous.
package accountmcp

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	version = "1.0"

	instructions = "freehire account tools. Search the catalogue, read one posting " +
		"or employer, score skills against the market, and manage this account's " +
		"saved jobs and applications. Geography filters union. You act only as the " +
		"signed-in account."
)

type ctxKey struct{}

// WithUser returns ctx carrying the account the grant authenticated.
func WithUser(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, ctxKey{}, userID)
}

func userID(ctx context.Context) (int64, error) {
	id, ok := ctx.Value(ctxKey{}).(int64)
	if !ok || id == 0 {
		return 0, errNoUser
	}
	return id, nil
}

// Service is the account the tools act for. The HTTP handlers implement it
// with the same services the website uses. A missing user in the context is
// the caller's bug: the bearer check rejects that request before a tool runs.
type Service interface {
	WhoAmI(ctx context.Context, userID int64) (any, error)
	Facets(ctx context.Context, userID int64, filters map[string][]string) (any, error)
	Search(ctx context.Context, userID int64, query string, limit int, filters map[string][]string) (any, error)
	Job(ctx context.Context, userID int64, slug string) (any, error)
	Company(ctx context.Context, userID int64, slug string) (any, error)
	MarketFit(ctx context.Context, userID int64, skills []string, filters map[string][]string) (any, error)
	Save(ctx context.Context, userID int64, slug string) (any, error)
	Unsave(ctx context.Context, userID int64, slug string) (any, error)
	Apply(ctx context.Context, userID int64, slug string) (any, error)
	Stage(ctx context.Context, userID int64, slug, stage, note string) (any, error)
	Note(ctx context.Context, userID int64, slug, note string) (any, error)
	My(ctx context.Context, userID int64) (any, error)
}

// Handler serves the tools over stateless streamable HTTP.
func Handler(s Service) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return newServer(s)
	}, &mcp.StreamableHTTPOptions{Stateless: true})
}

func newServer(s Service) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "freehire", Version: version}, &mcp.ServerOptions{Instructions: instructions})
	addRead(server, "whoami", "Who am I", "The signed-in account: id and email.", func(ctx context.Context, _ struct{}) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.WhoAmI(ctx, id)
	})
	addRead(server, "facets", "List filters", "Live filter vocabulary and counts. Call this before filtering a search.", func(ctx context.Context, in filterInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Facets(ctx, id, in.Filters)
	})
	addRead(server, "search", "Search jobs", "Search open IT postings. Geography filters union. Returns previews; call job for one posting in full.", func(ctx context.Context, in searchInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Search(ctx, id, in.Query, in.Limit, in.Filters)
	})
	addRead(server, "job", "Read one job", "Read one posting in full by its public slug.", func(ctx context.Context, in slugInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Job(ctx, id, in.Slug)
	})
	addRead(server, "company", "Read one employer", "Read one employer and a page of its open postings, by company slug.", func(ctx context.Context, in slugInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Company(ctx, id, in.Slug)
	})
	addRead(server, "market_fit", "Score skills against the market", "What share of the filtered open vacancies list at least one of these skills, and which missing skills unlock the most.", func(ctx context.Context, in marketInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.MarketFit(ctx, id, in.Skills, in.Filters)
	})
	addWrite(server, "save", "Save a job", "Bookmark a vacancy. Idempotent.", func(ctx context.Context, in slugInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Save(ctx, id, in.Slug)
	})
	addWrite(server, "unsave", "Unsave a job", "Remove a bookmark. Idempotent.", func(ctx context.Context, in slugInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Unsave(ctx, id, in.Slug)
	})
	addWrite(server, "apply", "Mark applied", "Record that the account applied. This does not submit anything to the employer.", func(ctx context.Context, in slugInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Apply(ctx, id, in.Slug)
	})
	addWrite(server, "stage", "Set application stage", "Set the stage and, optionally, a note on a tracked vacancy.", func(ctx context.Context, in stageInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Stage(ctx, id, in.Slug, in.Stage, in.Note)
	})
	addWrite(server, "note", "Set a note", "Store a free-text note against a tracked vacancy.", func(ctx context.Context, in noteInput) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.Note(ctx, id, in.Slug, in.Note)
	})
	addRead(server, "my", "List my jobs", "Vacancies this account has saved, applied to, or staged.", func(ctx context.Context, _ struct{}) (any, error) {
		id, err := userID(ctx)
		if err != nil {
			return nil, err
		}
		return s.My(ctx, id)
	})
	return server
}

type filterInput struct {
	Filters map[string][]string `json:"filters,omitempty"`
}

type searchInput struct {
	Query   string              `json:"q,omitempty"`
	Limit   int                 `json:"limit,omitempty"`
	Filters map[string][]string `json:"filters,omitempty"`
}

type slugInput struct {
	Slug string `json:"slug"`
}

type marketInput struct {
	Skills  []string            `json:"skills"`
	Filters map[string][]string `json:"filters,omitempty"`
}

type stageInput struct {
	Slug  string `json:"slug"`
	Stage string `json:"stage,omitempty"`
	Note  string `json:"note,omitempty"`
}

type noteInput struct {
	Slug string `json:"slug"`
	Note string `json:"note"`
}

func addRead[In any](server *mcp.Server, name, title, description string, fn func(context.Context, In) (any, error)) {
	ro := true
	open := true
	dest := false
	mcp.AddTool(server, &mcp.Tool{
		Name: name, Title: title, Description: description,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: ro, OpenWorldHint: &open, DestructiveHint: &dest},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		return call(ctx, in, fn)
	})
}

func addWrite[In any](server *mcp.Server, name, title, description string, fn func(context.Context, In) (any, error)) {
	open := true
	dest := false
	mcp.AddTool(server, &mcp.Tool{
		Name: name, Title: title, Description: description,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, OpenWorldHint: &open, DestructiveHint: &dest},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		return call(ctx, in, fn)
	})
}

func call[In any](ctx context.Context, in In, fn func(context.Context, In) (any, error)) (*mcp.CallToolResult, any, error) {
	out, err := fn(ctx, in)
	if err == nil {
		return nil, out, nil
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}, nil, nil
}
