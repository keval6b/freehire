// Package accountmcp is the authenticated MCP server. Hosts connect with an
// OAuth grant; the tools act as that account. The public ChatGPT server
// (internal/api/mcpapp) and the OJCP server stay anonymous.
//
// This package is the transport. The handler registers each tool and calls the
// same catalogue and tracking functions the in-app assistant uses. There is no
// second set of search, job, or save operations here.
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

// Server is the MCP server the handler registers tools on. It exists so the
// handler can mount tools without importing the SDK.
type Server struct {
	inner *mcp.Server
}

// Handler serves the tools over stateless streamable HTTP. mount registers
// them on each server the transport builds.
func Handler(mount func(*Server)) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return newServer(mount).inner
	}, &mcp.StreamableHTTPOptions{Stateless: true})
}

func newServer(mount func(*Server)) *Server {
	inner := mcp.NewServer(&mcp.Implementation{Name: "freehire", Version: version}, &mcp.ServerOptions{Instructions: instructions})
	s := &Server{inner: inner}
	if mount != nil {
		mount(s)
	}
	return s
}

// AddRead registers a tool that does not change the account. The account id
// comes from the grant; a request without one never reaches fn.
func AddRead[In any](server *Server, name, title, description string, fn func(context.Context, int64, In) (any, error)) {
	add(server, name, title, description, true, fn)
}

// AddWrite registers a tool that changes the account's own saved jobs or
// application board. It does not submit anything to an employer.
func AddWrite[In any](server *Server, name, title, description string, fn func(context.Context, int64, In) (any, error)) {
	add(server, name, title, description, false, fn)
}

func add[In any](server *Server, name, title, description string, readOnly bool, fn func(context.Context, int64, In) (any, error)) {
	open := true
	dest := false
	mcp.AddTool(server.inner, &mcp.Tool{
		Name: name, Title: title, Description: description,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, OpenWorldHint: &open, DestructiveHint: &dest},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		id, err := userID(ctx)
		if err != nil {
			return toolError(err), nil, nil
		}
		out, err := fn(ctx, id, in)
		if err != nil {
			return toolError(err), nil, nil
		}
		return nil, out, nil
	})
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}
}
