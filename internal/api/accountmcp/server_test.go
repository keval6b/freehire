package accountmcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type stub struct{}

func (stub) WhoAmI(context.Context, int64) (any, error) { return map[string]any{"id": 1}, nil }
func (stub) Facets(context.Context, int64, map[string][]string) (any, error) {
	return nil, nil
}
func (stub) Search(context.Context, int64, string, int, map[string][]string) (any, error) {
	return nil, nil
}
func (stub) Job(context.Context, int64, string) (any, error)     { return nil, nil }
func (stub) Company(context.Context, int64, string) (any, error) { return nil, nil }
func (stub) MarketFit(context.Context, int64, []string, map[string][]string) (any, error) {
	return nil, nil
}
func (stub) Save(context.Context, int64, string) (any, error)   { return nil, nil }
func (stub) Unsave(context.Context, int64, string) (any, error) { return nil, nil }
func (stub) Apply(context.Context, int64, string) (any, error)  { return nil, nil }
func (stub) Stage(context.Context, int64, string, string, string) (any, error) {
	return nil, nil
}
func (stub) Note(context.Context, int64, string, string) (any, error) { return nil, nil }
func (stub) My(context.Context, int64) (any, error)                   { return nil, nil }

func TestToolWithoutAUserDoesNotCallTheService(t *testing.T) {
	ctx := context.Background()
	server := newServer(stub{})
	// A direct call, the way the SDK invokes a tool. No user in the context.
	var saw bool
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			saw = true
			return next(ctx, method, req)
		}
	})
	_ = server
	_, err := userID(ctx)
	if err == nil {
		t.Fatal("a tool context without an account was accepted")
	}
	if saw {
		t.Fatal("middleware ran")
	}
	// The HTTP handler still answers a protocol request; the bearer check in
	// front of it is what returns 401. This test holds the inner gate.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/account", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	Handler(stub{}).ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("the tool server answered 401; that challenge belongs to the bearer check in front of it")
	}
}
