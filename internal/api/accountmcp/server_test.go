package accountmcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolWithoutAUserDoesNotCallTheTool(t *testing.T) {
	var called bool
	ctx := context.Background()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := newServer(func(s *Server) {
		AddRead(s, "whoami", "Who am I", "The signed-in account.", func(context.Context, int64, struct{}) (any, error) {
			called = true
			return map[string]any{"id": 1}, nil
		})
	}).inner.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if called {
		t.Fatal("the tool ran without an account")
	}
	if res == nil || !res.IsError {
		t.Fatalf("result = %#v, want an error the model can read", res)
	}

	// The HTTP handler still answers a protocol request; the bearer check in
	// front of it is what returns 401. This test holds the inner gate.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/account", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	Handler(nil).ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("the tool server answered 401; that challenge belongs to the bearer check in front of it")
	}
}
