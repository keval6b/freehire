package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/strelov1/freehire/internal/identity/auth"
	"github.com/strelov1/freehire/internal/identity/auth/mcpoauth"
	"github.com/strelov1/freehire/internal/platform/db"
)

// emptyOAuthStore declines every lookup. The challenge test only needs
// Authenticate to refuse a token; the other methods exist so New can take it.
type emptyOAuthStore struct{}

func (emptyOAuthStore) UpsertOAuthClient(context.Context, db.UpsertOAuthClientParams) error {
	return nil
}
func (emptyOAuthStore) GetOAuthClient(context.Context, string) (db.GetOAuthClientRow, error) {
	return db.GetOAuthClientRow{}, pgx.ErrNoRows
}
func (emptyOAuthStore) InsertOAuthAuthCode(context.Context, db.InsertOAuthAuthCodeParams) error {
	return nil
}
func (emptyOAuthStore) GetOAuthAuthCode(context.Context, string) (db.GetOAuthAuthCodeRow, error) {
	return db.GetOAuthAuthCodeRow{}, pgx.ErrNoRows
}
func (emptyOAuthStore) ConsumeOAuthAuthCode(context.Context, string) (int64, error) { return 0, nil }
func (emptyOAuthStore) InsertOAuthGrant(context.Context, db.InsertOAuthGrantParams) (db.InsertOAuthGrantRow, error) {
	return db.InsertOAuthGrantRow{}, nil
}
func (emptyOAuthStore) RotateOAuthGrantTokens(context.Context, db.RotateOAuthGrantTokensParams) (db.RotateOAuthGrantTokensRow, error) {
	return db.RotateOAuthGrantTokensRow{}, pgx.ErrNoRows
}
func (emptyOAuthStore) UseOAuthGrantByAccessHash(context.Context, pgtype.Text) (db.UseOAuthGrantByAccessHashRow, error) {
	return db.UseOAuthGrantByAccessHashRow{}, pgx.ErrNoRows
}
func (emptyOAuthStore) GetOAuthGrantByRefreshHash(context.Context, pgtype.Text) (db.GetOAuthGrantByRefreshHashRow, error) {
	return db.GetOAuthGrantByRefreshHashRow{}, pgx.ErrNoRows
}
func (emptyOAuthStore) ListOAuthGrantsByUser(context.Context, int64) ([]db.ListOAuthGrantsByUserRow, error) {
	return nil, nil
}
func (emptyOAuthStore) RevokeOAuthGrant(context.Context, db.RevokeOAuthGrantParams) (int64, error) {
	return 0, nil
}
func (emptyOAuthStore) GetUserTokenVersion(context.Context, int64) (int32, error) { return 0, nil }

func TestOAuthConsentDecisionIsPostOnly(t *testing.T) {
	h := &authHandlers{frontendOrigin: "https://freehire.test"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oauth/authorize?decision=allow&client_id=fhc_x&redirect_uri=http://127.0.0.1/cb", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "session"})
	id, err := h.decideOAuthConsent(rec, req)
	if err != nil || id != "" {
		t.Fatalf("GET decision=allow returned %q %v", id, err)
	}
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "https://freehire.test/oauth/mcp?") {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/oauth/authorize", strings.NewReader("decision=deny"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	id, err = h.decideOAuthConsent(rec, req)
	if id != "" || !errors.Is(err, oauth2errors.ErrAccessDenied) {
		t.Fatalf("POST deny returned %q %v", id, err)
	}
}

func TestAccountMCPMissingTokenChallenges(t *testing.T) {
	srv := mcpoauth.New(mcpoauth.Config{Origin: "https://freehire.test", Store: emptyOAuthStore{}})
	var ran bool
	h := accountMCPHTTP(srv, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		ran = true
	}))

	for _, header := range []string{"", "Bearer fho_not-a-grant", "Bearer fhk_an-api-key"} {
		ran = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/account", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%q status = %d, want 401", header, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != srv.WWWAuthenticate() {
			t.Fatalf("%q challenge = %q", header, got)
		}
		if ran {
			t.Fatalf("%q reached a tool", header)
		}
	}
}

func TestOAuthGrantRoutesAreCookieOnly(t *testing.T) {
	app := fiber.New()
	(&authHandlers{}).register(app.Group("/api/v1"), middleware{
		cookie:         namedGate("cookie"),
		optionalCookie: namedGate("optionalCookie"),
		cvKey:          namedGate("cvKey"),
		key:            namedGate("key"),
	})

	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/me/oauth-grants"},
		{http.MethodDelete, "/api/v1/me/oauth-grants/1"},
		{http.MethodGet, "/api/v1/me/api-keys"},
	} {
		req := httptest.NewRequestWithContext(context.Background(), r.method, r.path, nil)
		req.Header.Set("Authorization", "Bearer fho_grant")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("%s %s: %v", r.method, r.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := string(body); got != "cookie" {
			t.Errorf("%s %s with a grant bearer is gated by %q, want cookie", r.method, r.path, got)
		}
	}
}
