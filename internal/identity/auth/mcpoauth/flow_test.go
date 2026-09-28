package mcpoauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/strelov1/freehire/internal/platform/db"
)

type memStore struct {
	mu       sync.Mutex
	clients  map[string]db.GetOAuthClientRow
	codes    map[string]db.GetOAuthAuthCodeRow
	consumed map[string]bool
	grants   map[int64]memGrant
	nextID   int64
	version  map[int64]int32
}

type memGrant struct {
	row     db.InsertOAuthGrantRow
	access  string
	refresh string
	revoked bool
}

func newMem() *memStore {
	return &memStore{
		clients:  map[string]db.GetOAuthClientRow{},
		codes:    map[string]db.GetOAuthAuthCodeRow{},
		consumed: map[string]bool{},
		grants:   map[int64]memGrant{},
		version:  map[int64]int32{1: 1},
		nextID:   1,
	}
}

func (m *memStore) UpsertOAuthClient(_ context.Context, arg db.UpsertOAuthClientParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[arg.ClientID] = db.GetOAuthClientRow{ClientID: arg.ClientID, ClientName: arg.ClientName, RedirectUris: arg.RedirectUris}
	return nil
}

func (m *memStore) GetOAuthClient(_ context.Context, clientID string) (db.GetOAuthClientRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.clients[clientID]
	if !ok {
		return db.GetOAuthClientRow{}, pgx.ErrNoRows
	}
	return row, nil
}

func (m *memStore) InsertOAuthAuthCode(_ context.Context, arg db.InsertOAuthAuthCodeParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[arg.CodeHash] = db.GetOAuthAuthCodeRow{
		CodeHash: arg.CodeHash, ClientID: arg.ClientID, UserID: arg.UserID, RedirectUri: arg.RedirectUri,
		CodeChallenge: arg.CodeChallenge, CodeChallengeMethod: arg.CodeChallengeMethod,
		Resource: arg.Resource, Scope: arg.Scope, ExpiresAt: arg.ExpiresAt,
	}
	return nil
}

func (m *memStore) GetOAuthAuthCode(_ context.Context, codeHash string) (db.GetOAuthAuthCodeRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.codes[codeHash]
	if !ok || m.consumed[codeHash] || !row.ExpiresAt.Time.After(time.Now()) {
		return db.GetOAuthAuthCodeRow{}, pgx.ErrNoRows
	}
	return row, nil
}

func (m *memStore) ConsumeOAuthAuthCode(_ context.Context, codeHash string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.codes[codeHash]; !ok || m.consumed[codeHash] {
		return 0, nil
	}
	m.consumed[codeHash] = true
	return 1, nil
}

func (m *memStore) InsertOAuthGrant(_ context.Context, arg db.InsertOAuthGrantParams) (db.InsertOAuthGrantRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextID
	m.nextID++
	row := db.InsertOAuthGrantRow{
		ID: id, UserID: arg.UserID, ClientID: arg.ClientID, ClientName: arg.ClientName,
		CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}, ExpiresAt: arg.ExpiresAt,
		TokenVersion: arg.TokenVersion, Resource: arg.Resource, Scope: arg.Scope,
	}
	m.grants[id] = memGrant{row: row, access: arg.AccessTokenHash.String, refresh: arg.RefreshTokenHash.String}
	return row, nil
}

func (m *memStore) RotateOAuthGrantTokens(_ context.Context, arg db.RotateOAuthGrantTokensParams) (db.RotateOAuthGrantTokensRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[arg.ID]
	if !ok || g.revoked || !g.row.ExpiresAt.Time.After(time.Now()) {
		return db.RotateOAuthGrantTokensRow{}, pgx.ErrNoRows
	}
	g.access = arg.AccessTokenHash.String
	g.refresh = arg.RefreshTokenHash.String
	m.grants[arg.ID] = g
	return db.RotateOAuthGrantTokensRow{
		ID: g.row.ID, UserID: g.row.UserID, ClientID: g.row.ClientID, ClientName: g.row.ClientName,
		CreatedAt: g.row.CreatedAt, ExpiresAt: g.row.ExpiresAt, TokenVersion: g.row.TokenVersion,
		Resource: g.row.Resource, Scope: g.row.Scope,
	}, nil
}

func (m *memStore) findByHash(hash string, access bool) (memGrant, bool) {
	for _, g := range m.grants {
		got := g.refresh
		if access {
			got = g.access
		}
		if got == hash && !g.revoked && g.row.ExpiresAt.Time.After(time.Now()) && g.row.TokenVersion == m.version[g.row.UserID] {
			return g, true
		}
	}
	return memGrant{}, false
}

func (m *memStore) UseOAuthGrantByAccessHash(_ context.Context, accessTokenHash pgtype.Text) (db.UseOAuthGrantByAccessHashRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.findByHash(accessTokenHash.String, true)
	if !ok {
		return db.UseOAuthGrantByAccessHashRow{}, pgx.ErrNoRows
	}
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	g.row.LastUsedAt = now
	m.grants[g.row.ID] = g
	return db.UseOAuthGrantByAccessHashRow{
		ID: g.row.ID, UserID: g.row.UserID, ClientID: g.row.ClientID, ClientName: g.row.ClientName,
		CreatedAt: g.row.CreatedAt, ExpiresAt: g.row.ExpiresAt, TokenVersion: g.row.TokenVersion,
		Resource: g.row.Resource, Scope: g.row.Scope,
	}, nil
}

func (m *memStore) GetOAuthGrantByRefreshHash(_ context.Context, refreshTokenHash pgtype.Text) (db.GetOAuthGrantByRefreshHashRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.findByHash(refreshTokenHash.String, false)
	if !ok {
		return db.GetOAuthGrantByRefreshHashRow{}, pgx.ErrNoRows
	}
	return db.GetOAuthGrantByRefreshHashRow{
		ID: g.row.ID, UserID: g.row.UserID, ClientID: g.row.ClientID, ClientName: g.row.ClientName,
		CreatedAt: g.row.CreatedAt, ExpiresAt: g.row.ExpiresAt, TokenVersion: g.row.TokenVersion,
		Resource: g.row.Resource, Scope: g.row.Scope,
	}, nil
}

func (m *memStore) ListOAuthGrantsByUser(_ context.Context, userID int64) ([]db.ListOAuthGrantsByUserRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []db.ListOAuthGrantsByUserRow
	for _, g := range m.grants {
		if g.row.UserID == userID && !g.revoked {
			out = append(out, db.ListOAuthGrantsByUserRow{
				ID: g.row.ID, ClientName: g.row.ClientName, CreatedAt: g.row.CreatedAt,
				ExpiresAt: g.row.ExpiresAt, LastUsedAt: g.row.LastUsedAt,
			})
		}
	}
	return out, nil
}

func (m *memStore) RevokeOAuthGrant(_ context.Context, arg db.RevokeOAuthGrantParams) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[arg.ID]
	if !ok || g.row.UserID != arg.UserID || g.revoked {
		return 0, nil
	}
	g.revoked = true
	m.grants[arg.ID] = g
	return 1, nil
}

func (m *memStore) GetUserTokenVersion(_ context.Context, id int64) (int32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.version[id]
	if !ok {
		return 0, pgx.ErrNoRows
	}
	return v, nil
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return strings.TrimRight(base64.URLEncoding.EncodeToString(sum[:]), "=")
}

func TestAuthorizationCodePKCEAndRefreshDoesNotExtend(t *testing.T) {
	mem := newMem()
	redirectURI := "http://127.0.0.1:8765/callback"
	if err := mem.UpsertOAuthClient(context.Background(), db.UpsertOAuthClientParams{
		ClientID: "fhc_test", ClientName: "Test host", RedirectUris: []string{redirectURI},
	}); err != nil {
		t.Fatal(err)
	}
	origin := "https://freehire.test"
	srv := New(Config{
		Origin: origin,
		Store:  mem,
		AuthorizeUser: func(http.ResponseWriter, *http.Request) (string, error) {
			return "1", nil
		},
	})

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"fhc_test"},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {s256(verifier)},
		"code_challenge_method": {"S256"},
		"resource":              {srv.Resource()},
		"scope":                 {ScopeAccount},
		"state":                 {"xyz"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	srv.Authorize(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status %d body %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "xyz" {
		t.Fatalf("redirect = %s", loc)
	}

	token := exchange(t, srv, redirectURI, code, verifier)
	if !strings.HasPrefix(token["access_token"].(string), "fho_") {
		t.Fatalf("access token %v", token["access_token"])
	}
	if _, err := srv.Authenticate(context.Background(), token["access_token"].(string)); err != nil {
		t.Fatal(err)
	}

	// A second exchange of the same code fails.
	rec = httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {"fhc_test"}, "code_verifier": {verifier}, "resource": {srv.Resource()},
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Token(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("authorization code was accepted twice")
	}

	// Pull the deadline forward and refresh. expires_in must be the time left,
	// and the stored deadline must not move.
	var grant memGrant
	for _, g := range mem.grants {
		grant = g
	}
	deadline := time.Now().Add(2 * time.Hour)
	grant.row.ExpiresAt = pgtype.Timestamptz{Time: deadline, Valid: true}
	mem.grants[grant.row.ID] = grant

	rec = httptest.NewRecorder()
	form = url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {token["refresh_token"].(string)},
		"client_id": {"fhc_test"}, "resource": {srv.Resource()},
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Token(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status %d body %s", rec.Code, rec.Body.String())
	}
	var refreshed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &refreshed); err != nil {
		t.Fatal(err)
	}
	expiresIn, _ := refreshed["expires_in"].(float64)
	if expiresIn > 3*time.Hour.Seconds() || expiresIn < time.Hour.Seconds() {
		t.Fatalf("expires_in = %v, want about 2 hours", expiresIn)
	}
	got := mem.grants[grant.row.ID].row.ExpiresAt.Time
	if got.Sub(deadline).Abs() > time.Second {
		t.Fatalf("grant deadline moved from %s to %s", deadline, got)
	}
	if _, err := srv.Authenticate(context.Background(), refreshed["access_token"].(string)); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Authenticate(context.Background(), token["access_token"].(string)); err == nil {
		t.Fatal("the rotated access token still authenticated")
	}
}

func TestResourceMismatchAndExpiredGrant(t *testing.T) {
	mem := newMem()
	redirectURI := "https://host.example/cb"
	_ = mem.UpsertOAuthClient(context.Background(), db.UpsertOAuthClientParams{
		ClientID: "fhc_test", ClientName: "Host", RedirectUris: []string{redirectURI},
	})
	srv := New(Config{
		Origin: "https://freehire.test", Store: mem,
		AuthorizeUser: func(http.ResponseWriter, *http.Request) (string, error) { return "1", nil },
	})
	rec := httptest.NewRecorder()
	q := url.Values{
		"response_type": {"code"}, "client_id": {"fhc_test"}, "redirect_uri": {redirectURI},
		"code_challenge":        {s256("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")},
		"code_challenge_method": {"S256"}, "resource": {"https://evil.example/mcp"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	srv.Authorize(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for a foreign resource", rec.Code)
	}

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	q.Set("resource", srv.Resource())
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	srv.Authorize(rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	token := exchange(t, srv, redirectURI, loc.Query().Get("code"), verifier)

	// Token request bound to a different resource is refused.
	rec = httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {token["refresh_token"].(string)},
		"client_id": {"fhc_test"}, "resource": {"https://evil.example/mcp"},
	}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Token(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("refresh accepted a different resource")
	}

	for id, g := range mem.grants {
		g.row.ExpiresAt = pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
		mem.grants[id] = g
	}
	if _, err := srv.Authenticate(context.Background(), token["access_token"].(string)); err == nil {
		t.Fatal("expired grant authenticated")
	}
}

func TestCIMDClient(t *testing.T) {
	var docURL string
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	docURL = ts.URL + "/client.json"
	mux.HandleFunc("/client.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     docURL,
			"client_name":   "Cursor",
			"redirect_uris": []string{"http://127.0.0.1:9/cb"},
		})
	})
	srv := New(Config{
		Origin: "https://freehire.test", Store: newMem(), HTTPClient: ts.Client(),
		AuthorizeUser: func(http.ResponseWriter, *http.Request) (string, error) { return "1", nil },
	})
	name, ok := srv.ClientName(context.Background(), docURL)
	if !ok || name != "Cursor" {
		t.Fatalf("client name %q ok=%v", name, ok)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	q := url.Values{
		"response_type": {"code"}, "client_id": {docURL}, "redirect_uri": {"http://127.0.0.1:9/cb"},
		"code_challenge": {s256(verifier)}, "code_challenge_method": {"S256"}, "resource": {srv.Resource()},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	srv.Authorize(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestMetadataAndChallenge(t *testing.T) {
	srv := New(Config{Origin: "https://freehire.test", Store: newMem()})
	meta := srv.AuthorizationServerMetadata()
	if meta["client_id_metadata_document_supported"] != true {
		t.Fatalf("metadata = %#v", meta)
	}
	if !strings.Contains(srv.WWWAuthenticate(), `resource_metadata="https://freehire.test/.well-known/oauth-protected-resource/api/v1/mcp/account"`) {
		t.Fatal(srv.WWWAuthenticate())
	}
	rec := httptest.NewRecorder()
	WriteMetadata(rec, srv.ProtectedResourceMetadata())
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("metadata is not public")
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), srv.Resource()) {
		t.Fatalf("body %s", body)
	}
}

func exchange(t *testing.T, srv *Server, redirectURI, code, verifier string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {"fhc_test"}, "code_verifier": {verifier}, "resource": {srv.Resource()},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Token(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status %d body %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
