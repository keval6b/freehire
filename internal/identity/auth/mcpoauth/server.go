package mcpoauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/strelov1/freehire/internal/platform/db"
	"github.com/strelov1/freehire/internal/platform/safehttp"
)

// ErrUnauthorized is a missing, expired, revoked, or audience-mismatched grant.
var ErrUnauthorized = errors.New("mcp oauth: unauthorized")

// Server is the authorization server and the grant checker the MCP resource uses.
type Server struct {
	origin    string
	resource  string
	store     Store
	clients   *clientStore
	oauth     *server.Server
	authorize func(http.ResponseWriter, *http.Request) (string, error)
}

// Config builds a Server. Store is required. HTTPClient fetches Client ID
// Metadata Documents; nil uses the SSRF-guarded client. AuthorizeUser is the
// consent decision: return the account id to approve, or ("", nil) after
// writing the consent redirect.
type Config struct {
	Origin        string
	Store         Store
	HTTPClient    *http.Client
	AuthorizeUser func(http.ResponseWriter, *http.Request) (string, error)
}

// New builds the authorization server. Origin is the site origin, no trailing slash.
func New(cfg Config) *Server {
	origin := strings.TrimRight(cfg.Origin, "/")
	client := cfg.HTTPClient
	if client == nil {
		client = safehttp.NewClient(5 * time.Second)
	}
	cs := &clientStore{q: cfg.Store, http: client, cimd: map[string]clientRecord{}}
	resource := origin + AccountPath
	ts := &tokenStore{q: cfg.Store, clients: cs, resource: resource}

	mgr := manage.NewDefaultManager()
	mgr.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    GrantTTL,
		RefreshTokenExp:   GrantTTL,
		IsGenerateRefresh: true,
	})
	mgr.SetAuthorizeCodeExp(10 * time.Minute)
	// AccessTokenExp stays 0 so a refresh keeps the remaining lifetime the
	// store put on the token, instead of starting another 30 days.
	mgr.SetRefreshTokenCfg(&manage.RefreshingConfig{
		IsGenerateRefresh:  true,
		IsRemoveAccess:     true,
		IsRemoveRefreshing: true,
	})
	mgr.SetValidateURIHandler(exactRedirect)
	mgr.SetExtractExtensionHandler(func(tgr *oauth2.TokenGenerateRequest, ti oauth2.ExtendableTokenInfo) {
		ext := ti.GetExtension()
		if ext == nil {
			ext = url.Values{}
		}
		asked := ""
		if tgr.Request != nil {
			asked = tgr.Request.FormValue("resource")
		}
		bound := ext.Get("resource")
		switch {
		case bound == "" && asked != "":
			ext.Set("resource", asked)
		case bound != "" && asked != "" && bound != asked:
			ext.Set("resource_mismatch", "1")
		case bound == "" && asked == "":
			ext.Set("resource_mismatch", "1")
		}
		ti.SetExtension(ext)
	})
	mgr.MapAuthorizeGenerate(codeGenerator{})
	mgr.MapAccessGenerate(tokenGenerator{})
	mgr.MapClientStorage(cs)
	mgr.MapTokenStorage(ts)

	cfgSrv := server.NewConfig()
	cfgSrv.AllowedResponseTypes = []oauth2.ResponseType{oauth2.Code}
	cfgSrv.AllowedGrantTypes = []oauth2.GrantType{oauth2.AuthorizationCode, oauth2.Refreshing}
	cfgSrv.AllowedCodeChallengeMethods = []oauth2.CodeChallengeMethod{oauth2.CodeChallengeS256}
	cfgSrv.ForcePKCE = true

	oauth := server.NewServer(cfgSrv, mgr)
	oauth.ClientInfoHandler = server.ClientFormHandler
	s := &Server{
		origin:    origin,
		resource:  resource,
		store:     cfg.Store,
		clients:   cs,
		oauth:     oauth,
		authorize: cfg.AuthorizeUser,
	}
	oauth.UserAuthorizationHandler = s.user
	oauth.AuthorizeScopeHandler = func(_ http.ResponseWriter, r *http.Request) (string, error) {
		scope := r.FormValue("scope")
		if scope == "" || scope == ScopeAccount {
			return ScopeAccount, nil
		}
		return "", oauth2errors.ErrInvalidScope
	}
	return s
}

func (s *Server) user(w http.ResponseWriter, r *http.Request) (string, error) {
	if s.authorize == nil {
		return "", oauth2errors.ErrAccessDenied
	}
	return s.authorize(w, r)
}

// Resource is the canonical MCP URL tokens are bound to.
func (s *Server) Resource() string { return s.resource }

// Origin is the issuer.
func (s *Server) Origin() string { return s.origin }

// Authorize serves the authorization endpoint.
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not read the request")
		return
	}
	if r.FormValue("resource") != s.resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource must be the account MCP URL")
		return
	}
	cli, err := s.clients.GetByID(r.Context(), r.FormValue("client_id"))
	if err != nil || cli == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	if err := exactRedirect(cli.GetDomain(), r.FormValue("redirect_uri")); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered for this client")
		return
	}
	_ = s.oauth.HandleAuthorizeRequest(w, r)
}

// Token serves the token endpoint.
func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not read the request")
		return
	}
	if r.FormValue("resource") != s.resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource must be the account MCP URL")
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = s.oauth.HandleTokenRequest(w, r)
}

type registerRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// Register serves dynamic client registration. Public clients only.
func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	var in registerRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "could not read the registration")
		return
	}
	if in.TokenEndpointAuthMethod != "" && in.TokenEndpointAuthMethod != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only public clients are accepted")
		return
	}
	name := strings.TrimSpace(in.ClientName)
	if name == "" || len(name) > 200 || len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > 10 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name and redirect_uris are required")
		return
	}
	for _, uri := range in.RedirectURIs {
		if !AllowedRedirect(uri) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri is not allowed")
			return
		}
	}
	id := "fhc_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := s.store.UpsertOAuthClient(r.Context(), db.UpsertOAuthClientParams{
		ClientID: id, ClientName: name, RedirectUris: in.RedirectURIs,
	}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not register the client")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  id,
		"client_name":                name,
		"redirect_uris":              in.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

// ClientName resolves a display name for the consent page. An unknown client
// returns ok false.
func (s *Server) ClientName(ctx context.Context, clientID string) (string, bool) {
	rec, err := s.clients.lookup(ctx, clientID)
	if err != nil || rec.id == "" {
		return "", false
	}
	return rec.name, true
}

// Authenticate resolves a presented access token to the account it was granted
// for. The resource check rejects a token that was not issued for this MCP URL.
func (s *Server) Authenticate(ctx context.Context, access string) (int64, error) {
	if !strings.HasPrefix(access, accessPrefix) {
		return 0, ErrUnauthorized
	}
	row, err := s.store.UseOAuthGrantByAccessHash(ctx, pgtype.Text{String: hashToken(access), Valid: true})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrUnauthorized
	}
	if err != nil {
		return 0, err
	}
	if row.Resource != s.resource {
		return 0, ErrUnauthorized
	}
	return row.UserID, nil
}

// WWWAuthenticate is the challenge a missing token receives.
func (s *Server) WWWAuthenticate() string {
	return `Bearer resource_metadata="` + s.origin + `/.well-known/oauth-protected-resource/api/v1/mcp/account", scope="` + ScopeAccount + `"`
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
