package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/strelov1/freehire/internal/api/accountmcp"
	"github.com/strelov1/freehire/internal/api/ratelimit"

	"github.com/strelov1/freehire/internal/identity/auth"
	"github.com/strelov1/freehire/internal/identity/auth/mcpoauth"
	"github.com/strelov1/freehire/internal/platform/db"
	"github.com/strelov1/freehire/internal/platform/safehttp"
)

func (h *authHandlers) mountMCPOAuth(api fiber.Router) {
	if h.mcpOAuth == nil {
		return
	}
	// Credential endpoints, same family as login. A public client can ask as
	// often as a person approving a device; 30/min per IP is well above that.
	limit := ratelimit.Middleware(h.throttler, ratelimit.KeyByIP("oauth"), 30, time.Minute)
	api.Get("/oauth/authorization-server", h.oauthAuthorizationServer)
	api.Get("/oauth/protected-resource", h.oauthProtectedResource)
	// Name lookup stays off this limiter. The consent page calls it from the
	// Node server, so an IP limit would be one bucket for every visitor. The
	// outbound metadata fetch has its own budget inside the client store.
	api.Get("/oauth/client", h.oauthClient)
	api.All("/oauth/authorize", limit, adaptor.HTTPHandlerFunc(h.mcpOAuth.Authorize))
	api.Post("/oauth/token", limit, adaptor.HTTPHandlerFunc(h.mcpOAuth.Token))
	api.Post("/oauth/register", limit, adaptor.HTTPHandlerFunc(h.mcpOAuth.Register))
}

func newMCPOAuth(h *authHandlers) *mcpoauth.Server {
	if h.queries == nil || h.issuer == nil || h.frontendOrigin == "" {
		return nil
	}
	return mcpoauth.New(mcpoauth.Config{
		Origin:        h.frontendOrigin,
		Store:         h.queries,
		HTTPClient:    safehttp.NewClient(5 * time.Second),
		AuthorizeUser: h.decideOAuthConsent,
	})
}

func (h *authHandlers) decideOAuthConsent(w http.ResponseWriter, r *http.Request) (string, error) {
	// Allow and deny are the consent form's POST. A GET carries the session
	// cookie (SameSite=Lax still sends it on a top-level navigation), so a
	// decision on the authorize URL would approve the host without the click.
	if r.Method != http.MethodPost {
		http.Redirect(w, r, h.oauthConsentURL(r, ""), http.StatusFound)
		return "", nil
	}
	switch r.FormValue("decision") {
	case "deny":
		return "", oauth2errors.ErrAccessDenied
	case "allow":
		return h.approveOAuthConsent(w, r)
	default:
		http.Redirect(w, r, h.oauthConsentURL(r, ""), http.StatusFound)
		return "", nil
	}
}

func (h *authHandlers) approveOAuthConsent(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, err := r.Cookie(auth.CookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, h.oauthConsentURL(r, ""), http.StatusFound)
		return "", nil
	}
	userID, tv, err := h.issuer.Parse(cookie.Value)
	if err != nil {
		http.Redirect(w, r, h.oauthConsentURL(r, ""), http.StatusFound)
		return "", nil
	}
	current, err := h.queries.GetUserTokenVersion(r.Context(), userID)
	if err != nil || current != tv {
		http.Redirect(w, r, h.oauthConsentURL(r, ""), http.StatusFound)
		return "", nil
	}
	user, err := h.queries.GetUserByID(r.Context(), userID)
	if err != nil || !user.EmailVerified {
		http.Redirect(w, r, h.oauthConsentURL(r, "email_unverified"), http.StatusFound)
		return "", nil
	}
	return strconv.FormatInt(userID, 10), nil
}

func (h *authHandlers) oauthConsentURL(r *http.Request, oauthError string) string {
	q := url.Values{}
	for _, key := range []string{
		"client_id", "redirect_uri", "response_type", "code_challenge",
		"code_challenge_method", "resource", "scope", "state",
	} {
		if v := r.FormValue(key); v != "" {
			q.Set(key, v)
		}
	}
	if oauthError != "" {
		q.Set("error", oauthError)
	}
	return h.frontendOrigin + "/oauth/mcp?" + q.Encode()
}

func (h *authHandlers) oauthAuthorizationServer(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Cache-Control", "public, max-age=3600")
	return c.JSON(h.mcpOAuth.AuthorizationServerMetadata())
}

func (h *authHandlers) oauthProtectedResource(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Cache-Control", "public, max-age=3600")
	return c.JSON(h.mcpOAuth.ProtectedResourceMetadata())
}

func (h *authHandlers) oauthClient(c *fiber.Ctx) error {
	name, ok := h.mcpOAuth.ClientName(c.Context(), c.Query("client_id"))
	if !ok {
		return fiber.NewError(fiber.StatusNotFound, "unknown client")
	}
	return c.JSON(fiber.Map{"data": fiber.Map{"client_name": name}})
}

type oauthGrantResponse struct {
	ID         int64              `json:"id"`
	ClientName string             `json:"client_name"`
	CreatedAt  pgtype.Timestamptz `json:"created_at"`
	ExpiresAt  pgtype.Timestamptz `json:"expires_at"`
	LastUsedAt pgtype.Timestamptz `json:"last_used_at"`
}

func (h *authHandlers) ListOAuthGrants(c *fiber.Ctx) error {
	userID, err := requireUserID(c)
	if err != nil {
		return err
	}
	rows, err := h.queries.ListOAuthGrantsByUser(c.Context(), userID)
	if err != nil {
		return err
	}
	out := make([]oauthGrantResponse, len(rows))
	for i, row := range rows {
		out[i] = oauthGrantResponse{
			ID: row.ID, ClientName: row.ClientName,
			CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, LastUsedAt: row.LastUsedAt,
		}
	}
	return c.JSON(fiber.Map{"data": out, "meta": fiber.Map{"total": len(out)}})
}

func (h *authHandlers) RevokeOAuthGrant(c *fiber.Ctx) error {
	userID, err := requireUserID(c)
	if err != nil {
		return err
	}
	id, err := pathID(c)
	if err != nil {
		return err
	}
	n, err := h.queries.RevokeOAuthGrant(c.Context(), db.RevokeOAuthGrantParams{ID: id, UserID: userID})
	if err != nil {
		return err
	}
	if n == 0 {
		return fiber.NewError(fiber.StatusNotFound, "device not found")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// accountMCPHTTP is the bearer check in front of the tool server. A missing
// or rejected token never reaches a tool.
func accountMCPHTTP(s *mcpoauth.Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unauthorized := func() {
			w.Header().Set("WWW-Authenticate", s.WWWAuthenticate())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			unauthorized()
			return
		}
		userID, err := s.Authenticate(r.Context(), token)
		if err != nil {
			if errors.Is(err, mcpoauth.ErrUnauthorized) {
				unauthorized()
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"unavailable"}`))
			return
		}
		next.ServeHTTP(w, r.WithContext(accountmcp.WithUser(r.Context(), userID)))
	})
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}
