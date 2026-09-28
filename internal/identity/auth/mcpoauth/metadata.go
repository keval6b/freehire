package mcpoauth

import (
	"encoding/json"
	"net/http"
)

// ProtectedResourceMetadata is the document a client fetches from the URL in
// the WWW-Authenticate challenge.
func (s *Server) ProtectedResourceMetadata() map[string]any {
	return map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.origin},
		"scopes_supported":         []string{ScopeAccount},
		"bearer_methods_supported": []string{"header"},
	}
}

// AuthorizationServerMetadata is RFC 8414 discovery for this issuer.
func (s *Server) AuthorizationServerMetadata() map[string]any {
	return map[string]any{
		"issuer":                                s.origin,
		"authorization_endpoint":                s.origin + "/api/v1/oauth/authorize",
		"token_endpoint":                        s.origin + "/api/v1/oauth/token",
		"registration_endpoint":                 s.origin + "/api/v1/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{ScopeAccount},
		"client_id_metadata_document_supported": true,
	}
}

// WriteMetadata writes one discovery document. Both are public.
func WriteMetadata(w http.ResponseWriter, doc map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(doc)
}
