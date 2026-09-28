package mcpoauth

import (
	"net"
	"net/url"
	"strings"

	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
)

// AllowedRedirect reports whether uri may be registered or used as an OAuth
// redirect. Loopback http is allowed. Every other http URL is not. https is
// allowed. Any other scheme is a private URI scheme and is allowed only as an
// exact string the client listed — this function checks the shape, and the
// authorize step then requires an exact match. Wildcards are never allowed.
func AllowedRedirect(raw string) bool {
	if raw == "" || strings.Contains(raw, "*") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" && u.Opaque == "" && u.Path == "" {
		return false
	}
	if u.Fragment != "" || u.User != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u.Host != ""
	case "http":
		return loopbackHost(u.Hostname())
	case "javascript", "data", "file", "blob", "vbscript", "about":
		return false
	default:
		// A private scheme still needs a path or opaque part so "cursor:" alone
		// is not a redirect.
		return u.Host != "" || u.Opaque != "" || u.Path != ""
	}
}

func loopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// exactRedirect matches redirect against the newline-joined list a client
// stores in Client.Domain. The library's default prefix-matches one string;
// MCP clients register several, and a prefix match would accept a longer URI
// than the one that was approved.
func exactRedirect(baseURI, redirectURI string) error {
	if redirectURI == "" || !AllowedRedirect(redirectURI) {
		return oauth2errors.ErrInvalidRedirectURI
	}
	for _, candidate := range strings.Split(baseURI, "\n") {
		if candidate == redirectURI {
			return nil
		}
	}
	return oauth2errors.ErrInvalidRedirectURI
}
