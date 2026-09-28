// Package mcpoauth is the OAuth 2.1 authorization server MCP hosts use to
// connect a freehire account without an API key.
//
// The grant is a device, not an API key. Access tokens are opaque (fho_…),
// stored only as a SHA-256, and die 30 days after the grant was created. A
// refresh rotates the secret and does not move that deadline. The grant also
// stores the account's token_version at issue time: a later bump (sign-out
// everywhere, a password change) fails it on the next use, the way a session
// JWT fails. API keys still do not.
//
// github.com/go-oauth2/oauth2/v4 owns the authorization-code grant, PKCE S256,
// and the token endpoint. This package owns the two stores, the redirect
// check, Client ID Metadata Documents, dynamic registration, RFC 8707
// resource binding, and the 30-day clamp the library does not implement.
package mcpoauth
