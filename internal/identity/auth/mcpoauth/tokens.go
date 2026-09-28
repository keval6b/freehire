package mcpoauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/strelov1/freehire/internal/identity/auth"
)

const (
	accessPrefix  = "fho_"
	refreshPrefix = "fhr_"
	codePrefix    = "fhz_"
)

// GrantTTL is how long a device grant lives, measured from when it was
// created. A refresh does not extend it.
const GrantTTL = 30 * 24 * time.Hour

// ScopeAccount is the only scope this server issues. It reaches the
// authenticated MCP tools and nothing else.
const ScopeAccount = "account"

// AccountPath is the protected MCP resource, relative to the site origin.
const AccountPath = "/api/v1/mcp/account"

func mint(prefix string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashToken(token string) string {
	return auth.HashAPIKey(token)
}

type codeGenerator struct{}

func (codeGenerator) Token(_ context.Context, _ *oauth2.GenerateBasic) (string, error) {
	return mint(codePrefix)
}

type tokenGenerator struct{}

func (tokenGenerator) Token(_ context.Context, _ *oauth2.GenerateBasic, refresh bool) (string, string, error) {
	access, err := mint(accessPrefix)
	if err != nil {
		return "", "", err
	}
	if !refresh {
		return access, "", nil
	}
	rt, err := mint(refreshPrefix)
	if err != nil {
		return "", "", err
	}
	return access, rt, nil
}
