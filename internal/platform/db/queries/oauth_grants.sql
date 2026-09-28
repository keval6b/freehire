-- name: UpsertOAuthClient :exec
-- Register (or replace) a dynamically registered public client. client_id is
-- server-minted; redirect_uris is the exact list the authorize endpoint matches.
INSERT INTO oauth_clients (client_id, client_name, redirect_uris)
VALUES ($1, $2, $3)
ON CONFLICT (client_id) DO UPDATE
SET client_name = EXCLUDED.client_name,
    redirect_uris = EXCLUDED.redirect_uris;

-- name: GetOAuthClient :one
SELECT client_id, client_name, redirect_uris
FROM oauth_clients
WHERE client_id = $1;

-- name: InsertOAuthAuthCode :exec
INSERT INTO oauth_auth_codes (
    code_hash, client_id, user_id, redirect_uri,
    code_challenge, code_challenge_method, resource, scope, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetOAuthAuthCode :one
-- A live, unconsumed code. The caller still has to check the PKCE verifier.
SELECT code_hash, client_id, user_id, redirect_uri, code_challenge,
       code_challenge_method, resource, scope, expires_at
FROM oauth_auth_codes
WHERE code_hash = $1
  AND consumed_at IS NULL
  AND expires_at > now();

-- name: ConsumeOAuthAuthCode :execrows
-- Single use. A second exchange finds no row.
UPDATE oauth_auth_codes
SET consumed_at = now()
WHERE code_hash = $1
  AND consumed_at IS NULL;

-- name: InsertOAuthGrant :one
INSERT INTO oauth_grants (
    user_id, client_id, client_name, expires_at, token_version,
    access_token_hash, refresh_token_hash, resource, scope
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, user_id, client_id, client_name, created_at, expires_at,
          last_used_at, token_version, resource, scope;

-- name: RotateOAuthGrantTokens :one
-- Replace the current access and refresh hashes. expires_at is not written:
-- a refresh must not move the 30-day deadline.
UPDATE oauth_grants
SET access_token_hash = $2,
    refresh_token_hash = $3
WHERE id = $1
  AND revoked_at IS NULL
  AND expires_at > now()
RETURNING id, user_id, client_id, client_name, created_at, expires_at,
          token_version, resource, scope;

-- name: UseOAuthGrantByAccessHash :one
-- Resolve a presented access token. The token_version join is what makes a
-- sign-out-everywhere or a password change fail the grant on its next use.
UPDATE oauth_grants g
SET last_used_at = now()
FROM users u
WHERE g.access_token_hash = $1
  AND g.user_id = u.id
  AND g.revoked_at IS NULL
  AND g.expires_at > now()
  AND g.token_version = u.token_version
RETURNING g.id, g.user_id, g.client_id, g.client_name, g.created_at, g.expires_at,
          g.token_version, g.resource, g.scope;

-- name: GetOAuthGrantByRefreshHash :one
SELECT g.id, g.user_id, g.client_id, g.client_name, g.created_at, g.expires_at,
       g.token_version, g.resource, g.scope
FROM oauth_grants g
JOIN users u ON u.id = g.user_id
WHERE g.refresh_token_hash = $1
  AND g.revoked_at IS NULL
  AND g.expires_at > now()
  AND g.token_version = u.token_version;

-- name: ListOAuthGrantsByUser :many
-- Devices still on the account. Revoked rows are gone from the list; an expired
-- grant stays so the page can show that it ended.
SELECT id, client_name, created_at, expires_at, last_used_at
FROM oauth_grants
WHERE user_id = $1
  AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: RevokeOAuthGrant :execrows
UPDATE oauth_grants
SET revoked_at = now()
WHERE id = $1
  AND user_id = $2
  AND revoked_at IS NULL;
