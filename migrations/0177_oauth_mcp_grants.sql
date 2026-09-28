-- MCP OAuth grants: the devices an AI host connects as, distinct from api_keys.
--
-- An API key is a durable credential the CLI and the stdio MCP server present.
-- A grant is what a remote MCP host (Claude, Cursor, ChatGPT connectors) receives
-- after the account approves it in the browser. The access token is opaque and
-- stored only as a SHA-256 hash; expiry is absolute, 30 days from the grant, and
-- a refresh rotates the secret without moving expires_at.
--
-- token_version is copied from users at issue time. A later bump (sign-out
-- everywhere, password change) fails the grant on its next use, the same way a
-- session JWT fails. Reset and seizure delete the rows outright, in the same
-- statement that already deletes api_keys — a grant must not outlive a takeover.

CREATE TABLE oauth_clients (
    client_id     text        PRIMARY KEY,
    client_name   text        NOT NULL,
    redirect_uris text[]      NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oauth_auth_codes (
    code_hash             text        PRIMARY KEY,
    client_id             text        NOT NULL,
    user_id               bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri          text        NOT NULL,
    code_challenge        text        NOT NULL,
    code_challenge_method text        NOT NULL,
    resource              text        NOT NULL,
    scope                 text        NOT NULL,
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- The account-deletion cascade. TestEveryUserForeignKeyIsIndexed requires it.
CREATE INDEX oauth_auth_codes_user_id_idx ON oauth_auth_codes (user_id);

CREATE TABLE oauth_grants (
    id                 bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id            bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id          text        NOT NULL,
    client_name        text        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    last_used_at       timestamptz,
    revoked_at         timestamptz,
    token_version      integer     NOT NULL,
    access_token_hash  text,
    refresh_token_hash text,
    resource           text        NOT NULL,
    scope              text        NOT NULL
);

-- Lookup keys. Partial so a grant between rotation steps (a hash momentarily
-- null) does not collide with every other unset row.
CREATE UNIQUE INDEX oauth_grants_access_token_hash_idx
    ON oauth_grants (access_token_hash) WHERE access_token_hash IS NOT NULL;
CREATE UNIQUE INDEX oauth_grants_refresh_token_hash_idx
    ON oauth_grants (refresh_token_hash) WHERE refresh_token_hash IS NOT NULL;

CREATE INDEX oauth_grants_user_id_idx ON oauth_grants (user_id);
