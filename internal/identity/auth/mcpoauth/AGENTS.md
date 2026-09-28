# MCP OAuth grants

The authorization server MCP hosts use to reach `/api/v1/mcp/account`. API keys stay the credential for the CLI and for `npx freehire-mcp`.

## Always true

- **A grant is a device, and it dies with `token_version`.** The row stores the account's generation at approval. The next use compares it with `users.token_version`. Sign-out everywhere and a password change fail the grant. Account seizure and password reset delete the rows in the same statement that deletes `api_keys`.
- **An API key does not.** `AuthenticateAPIKey` never reads `token_version`. Do not give a grant that exemption, and do not give a key this check.
- **Expiry is 30 days from approval** (`GrantTTL`). A refresh rotates the secrets and does not move `expires_at`. The devices list shows that date.
- **Tokens are opaque and stored as SHA-256.** The plaintext is handed to the client once per rotation and is not recoverable. Access tokens are `fho_`, refresh tokens `fhr_`.
- **The audience is the account MCP URL.** A token whose `resource` is anything else is rejected. It is not a session and it is not accepted by `RequireAuthOrKey`.
