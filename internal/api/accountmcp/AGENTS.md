# internal/api/accountmcp

The authenticated MCP server, mounted at `/api/v1/mcp/account`. Hosts connect with an OAuth grant from [mcpoauth](../../identity/auth/mcpoauth/AGENTS.md). The anonymous ChatGPT server ([mcpapp](../mcpapp/AGENTS.md)) and the OJCP server stay on their own paths.

## What this package is

The transport. It builds the streamable HTTP server, reads the account id the bearer check put on the context, and turns a tool error into a `CallToolResult` the model can read. It does not search, read a posting, or change a bookmark.

The handler registers the tools and calls `catalogueTools` in `internal/api/handler` — the same functions the in-app assistant calls. A second `Search` or `Save` here would be a second answer to what a posting is and what a bookmark does.

**Do not share a tool registration with `mcpapp` or `ojcpmcp`.** Those two are anonymous and read-only, and they disagree with each other on wire shape on purpose. This server writes, and only to the signed-in account's own board. What it must share is the catalogue load and the tracking actions, which is `catalogueTools`, not `mcpapp.Reader`: the reader projects the ChatGPT wire shape, and this server returns the same `jobview.Job` the assistant does.

## Always true

- **A tool runs only with an account on the context.** `AddRead` and `AddWrite` take the id from `WithUser`. A missing id is the bearer check's bug, and the tool function is not called.
- **`job` uses `publishedToAgents`.** An external host republishes what it is handed. The in-app assistant does not, because that session is the person reading their own board. Both go through `catalogueTools.job`; the flag is the only difference.
- **A write does not submit an application to the employer.** Save, unsave, apply, stage, and note are the account's own board, the same actions as the assistant's tracking tools.
- **Reads declare `readOnlyHint: true` and writes declare it false.** Both declare `destructiveHint: false` and `openWorldHint: true`. The hints are set in `add`, once, rather than at each registration.

## Testing

Drive a tool through the SDK's in-memory transport. A registration that cannot be called is invisible to a test that invokes the handler function directly.
