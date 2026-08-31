# MCP client setup

Connect an MCP client to a remote Hecate MCP server over **Streamable HTTP** (HTTPS).

This guide covers **Cursor**, **Claude Code**, and **Hermes Agent**.

## Prerequisites (all clients)

- Hecate deployed and reachable at `https://<fqdn>:<port>/mcp`  
  Production default: `https://<fqdn>:18443/mcp`
- Prefer exposing MCP only on a private network or behind edge auth (mTLS / IP allowlist). Do not rely solely on Host-header allowlists when a reverse proxy rewrites `Host`.
- An **AI API key** for your AI identity (operator UI: **Admin → AI identities → API keys**)
  - Format: `hecate_<hex>` — shown once at creation; store it securely
  - This is **not** the server `INTERNAL_TOKEN` (that token is only used between MCP and the Rust API)
- JSON request bodies to `/mcp` are limited to **2 MiB**; upload large files via `upload_command_artifact` instead.

Replace placeholders below:

| Placeholder | Example |
|---|---|
| `<FQDN>` / URL | `https://hecate.example.com:18443/mcp` |
| API key | `hecate_…` (or `$HECATE_MCP_API_KEY`) |

## Authentication model

```text
Client  --Bearer AI API key-->  MCP  --X-Internal-Token-->  Rust API
```

- **Client → MCP**: `Authorization: Bearer <ai_api_key>` on every HTTP request
- **MCP → API**: `X-Internal-Token` (server-side only; never put this in a client config)
- Permissions and machine scope are enforced in the Rust API for the authenticated AI identity

## Verify the endpoint

Without a token, the server must return **401** (not a connection error):

```bash
curl -sS -X POST "https://hecate.example.com:18443/mcp" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Expected:

```json
{"jsonrpc":"2.0","error":{"code":-32000,"message":"Unauthorized: Bearer API key required"},"id":null}
```

---

## Cursor

Config files:

- **Global**: `~/.cursor/mcp.json` (all projects)
- **Project**: `.cursor/mcp.json` in the repo root (team-shared; use env interpolation, never commit secrets)

### Recommended — environment variable

```json
{
  "mcpServers": {
    "hecate": {
      "url": "https://hecate.example.com:18443/mcp",
      "headers": {
        "Authorization": "Bearer ${env:HECATE_MCP_API_KEY}"
      }
    }
  }
}
```

```bash
export HECATE_MCP_API_KEY="hecate_your_api_key_here"
```

Restart Cursor after changing `mcp.json` or environment variables.

### Inline token (local testing only)

```json
{
  "mcpServers": {
    "hecate": {
      "url": "https://hecate.example.com:18443/mcp",
      "headers": {
        "Authorization": "Bearer hecate_your_api_key_here"
      }
    }
  }
}
```

Do not commit real API keys to git.

### Verify in Cursor

1. Open **Customize** in the sidebar → enable **hecate**
2. Open **Output** (`Ctrl+Shift+U`) → channel **MCP Logs**
3. Confirm initialization without auth or TLS errors
4. Ask the agent to call `list_machines` or read `hecate://skill/overview`

---

## Claude Code

Claude Code talks to remote MCP over HTTP (`type: "http"`; alias `streamable-http`). A JSON entry with `url` but **no** `type` is invalid and will be skipped.

### CLI (quickest)

```bash
claude mcp add --transport http hecate \
  https://hecate.example.com:18443/mcp \
  --header "Authorization: Bearer ${HECATE_MCP_API_KEY}"
```

Scopes: `--scope local` (default, this project), `--scope project` (`.mcp.json` in the repo), or `--scope user` (all projects).

### Project file — `.mcp.json`

```json
{
  "mcpServers": {
    "hecate": {
      "type": "http",
      "url": "https://hecate.example.com:18443/mcp",
      "headers": {
        "Authorization": "Bearer ${HECATE_MCP_API_KEY}"
      }
    }
  }
}
```

Claude Code expands `${HECATE_MCP_API_KEY}` from the environment. Prefer that over hard-coding the key in a committed `.mcp.json`.

### User / local scopes — `~/.claude.json`

Same server object under the top-level `mcpServers` key (user scope) or under the project entry (local scope). Always include `"type": "http"`.

### Verify in Claude Code

```bash
# In a Claude Code session:
/mcp
```

Confirm `hecate` shows as **connected**. Then ask for `list_machines` or resource `hecate://skill/overview`.

### Claude Desktop note

Claude Desktop historically uses stdio via `claude_desktop_config.json`. For a remote Hecate HTTP endpoint, prefer **Claude Code** (above) or Desktop **Custom Connectors** if your plan supports remote HTTP connectors. Do not paste a Cursor-style `url`-only block into Desktop’s stdio config without a supported remote-HTTP path.

---

## Hermes Agent

Configure under `mcp_servers` in `~/.hermes/config.yaml`. Hermes supports HTTP / Streamable HTTP with custom headers.

```yaml
mcp_servers:
  hecate:
    url: "https://hecate.example.com:18443/mcp"
    headers:
      Authorization: "Bearer hecate_your_api_key_here"
    timeout: 180
```

Prefer injecting the key from the environment if your Hermes version supports it; otherwise keep the token only in this local config file (mode `0600`) and never commit it.

After editing:

1. Run `/reload-mcp` in a chat session (or restart Hermes)
2. Run `/tools` or ask: “What MCP tools do you have available?”
3. Hermes names tools as `mcp__hecate__<toolname>` (for example `mcp__hecate__list_machines`)

Official Hermes MCP docs: [MCP integration](https://nousresearch-hermes-agent.mintlify.app/user-guide/features/mcp).

---

## Available capabilities

### Tools

| Tool | Purpose |
|------|---------|
| `list_machines` | Machines authorized for your AI identity |
| `get_machine` | Machine detail by UUID |
| `list_commands` | Command history / queue |
| `get_command` | Poll command status (async workflow) |
| `execute_command` | Enqueue a command on a machine (async by default) |
| `cancel_command` | Cancel a pending command |

Other tools (permissions, queue, artifacts, audit, …) appear once the client finishes MCP initialization. Read `hecate://skill/overview` first when onboarding a new agent session.

### Resources

Static skills and rules (`hecate://skill/*`, `hecate://rule/*`) plus live permissions at `hecate://context/permissions`.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Connection refused / timeout | Firewall, wrong host/port, or stack not running |
| TLS / certificate error | Wrong cert on host (see [install.md](install.md) / Ansible TLS notes) |
| `401 Unauthorized` | Missing or invalid AI API key; revoked key |
| `403 Forbidden: invalid Host header` | `MCP_ALLOWED_HOSTS` on server missing the public FQDN |
| `503 missing internal token` | Server misconfiguration (`HECATE_INTERNAL_TOKEN` unset) |
| Claude: server skipped / `url` without `type` | Add `"type": "http"` to the Claude Code entry |
| Cursor: tools empty / server disabled | Enable the server in **Customize**; check MCP Logs |
| Hermes: tools missing after edit | Run `/reload-mcp` |

---

## Local development

Run MCP against a local API (stdio is not required; HTTP is fine):

```bash
cd packages/mcp
export HECATE_API_URL=http://127.0.0.1:8080
export HECATE_INTERNAL_TOKEN=dev-internal-token
export MCP_PORT=3100
export MCP_ALLOWED_HOSTS=127.0.0.1,localhost
npm run dev
```

Point any client at `http://127.0.0.1:3100/mcp` with the same `Authorization: Bearer …` header pattern as above.
