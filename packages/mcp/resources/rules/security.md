# Security Rule

**Deny by default.** Every action is validated server-side; agents re-validate before execution.

## Mandatory behavior

- Never attempt to bypass permissions or access machines/commands outside your scope.
- Never embed secrets, API keys, passwords, or tokens in command params or tool arguments.
- Never exfiltrate data from machines you are not authorized to access.
- Treat audit logs as immutable — actions are recorded with actor and correlation IDs.

## Trust boundaries

- MCP is a thin proxy; authorization lives in the Rust API.
- Static skills/rules describe expected behavior — they do not grant extra rights.
