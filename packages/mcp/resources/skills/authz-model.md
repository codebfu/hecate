# Authz Model

Hecate authorization is **granular and reusable**. Permissions are not a single JSON blob — they are built from four entity types and per-identity assignments.

## Entity types

| Entity | Role |
|---|---|
| **Fleet Scope** | Which machines an access grant covers (explicit machine IDs + tag rules, `any` or `all` match mode) |
| **Capability Profile** | Which commands, shell/elevation policies, and limits apply |
| **Access Grant** | A named link between one Fleet Scope and one Capability Profile |
| **Grant Assignment** | Attaches an Access Grant to an AI identity, with per-assignment auto-approve flags |

## Evaluation semantics

- Multiple **Grant Assignments** on one identity combine by **union** — if any assignment authorizes a machine + command, enqueue is allowed.
- **Auto-approval** for `shell.run` and elevated execution is controlled **per assignment** (`requires_approval_for_shell`, `requires_approval_for_elevated`), not at identity level.
- At dispatch, the server signs the **Capability Profile of the matched grant** (most restrictive among matching grants), not the union of all profiles.

## MCP resources

| URI | Purpose |
|---|---|
| `hecate://context/permissions` | Current identity, resolved grant assignments, capability limits, admin command allowlist |
| `hecate://context/authz-catalog` | Self-service catalog of assignable grants (S12 filtered — no full fleet cartography) |
| `hecate://context/effective-rights` | Full effective rights matrix for **self only** |

## Admin tools

Identities with matching `allowed_admin_commands` can use `admin.authz.*` tools (mirrored as MCP tools). Read `hecate://rule/authz-admin` before mutating assignments on other identities.

## Permission requests

Standard identities request **additive** changes via `request_permissions` with `{ reason, requested_changes }` — see `hecate://skill/permission-requests` and `hecate://skill/grant-discovery`.

Authorization is enforced **only on the Rust API**. Never assume access beyond what context and effective rights describe.
