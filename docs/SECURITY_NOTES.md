# Security notes (pre-release)

## Accepted residual risks

- **Agent elevation / sudoers `NOPASSWD: ALL`**: by design. Authorization is carried in the signed task policy (`shell_policy` / `elevation_policy`), re-validated on the agent. Compromising the agent service user can still yield root via sudo; treat the agent host as a high-trust endpoint.
- **Automatic machine tags**: reserved namespaces (`os`, `arch`, `distro`, `virt`, `init`, `gui`, `display`) are agent-reported. Admins choose which tag sources count for AI authorization (defaults: auto + operator on, agent custom off). A root-level attacker on the machine can already alter the agent.
- **Fleet backup privkeys**: agent task-signing private keys are included in encrypted fleet backups so restore can avoid mass re-enroll. Confidentiality relies on the backup password.
- **MCP approval tools (actor and approver on one channel)**: by design. Self-approval is blocked server-side (`block_self_for_ai`): an identity cannot approve its own request. What remains is cross-approval — `approve_permission_request`, `reject_permission_request`, `approve_queue_command` and `cancel_queue_command` are exposed over MCP, so an AI identity holding the matching admin rights can approve requests raised by *another* identity. Two such identities can therefore cover for each other and reconstitute self-approval, and `cancel_queue_command` lets them cancel `dispatched`/`running` commands fleet-wide. Every decision is audited with the reviewer as actor (`ai_permissions.request.approve`, `ai_permissions.request.reject`, `ai_permissions.update`), so cross-approval is detectable after the fact.
- **Operator non-admin can `approve_command`**: by design. Queue command approval uses `require_operator_write` (operator role), not `require_admin`. Approving a pending command is an operator duty; permission-change requests remain admin-gated.
- **Proxmox local API TLS (`danger_accept_invalid_certs`)**: accepted only when the API host is loopback. The Proxmox helper talks to a hard-coded local API (`https://127.0.0.1:8006`) with a typical self-signed PVE certificate; skipping verification is gated so a future configurable API base cannot silently inherit the exemption for non-loopback hosts.

## Controls added in the remediation pass

- AI authz tag source toggles (admin settings).
- `desktop.shell.run` uses the same shell/elevation/cwd/env policy as `shell.run`.
- Desktop/Proxmox IPC requires a shared `ipc.token` on every request (OsRng, constant-time compare). Linux: token `0640` + socket `0660` under `/run/hecate-lampad` (`RuntimeDirectoryMode=0750`, group `hecate-ipc`); Windows: named pipe DACL `SY/BA/CO` and `%ProgramData%\hecate-lampad\ipc.token`. Helpers also re-validate shell/cwd/env policy locally.
- Path traversal rejection and deny-by-default empty `allowed_cwd`.
- Env allowlist enforcement (dangerous vars blocked even with `*`).
- SSRF-hardened `remote.download` (server DNS pin via `connect_ip`; agent pins via reqwest DNS override so TLS SNI stays on the hostname; IPv4-mapped / CGNAT / NAT64 / Teredo / 6to4 / documentation prefixes blocked; no blind redirects). Feature-repo fetches use the same IP policy and DNS pin.
- Task-signing private keys at rest must be `enc:v1:` envelopes; plaintext keys are rejected.
- MCP tool responses that include remote-origin data separate `metadata` from `untrusted_output` (hostname, stdout/stderr, artifact bytes, command lists) with explicit markers.
- Agent HTTP client and Propylaea upstream client disable automatic redirects (signed agent headers must not follow Location).
- Desktop helper policy file missing → deny-by-default (empty allowlists), not wildcard. Windows policy must be owned by Administrators/SYSTEM under ProgramData/Program Files.
- Windows desktop IPC pipe DACL is SYSTEM + Administrators + Creator Owner (no Interactive Users). IPC token files use a protected DACL (no Users:RX inheritance).
- Install scripts / agent keys / config / Propylaea proxy key / IPC tokens / runtime status use exclusive create (`create_new` + `O_NOFOLLOW` / Windows reparse refusal); key loads refuse symlinks; package updates refuse world-writable `/tmp`; write probes do not follow symlinks.
- Production refuses placeholder secrets (`change-me`, short values) and all-zero `HECATE_TASK_SIGNING_MASTER_KEY`.
- Operator CLI HTTP client disables redirects when carrying session cookies / API keys.
- Content-policy scanner on uploads / shell payloads with strike + lockout (timer never disclosed to the AI).
- Production refuse default secrets; `HECATE_ENV` must be set explicitly (Ansible compose passes it into the API container).
- Atomic enrollment token claim; agent self-update release downloads require `active` agents and jailed artifact paths. Latest installer/helper bootstrap downloads (`/api/v1/releases/.../latest`) are unauthenticated by design so new hosts can fetch packages from Hecate without GitLab.
- **Re-enroll**: bound one-shot `enr_` / `penr_` tokens (created from machine/proxy detail in the admin UI) reuse the standard enroll endpoints. The server derives the target entity from the token binding; clients may send `agent_id` / `proxy_id` for defense in depth. Re-enroll rotates credential and task-signing material atomically; restart the agent or Propylaea service afterward so in-memory keys are refreshed.
- MCP JSON body limit reduced to 2 MiB.
- Compose publishes API/MCP on loopback by default; optional Caddy profile is HTTPS-only (no plaintext `:80`). Production `.env.example` uses `https://` WebAuthn origin so session cookies get `Secure`.

## Operator guidance

- Prefer AI permissions that combine `machine_ids` with tags for sensitive identities.
- Keep `agent_custom` tags out of authz unless you intentionally trust agent-reported custom labels.
- Protect backup passwords; treat fleet restore as high privilege.
- Place MCP behind private network / edge auth; do not rely on Host allowlists alone behind a reverse proxy.

## Granular authz model (1.2.0)

- **S1 TOCTOU**: `execution_policy_snapshot` frozen at enqueue; dispatch signs snapshot after live re-authorization.
- **S2 grant selection**: among matching assignments, the most restrictive grant is selected deterministically for approval flags, snapshot, and audit.
- **S3 auto-approve via request**: allowed server-side; UI requires explicit acknowledgment before Approve.
- **S4 admin vs standard**: mixed payloads rejected; admin requests require human approval; max one pending per class.
- **S12 catalog leakage**: self-service `authz-catalog` is filtered; full catalog requires admin commands.
- **S13 remove assignments**: allowed via permission request with lockout and audit-grant guards.
- **S14 orphan FK**: `matched_grant_assignment_id ON DELETE SET NULL`; dispatch cancels orphaned commands.
- **S15 max_concurrent**: enforced at enqueue against active queue depth.
- Grant approval-capable admin rights to at most one AI identity, or accept that several such identities can approve each other's requests. For sensitive deployments, keep approval on the operator UI and alert on `ai_permissions.request.approve` events whose actor is an AI identity.
- Treat `approve_command` as an operator duty: any operator with write access can approve queued commands (not admin-only). Limit operator accounts accordingly.
- Keep the Proxmox helper API target on loopback; TLS verification is skipped only for loopback API hosts with self-signed PVE certificates.
