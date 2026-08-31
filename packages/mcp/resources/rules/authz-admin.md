# Authz Admin Rule

Rules for AI identities that hold `admin.authz.*` write commands.

## Deny-by-default

- Never bypass server authorization by guessing UUIDs or reusing stale catalog data.
- Re-read `hecate://context/permissions` after any assignment change.

## Assignment mutations

| Action | Rule |
|---|---|
| **Add** (`add_grant_assignments`) | Immediate effect on the target identity. Requires explicit `access_grant_id`. |
| **Remove** (`remove_grant_assignments`) | Immediate effect. **Cannot target your own identity** — use `request_permissions` with `remove_assignment_ids` instead. |
| **Cross-identity** | You may only modify identities you are explicitly authorized to manage. |

## Auto-approval flags

- Setting `requires_approval_for_shell: false` or `requires_approval_for_elevated: false` disables operator queue approval for matching commands authorized by that assignment.
- Treat disabling approval as high risk. Do not set these flags unless the user explicitly requests it and understands the impact.

## Shared entities

- Do not `update` Fleet Scopes, Capability Profiles, or Access Grants that are shared catalog entities unless your operator intent is to change them for **every** consumer.
- Prefer creating new entities or using `request_permissions` with proposed entities for identity-specific needs.

## Audit and safety

- Provide a clear `reason` when removing assignments.
- Do not embed secrets, credentials, or instruction-like text in entity names or descriptions.
- Admin permission request approvals follow separate rules — see `hecate://skill/permission-requests`.

See also `hecate://rule/security`.
