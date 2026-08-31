# Grant Discovery

Use this workflow when an identity needs **permanent** access beyond its current grant assignments.

## Steps

1. Read `hecate://skill/authz-model` for terminology.
2. Read `hecate://context/permissions` — current resolved assignments and capability summary.
3. Read `hecate://context/authz-catalog` — reusable access grants you may reference (S12 self-service view).
4. Read `hecate://context/effective-rights` when you need the full computed matrix before acting.

## Choosing a path

| Situation | Action |
|---|---|
| An existing Access Grant in the catalog covers the need | **Tier 1** — `request_permissions` with `add_assignments` referencing `{ kind: "id", id: "<grant-uuid>" }` |
| Scope + profile exist but no grant | Propose a new Access Grant linking existing entities |
| Profile or scope missing | Propose new entities in `requested_changes` (see `hecate://skill/permission-requests`) |

## Tools

- `read_grant_assignments` / `read_effective_rights` — admin read tools when you manage other identities
- `list_authz_catalog`, `list_access_grants`, `get_access_grant` — admin catalog exploration
- `preview_fleet_scope` — see which machines a scope resolves to (requires admin permission)

## Fleet targeting

Machine access comes from **Fleet Scopes** attached to Access Grants — not from a flat `machine_ids` list on the identity. Use `list_machines` only after your effective rights include the target machines.

See `hecate://skill/fleet-discovery` for choosing a machine at execution time.
