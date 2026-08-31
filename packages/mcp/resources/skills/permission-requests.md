# Permission Requests

AI identities can request permanent permission changes via `request_permissions` (platform command `permissions.request`). Every identity receives this capability through a hidden bootstrap grant assignment (not shown in the operator UI).

## Submitting a request

1. Read `hecate://skill/authz-model` and `hecate://skill/grant-discovery`.
2. Read current assignments from `hecate://context/permissions`.
3. Read assignable grants from `hecate://context/authz-catalog`.
4. Build an **additive** `requested_changes` object (not a monolithic rules replacement):
   - `add_assignments[]` — reference existing grants `{ kind: "id", id: "<uuid>" }` or proposed grants `{ kind: "proposed", key: "..." }`
   - `propose_fleet_scopes[]`, `propose_capability_profiles[]`, `propose_access_grants[]` — when catalog entities do not exist
   - `remove_assignment_ids[]` — optional removals (operator approval required)
5. Call `request_permissions` with **`reason`** (required, min 8 characters) and `requested_changes`.
6. Only one pending standard request per identity — a second submit returns conflict.

## Payload example (Tier 1 — existing grant)

```json
{
  "reason": "Need read-only fleet visibility for incident triage",
  "requested_changes": {
    "add_assignments": [
      {
        "access_grant": { "kind": "id", "id": "00000000-0000-4000-8000-000000000001" }
      }
    ]
  }
}
```

## After submission

- An operator reviews requests in the Hecate UI **Permission requests** page.
- An identity with `admin.permissions.request.approve` may approve **other** identities' **standard** requests, never its own.
- On approval, proposed entities are materialized and assignments are applied additively.

## Rejection

Operators or an AI with `admin.permissions.request.reject` can reject without changing current assignments.

## Related tools

- `list_permission_requests` — paginated list (default status: pending)
- `read_grant_assignments` — read assignments for self or another identity (admin)
- `read_effective_rights` — computed rights matrix (admin; prefer `hecate://context/effective-rights` for self)

See also `hecate://skill/approval-flow` for command queue approval (separate from permission requests).
