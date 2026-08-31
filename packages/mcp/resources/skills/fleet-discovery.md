# Fleet Discovery

Choose a target machine before enqueueing commands.

## Steps

1. **`list_machines`** — returns machines authorized for your AI identity (already filtered server-side by effective fleet scope).
2. **`get_machine(machine_id)`** — inspect hostname, OS, arch, tags, online status, agent version, last seen, and `installable_helpers` (missing helpers with a synced package for that OS/arch).
3. Prefer machines with recent `last_seen_at` and matching tags for the task.

## Fleet scopes and permissions

Machine access is granted through **Fleet Scopes** linked to your **Grant Assignments**, not a flat `machine_ids` list on the identity. Read `hecate://context/effective-rights` or `hecate://context/permissions` to see your current scope.

If a machine is not in scope, you do not have access — do not attempt workarounds. Admins with `admin.authz.fleet_scopes.preview` can use `preview_fleet_scope` to inspect scope membership.

## Online vs offline

Offline machines may still accept queued commands, but execution waits until the agent pulls again. Check status before retrying failed dispatches.

See `hecate://skill/grant-discovery` when you need broader fleet access via permission requests.
