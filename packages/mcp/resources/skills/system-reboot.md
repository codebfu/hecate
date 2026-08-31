# system.reboot

Reboot the machine operating system. The command is **complete only after** the agent restarts and heartbeats again — not when the reboot is merely requested.

## Requirements

- `system.reboot` in `allowed_commands`
- `elevation_policy.enabled = true` (reboot always runs elevated)
- Operator approval (high-risk), unless the identity has approval waived for this command

## How to run

```json
{
  "machine_id": "<uuid>",
  "command_name": "system.reboot",
  "params": {}
}
```

Use async flow (`wait=false`). Poll `get_command` until a terminal status. Default server timeout is **900 seconds** (15 minutes) to allow slow boots.

Do **not** rely on a single `wait=true` call with `wait_timeout_secs` ≤ 300 — that is shorter than a typical reboot cycle. Keep pulling `get_command`.

## Status meaning

| Status | Meaning |
|--------|---------|
| `pending_approval` | Waiting for operator |
| `queued` / `dispatched` / `running` | Reboot requested or in progress (`reboot_phase`: `initiated` → `agent_down`) |
| `completed` | Agent process restarted after the claim (uptime reset and/or offline→online) |
| `failed` | Reboot could not be started (permissions, elevation, etc.) |
| `expired` | Machine did not return within the timeout |

## Completion detection

The server completes the command when either:

1. **Uptime reset (preferred for fast VMs)** — a heartbeat reports `uptime_secs` lower than the age of the reboot claim (or lower than the previous sample), proving the agent process restarted; or
2. **Offline → online** — `last_seen_at` goes stale (~5s for in-flight reboot), then a fresh heartbeat arrives.

## Notes

- Blocks other commands on that machine while active.
- Action Queue only lists **active** statuses; once completed/expired the row leaves that page (audit still records enqueue).
- Platforms: Linux, macOS, Windows.
