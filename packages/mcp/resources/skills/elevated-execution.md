# Elevated Execution

Privileged (root/admin) commands use the **`elevated: true`** flag on `shell.run`. Never pass `sudo`, `pkexec`, or `runas` in `argv`.

## When to use

| Need | Approach |
|------|----------|
| Read-only host metadata | `system.info` (no elevation) |
| Normal user-level command | `shell.run` with `elevated: false` (default) |
| Root/admin command | `shell.run` with `elevated: true` |
| Reboot the host OS | `system.reboot` (always elevated; completes after offline → online) |

## Prerequisites

1. Read `hecate://context/permissions` — `capabilities.elevation_enabled` must be `true`.
2. `argv[0]` must be in `capabilities.elevation_allowed_binaries` (or `"*"`).
3. `elevated=true` commands require operator approval by default (`requires_approval_for_elevated` on the identity). Auto-approve is possible when that flag is disabled.

## OS behavior

| OS | Method | Operator setup |
|----|--------|----------------|
| **Linux** | `sudo -n` (non-interactive) | Installed to `/etc/sudoers.d/hecate-lampad` by the deb package. The systemd unit must set `ProtectSystem=no` and must **not** use `ReadWritePaths=` (incompatible pair → exit 226/NAMESPACE; strict mounts break sudo/dpkg). |
| **macOS** | `sudo -n` | Installed to `/etc/sudoers.d/hecate-lampad` by the pkg/`install.sh`. Agent updates schedule a root LaunchDaemon; blocking helper installs need sudo in the service user session. |
| **Windows** | SYSTEM scheduled task | Service must run as `LocalSystem` (MSI `ServiceInstall`). Package updates run via a one-shot SYSTEM `schtasks` job outside the service process tree. |

## Example

```json
{
  "command_name": "shell.run",
  "params": {
    "argv": ["/usr/bin/apt", "update"],
    "elevated": true,
    "cwd": "/"
  }
}
```

## Discover live state

Run `system.info` on the machine. Check `agent_runtime`:

- `effective_user` — current service user
- `is_privileged` — whether the agent process is already root/admin
- `elevation.available` — whether non-interactive elevation works right now (Linux/macOS: sudo auth plus a writable-path probe; fails when the service sandbox blocks root writes)
- `elevation.method` — `sudo` or `windows_admin`

`get_machine` / `list_machines` include static `agent_runtime` hints per OS; use `system.info` for live probes.

## Linux systemd note

`shell.run` and `agent.update` spawn child processes (including `sudo -n -- …`) inside the agent service cgroup. Never use `ReadWritePaths=` on the unit: it implies `ProtectSystem=strict` and breaks elevated commands and package self-updates. Do not set `ProtectSystem=no` together with `ReadWritePaths=` — systemd fails to start the service (exit 226/NAMESPACE). Linux deb packages ship `ProtectSystem=no` without `ReadWritePaths=`.
