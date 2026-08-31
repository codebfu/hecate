# shell.run Usage

`shell.run` executes a process with **explicit argv** — no shell interpretation.

## Valid params shape

```json
{
  "argv": ["/usr/bin/uname", "-a"],
  "cwd": "/home/hecate-lampad",
  "env": {},
  "elevated": false
}
```

## Rules

- `argv[0]` must be an absolute path to an allowed binary (see permissions `shell_policy.allowed_binaries`).
- Use `"*"` in `allowed_binaries` to allow any binary (metacharacter checks still apply).
- `cwd` must fall under `shell_policy.allowed_cwd` when specified. Each allowed directory also permits its subdirectories.
- Environment variables are not restricted.
- Do not pass shell wrappers (`/bin/sh`, `bash -c`, etc.) unless `"*"` is allowed for binaries.
- Do not pass `sudo`, `pkexec`, or `runas` in argv — use `"elevated": true` instead (see `hecate://skill/elevated-execution`).

## Privilege level

- **Default (`elevated: false`)**: runs as the agent service user (non-privileged).
- **`elevated: true`**: runs with root/admin privileges via OS-specific elevation. Requires `elevation_policy.enabled` and a separate binary allowlist. Requires operator approval by default (`requires_approval_for_elevated` on the identity).

## Before calling

1. Read `hecate://rule/shell-run`.
2. Read `hecate://context/permissions` for allowlists and limits.
3. Read `hecate://skill/elevated-execution` when admin/root access is needed.
4. Use `system.info` when read-only host metadata is sufficient, or to probe `agent_runtime.elevation.available`.
