# shell.run Rule

Strict constraints for remote shell execution.

## Forbidden

- `/bin/sh -c`, `bash -c`, or any shell-as-interpreter pattern (unless `"*"` is allowed for binaries)
- Shell metacharacters in argv: `;`, `|`, `&`, `` ` ``, `$`, `>`, `<`, newlines
- Relative binary paths without resolution to an allowed absolute path
- Working directories outside `shell_policy.allowed_cwd` (subdirectories of allowed paths are permitted)
- Elevation wrappers in argv: `/usr/bin/sudo`, `pkexec`, `runas` — use `"elevated": true` instead

## Required

- Explicit argv array with absolute binary path
- Respect `timeout_secs` and `max_output_bytes` from permissions
- For privileged commands: `elevated: true` plus `elevation_policy` allowlist (separate from normal shell policy)

Violations are rejected at enqueue time and again on the agent before exec.
