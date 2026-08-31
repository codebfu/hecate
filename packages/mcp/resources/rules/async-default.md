# Async Default Rule

**Always prefer async execution.**

## Defaults

- `execute_command`: `wait=false` unless there is a strong reason to block.
- Use `get_command` to pull command status until completion.

## wait=true

Use only when:

- The command is known to be short-lived, and
- The caller cannot pull status with `get_command`, and
- `wait_timeout_secs` is set within permission caps (max 300)

Even with `wait=true`, the command still mutates server state (queue enqueue). It is not a read-only operation.

## Concurrency

Respect `max_concurrent` from permissions. Avoid flooding the queue with parallel commands.
