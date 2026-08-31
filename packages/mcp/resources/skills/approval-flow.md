# Approval Flow

Some grant assignments require operator approval for `shell.run`, elevated execution, `agent.update`, `helper.install`, `system.reboot`, and other high-risk commands.

Auto-approval is controlled **per Grant Assignment** (`requires_approval_for_shell`, `requires_approval_for_elevated`), not at identity level. Read `hecate://context/permissions` to see flags on each assignment.

## pending_approval

When `execute_command` returns `pending_approval`:

1. Inform the user that an operator must approve the command in the Hecate UI.
2. Pull `get_command` periodically — do not re-enqueue the same command.
3. After approval, status moves to `queued` then proceeds normally.

## expired

Approval or execution may expire on timeout. Status becomes `expired`.

- Dispatched commands that never report a result are expired after the matched grant's `timeout_secs` plus a short grace period.
- Do not retry automatically with identical params without user confirmation.
- Review whether the command is still needed and within policy.

## cancelled

Operators or your identity may cancel queued commands before dispatch. Admins may also force-cancel `dispatched` / `running` commands stuck in the fleet action queue. Use `list_commands` to inspect history if needed.

## Admin queue tools

Identities with `admin.queue.approve` may approve **other** identities' `pending_approval` commands (never their own). Use `list_action_queue` for the fleet-wide view.

For permanent permission changes, see `hecate://skill/permission-requests`.
