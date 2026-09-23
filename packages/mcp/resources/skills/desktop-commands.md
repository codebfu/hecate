# Desktop Commands (computer-use)

Control a machine GUI through the session helper `hecate-lampad-desktop`.
Requires package installed, helper running in a logged-in GUI session, and
`gui:ready` (or explicit machine allowlist) plus `desktop.*` in `allowed_commands`.

These commands control the enrolled host's desktop, not a Proxmox guest VM
console. For a VM display selected by `vmid`, read
`hecate://skill/proxmox-console` and `hecate://rule/proxmox-console`.

Read `hecate://context/permissions` first. Prefer machines tagged `gui:ready`.

## Coordinates

- With `display` set: pixels relative to that monitor (origin top-left).
- Without `display`: virtual desktop coordinates from `desktop.info.virtual_desktop`.
- Use `desktop.info` monitors list for ids, geometry, scale, and primary.

## One-shot workflow

1. `desktop.info`
2. `desktop.screenshot` → `download_command_artifact`
3. `desktop.click` / `desktop.drag` / `desktop.type` / `desktop.key` / clipboard
4. Screenshot again to verify

### desktop.info

```json
{ "command_name": "desktop.info", "params": {} }
```

### desktop.screenshot

```json
{
  "command_name": "desktop.screenshot",
  "params": { "display": 0, "region": { "x": 0, "y": 0, "width": 800, "height": 600 } }
}
```

Stdout includes `artifact_id`, `sha256`, `width`, `height`, `format`, `display_id`.
Download with `download_command_artifact`.

### Input

- `desktop.move` — `{ "x", "y", "relative"?: false, "display"?: 0 }`
- `desktop.click` — `{ "x", "y", "button"?: "left"|"right"|"middle", "count"?: 1, "display"?: 0 }`
- `desktop.scroll` — `{ "x", "y", "dx"?: 0, "dy"?: -3, "display"?: 0 }`
- `desktop.drag` — `{ "from": {"x","y"}, "to": {"x","y"}, "button"?: "left", "duration_ms"?: 200 }`
- `desktop.type` — `{ "text": "hello", "delay_ms"?: 0 }`
- `desktop.key` — `{ "key": "Return", "modifiers"?: ["ctrl"], "action"?: "tap" }`

### Clipboard

- `desktop.clipboard.get` — `{ "format"?: "text"|"image" }` (image → artifact)
- `desktop.clipboard.set` text — `{ "text": "..." }`
- `desktop.clipboard.set` image — upload via `upload_command_artifact`, then
  `{ "artifact_id", "sha256", "format": "image/png" }`

## Session workflow (streaming frames via artifacts)

1. `desktop.session.open` — `{ "fps"?: 2, "max_duration_secs"?: 600, "display"?: 0, "format"?: "png"|"jpeg" }`
   - Server allocates `session_id` (also returned in stdout).
   - Operator approval applies to open; follow-ups are approve-once auto-queued.
2. Loop: `desktop.session.frame` `{ "session_id" }` → download artifact → reason →
   `desktop.session.input` `{ "session_id", "events": [ {"action":"click","x":10,"y":20}, ... ] }`
3. `desktop.session.close` `{ "session_id" }`

Atomic `desktop.click` etc. still work without a session.

## App / window / GUI shell

### desktop.app.launch

```json
{
  "command_name": "desktop.app.launch",
  "params": { "app": "mousepad", "args": [], "wait_window_ms": 5000 }
}
```

- Linux: executable name/path or `.desktop` id
- macOS: app name or bundle id
- Windows: exe path or registered app name
- `app` must be present in `shell_policy.allowed_binaries` (exact match, same policy as `shell.run` / `desktop.shell.run`; `"*"` allows any)
- Optional `cwd` is checked against `shell_policy.allowed_cwd` when provided
- Optional `wait_window_ms`: poll for a related window after launch (timeout still returns `launched: true`)
- Typed / keyed input (`desktop.type`, `desktop.key`) and launch params are also scanned by content policy: references to shells / LOLBins outside the allowlist are rejected
- Nested `desktop.session.input` events (`text` / `key`) are scanned the same way
- A sliding keystroke buffer (per identity + machine, 256 chars, 5 min idle TTL; cleared on `desktop.window.focus`) also scans fragmented typing across requests
- OS launcher hotkeys (`Win+R`, `Alt+F2`, `Ctrl+Alt+T`, `Ctrl+Shift+Esc`, `Win+letter`, …) are **blocked by default**; set `desktop_policy.allow_os_launchers: true` only after explicit admin review
- Permission requests that include desktop injection commands (`desktop.type` / `key` / `click` / `app.launch` / `session.input` / `session.open`) are classified **Admin** for human review
- The agent re-validates `app` against the signed task `shell_policy` before IPC; the desktop helper re-validates against its local allowlist (same files as `shell.run`)
- GUI apps inherit the **interactive session user**, not agent LocalSystem/root. Keep that session account standard (non-Administrator / no broad NOPASSWD). Route real elevation through `shell.run` / `desktop.shell.run` with `elevated:true` + `elevation_policy`

### desktop.window.list / focus / wait

- `desktop.window.list` — `{ "include_hidden"?: false }`
- `desktop.window.focus` — exactly one of `{ "id" }` / `{ "title" }` / `{ "app" }` (title = case-insensitive substring)
- `desktop.window.wait` — same match fields + `{ "timeout_ms"?: 15000, "state"?: "visible"|"focused" }`

### desktop.shell.run

Run an explicit argv **inside the GUI session helper** (inherits `DISPLAY` / user env). Not elevated.

```json
{
  "command_name": "desktop.shell.run",
  "params": { "argv": ["/usr/bin/xdg-user-dir", "DESKTOP"], "timeout_secs": 30 }
}
```

Stdout: `{ "stdout", "stderr", "exit_code" }`. Prefer this over agent `shell.run` when you need session GUI environment.

## Prerequisites / tags

| Tag | Meaning |
|-----|---------|
| `gui:ready` | Helper connected and display usable |
| `gui:none` | Helper package present but no active GUI session |
| `display:x11` / `wayland` / `windows` / `macos` | Active backend |

Helper package is separate from the agent service (`hecate-lampad-desktop`).
`helper.install` / package postinst on Linux grant `hecate-ipc` membership and
start the user-session helper when a GUI session is already logged in (same idea
as the macOS LaunchAgent / Windows logon task). Without a live GUI session the
package still installs and activates on next graphical login (`gui:none` until then).
Without the helper, commands fail with `helper_unavailable` / `no_active_gui_session`.

## OS permissions

- Linux: X11 primary; Wayland-only sessions return `display_unsupported` for window/app APIs.
- macOS: Accessibility + Screen Recording TCC for the helper (window focus may need Accessibility).
- Windows: user-session helper (not LocalSystem) for input/capture/window control.

### Session privilege checklist (ops)

- Use a **standard** interactive account for the GUI session the desktop helper joins — not the built-in Administrator and not a user with broad passwordless sudo.
- Keep UAC / Admin Approval Mode enabled on Windows session accounts used for automation.
- Grant elevated work only via `elevation_policy` + `elevated:true` on `shell.run` / `desktop.shell.run`, never by making the GUI session itself privileged.
- Treat `desktop_policy.allow_os_launchers` as an intentional admin override, not a default for jail-style grants.

Stable error codes include `not_found`, `timeout`, `permission_denied`, `display_unsupported`.
