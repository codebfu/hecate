# Proxmox VM Console

Use `proxmox.*` commands to inspect a Proxmox host and operate a virtual
machine's graphical console through `hecate-lampad-proxmox`.

Read `hecate://rule/proxmox-console` and `hecate://context/permissions` first.
The target machine must expose the agent-owned `proxmox:console` tag and the
required commands must be present in `allowed_commands`.

## Discovery

1. Run `proxmox.info` with `{}` to confirm helper and host capability.
2. Run `proxmox.vm.list` with `{}` to discover the numeric `vmid`.
3. Prefer guest-agent commands or `shell.run` with `qm`/`pvesh` for normal
   administration. Continue with the console only for display, boot, installer,
   or recovery work.

## Console session

1. Open:
   `proxmox.console.open` with
   `{ "vmid": 100, "fps": 2, "format": "png", "max_duration_secs": 600 }`.
   The server allocates `session_id`. Opening requires operator approval;
   follow-up commands for that session use approve-once.
2. Fetch:
   `proxmox.console.frame` with `{ "session_id": "..." }`, then download the
   returned image with `download_command_artifact`.
3. Interact:
   `proxmox.console.input` with
   `{ "session_id": "...", "events": [{ "action": "key", "key": "Enter" }] }`.
   Keep event batches small and fetch another frame to verify the result.
4. Close:
   `proxmox.console.close` with `{ "session_id": "..." }`.

Always close the session when finished. Sessions also expire at
`max_duration_secs`.

This is a Proxmox VM console, not the host user's desktop. `desktop.*` controls
the GUI session of the machine running the Hecate agent; `proxmox.console.*`
controls the display of a guest VM selected by `vmid`.
