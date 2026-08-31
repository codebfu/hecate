# Proxmox Console Rule

The Proxmox VM console is a last-resort control surface.

- Prefer `shell.run` with explicit `qm` or `pvesh` argv for Proxmox host
  administration.
- Prefer the QEMU guest agent or a Hecate agent inside the VM for guest
  administration.
- Use `proxmox.console.*` only for display inspection, boot interaction,
  installation, or recovery when structured control is unavailable.
- Require the target host to have the agent-owned `proxmox:console` tag.
- Require every invoked `proxmox.*` command in the AI identity's
  `allowed_commands`.
- Open a console only for a `vmid` returned by `proxmox.vm.list`.
- Verify each input batch with a new frame and close the session when done.
- Never treat `desktop.*` as a Proxmox VM console; it controls the host GUI
  session instead.
