// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
import { findToolSpec } from "./specs.js";
import { splitCommandDetail } from "./get_command.js";
import { formatUntrustedToolResult } from "./untrusted.js";

export const executeCommandInputSchema = z.object({
  machine_id: z.string().uuid(),
  command_name: z.string().min(1),
  params: z.record(z.string(), z.unknown()).default({}),
  wait: z.boolean().default(false),
  wait_timeout_secs: z.number().int().min(1).max(300).optional(),
});

export function registerExecuteCommandTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("execute_command")!;

  server.registerTool(
    spec.name,
    {
      description: `Enqueue a command on a machine. Async by default (wait=false). Use get_command to poll status.

For shell.run:
- Runs as the agent service user unless elevated=true (requires elevation_policy.enabled).
- elevated=true uses OS-specific elevation: sudo on Linux/macOS, admin service token on Windows.
- Never pass sudo, pkexec, or runas in argv; use the elevated flag instead.
- elevated=true always requires operator approval by default; set requires_approval_for_elevated=false on the identity to auto-approve.
- Read hecate://context/permissions, hecate://skill/authz-model, and hecate://skill/elevated-execution before privileged work.

For system.reboot:
- Reboots the OS; completes only after the agent goes offline then online again (up to ~15 minutes).
- Requires elevation_policy.enabled and operator approval by default.
- Always poll get_command asynchronously — do not use wait=true (MCP wait max is 300s).
- See hecate://skill/system-reboot.

For file.push:
- Upload first with upload_command_artifact, then enqueue with artifact_id and sha256.
- See hecate://skill/file-commands for file.pull, file.push, remote.download, and local file/folder manipulation workflows.

For desktop.* (computer-use):
- Requires hecate-lampad-desktop helper in the user GUI session (tag gui:ready).
- See hecate://skill/desktop-commands for screenshot, input, clipboard, windows, app.launch, desktop.shell.run, multi-monitor, and session workflows.
- desktop.screenshot / desktop.session.frame / clipboard image: download via download_command_artifact.

For helper.install:
- Requires an enrolled, active agent. Installs one missing helper package (desktop or proxmox) that is already synced for the machine OS/arch.
- Params: { "component": "desktop" | "proxmox" }. Check get_machine.installable_helpers first.
- High-risk: operator approval may be required (same gate as agent.update).
- Poll get_command; do not treat this as an agent self-update.

For proxmox.*:
- Prefer shell.run with qm/pvesh or an agent inside the VM; console use is for display, boot, installation, and recovery.
- Requires hecate-lampad-proxmox, the proxmox:console tag, and explicit proxmox.* permissions.
- Read hecate://rule/proxmox-console and hecate://skill/proxmox-console before use.
- proxmox.console.frame images are downloaded via download_command_artifact.`,
      inputSchema: executeCommandInputSchema,
      annotations: spec.annotations,
    },
    async ({ machine_id, command_name, params, wait, wait_timeout_secs }) => {
      const enqueued = await client.executeCommand({
        machine_id,
        command_name,
        params,
      });

      if (!wait) {
        return {
          content: [{ type: "text", text: JSON.stringify(enqueued, null, 2) }],
        };
      }

      const detail = await client.getCommand(
        enqueued.command_id,
        true,
        wait_timeout_secs,
      );
      const { metadata, untrustedOutput } = splitCommandDetail(detail);
      return formatUntrustedToolResult(metadata, untrustedOutput);
    },
  );

  return spec;
}
