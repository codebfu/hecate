// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later
import { z } from "zod";
import { findToolSpec } from "./specs.js";
import { formatUntrustedToolResult } from "./untrusted.js";
export const downloadCommandArtifactInputSchema = z.object({
    command_id: z.string().uuid(),
});
export function registerDownloadCommandArtifactTool(server, client) {
    const spec = findToolSpec("download_command_artifact");
    server.registerTool(spec.name, {
        description: `Download the output artifact for a completed file.pull, remote.download, desktop.screenshot, desktop.session.frame, desktop.clipboard.get (image), or proxmox.console.frame command.
Use after get_command shows status=completed and stdout JSON includes artifact_id.
Returns base64-encoded content plus sha256 metadata.`,
        inputSchema: downloadCommandArtifactInputSchema,
        annotations: spec.annotations,
    }, async ({ command_id }) => {
        const artifact = await client.downloadCommandArtifact(command_id);
        const { content_base64, ...metadata } = artifact;
        return formatUntrustedToolResult(metadata, { content_base64 });
    });
    return spec;
}
//# sourceMappingURL=download_command_artifact.js.map