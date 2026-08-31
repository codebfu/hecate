// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later
import { z } from "zod";
import { findToolSpec } from "./specs.js";
import { formatUntrustedToolResult } from "./untrusted.js";
/** Split server metadata from agent-origin stdout/stderr. */
export function splitCommandDetail(command) {
    const { result, ...rest } = command;
    if (!result) {
        return { metadata: { ...rest }, untrustedOutput: null };
    }
    const { stdout, stderr, ...resultMeta } = result;
    return {
        metadata: { ...rest, result: resultMeta },
        untrustedOutput: { stdout, stderr },
    };
}
export function registerGetCommandTool(server, client) {
    const spec = findToolSpec("get_command");
    server.registerTool(spec.name, {
        description: "Get command status and result for a command_id owned by the current AI identity.",
        inputSchema: z.object({
            command_id: z.string().uuid(),
        }),
        annotations: spec.annotations,
    }, async ({ command_id }) => {
        const command = await client.getCommand(command_id);
        const { metadata, untrustedOutput } = splitCommandDetail(command);
        return formatUntrustedToolResult(metadata, untrustedOutput);
    });
    return spec;
}
//# sourceMappingURL=get_command.js.map