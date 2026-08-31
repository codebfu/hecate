// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later
import { z } from "zod";
import { findToolSpec } from "./specs.js";
import { formatUntrustedToolResult } from "./untrusted.js";
import { splitCommandDetail } from "./get_command.js";
const commandStatusSchema = z.enum([
    "pending_approval",
    "queued",
    "dispatched",
    "running",
    "completed",
    "failed",
    "expired",
    "cancelled",
]);
export function registerListCommandsTool(server, client) {
    const spec = findToolSpec("list_commands");
    server.registerTool(spec.name, {
        description: "List paginated commands for the current AI identity with optional filters.",
        inputSchema: z.object({
            machine_id: z.string().uuid().optional(),
            status: commandStatusSchema.optional(),
            limit: z.number().int().min(1).max(100).optional(),
            offset: z.number().int().min(0).optional(),
        }),
        annotations: spec.annotations,
    }, async ({ machine_id, status, limit, offset }) => {
        const commands = await client.listCommands({
            machineId: machine_id,
            status,
            limit,
            offset,
        });
        const split = commands.map(splitCommandDetail);
        return formatUntrustedToolResult({ commands: split.map((item) => item.metadata) }, { commands: split.map((item) => item.untrustedOutput) });
    });
    return spec;
}
//# sourceMappingURL=list_commands.js.map