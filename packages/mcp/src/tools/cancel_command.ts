// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
import { findToolSpec } from "./specs.js";

export function registerCancelCommandTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("cancel_command")!;

  server.registerTool(
    spec.name,
    {
      description: "Cancel a command when status is queued (not after dispatch).",
      inputSchema: z.object({
        command_id: z.string().uuid(),
      }),
      annotations: spec.annotations,
    },
    async ({ command_id }) => {
      const command = await client.cancelCommand(command_id);
      return {
        content: [{ type: "text", text: JSON.stringify(command, null, 2) }],
      };
    },
  );

  return spec;
}
