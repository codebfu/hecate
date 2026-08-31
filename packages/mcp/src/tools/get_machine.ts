// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
import type { MachineSummary } from "../types.js";
import { findToolSpec } from "./specs.js";
import { formatUntrustedToolResult } from "./untrusted.js";

/** Split server metadata from agent-reported hostname. */
export function splitMachineSummary(machine: MachineSummary): {
  metadata: Record<string, unknown>;
  untrustedOutput: { hostname: string };
} {
  const { hostname, ...rest } = machine;
  return {
    metadata: { ...rest },
    untrustedOutput: { hostname },
  };
}

export function registerGetMachineTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("get_machine")!;

  server.registerTool(
    spec.name,
    {
      description:
        "Get machine details: status, last seen, OS, tags, agent version, installable_helpers, and agent_runtime hints (elevation method per platform). Call system.info for live effective_user and elevation availability.",
      inputSchema: z.object({
        machine_id: z.string().uuid(),
      }),
      annotations: spec.annotations,
    },
    async ({ machine_id }) => {
      const machine = await client.getMachine(machine_id);
      const { metadata, untrustedOutput } = splitMachineSummary(machine);
      return formatUntrustedToolResult(metadata, untrustedOutput);
    },
  );

  return spec;
}
