// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
import { findToolSpec } from "./specs.js";
import { splitMachineSummary } from "./get_machine.js";
import { formatUntrustedToolResult } from "./untrusted.js";

export function registerListMachinesTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("list_machines")!;

  server.registerTool(
    spec.name,
    {
      description:
        "List machines authorized for the current AI identity. Each entry includes agent_runtime hints for OS-dependent elevation (use elevated=true in shell.run, never sudo in argv).",
      inputSchema: z.object({}),
      annotations: spec.annotations,
    },
    async () => {
      const machines = await client.listMachines();
      const split = machines.map((machine) => {
        const { metadata, untrustedOutput } = splitMachineSummary(machine);
        return {
          metadata,
          untrusted: { id: machine.id, ...untrustedOutput },
        };
      });
      return formatUntrustedToolResult(
        { machines: split.map((entry) => entry.metadata) },
        { machines: split.map((entry) => entry.untrusted) },
      );
    },
  );

  return spec;
}
