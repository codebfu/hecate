import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { HecateApiClient } from "../client.js";
import type { MachineSummary } from "../types.js";
/** Split server metadata from agent-reported hostname. */
export declare function splitMachineSummary(machine: MachineSummary): {
    metadata: Record<string, unknown>;
    untrustedOutput: {
        hostname: string;
    };
};
export declare function registerGetMachineTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
//# sourceMappingURL=get_machine.d.ts.map