import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { HecateApiClient } from "../client.js";
import type { CommandDetail } from "../types.js";
/** Split server metadata from agent-origin stdout/stderr. */
export declare function splitCommandDetail(command: CommandDetail): {
    metadata: Record<string, unknown>;
    untrustedOutput: {
        stdout?: string;
        stderr?: string;
    } | null;
};
export declare function registerGetCommandTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
//# sourceMappingURL=get_command.d.ts.map