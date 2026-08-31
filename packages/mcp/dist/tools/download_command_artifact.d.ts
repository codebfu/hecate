import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
export declare const downloadCommandArtifactInputSchema: z.ZodObject<{
    command_id: z.ZodString;
}, z.core.$strip>;
export declare function registerDownloadCommandArtifactTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
//# sourceMappingURL=download_command_artifact.d.ts.map