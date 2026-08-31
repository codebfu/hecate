import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
export declare const uploadCommandArtifactInputSchema: z.ZodObject<{
    content_base64: z.ZodString;
    sha256: z.ZodOptional<z.ZodString>;
    filename: z.ZodDefault<z.ZodString>;
}, z.core.$strip>;
export declare function registerUploadCommandArtifactTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
//# sourceMappingURL=upload_command_artifact.d.ts.map