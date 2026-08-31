import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
export declare const executeCommandInputSchema: z.ZodObject<{
    machine_id: z.ZodString;
    command_name: z.ZodString;
    params: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
    wait: z.ZodDefault<z.ZodBoolean>;
    wait_timeout_secs: z.ZodOptional<z.ZodNumber>;
}, z.core.$strip>;
export declare function registerExecuteCommandTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
//# sourceMappingURL=execute_command.d.ts.map