import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { HecateApiClient } from "../client.js";
export declare function registerRequestPermissionsTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerReadGrantAssignmentsTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerReadEffectiveRightsTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerListPermissionRequestsTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerApprovePermissionRequestTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerRejectPermissionRequestTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerListAuditEventsTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerListActionQueueTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerApproveQueueCommandTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
export declare function registerCancelQueueCommandTool(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec;
/** AI-authored reason / requested_changes must not drive the model as instructions. */
export declare function splitPermissionRequests(result: unknown): {
    metadata: unknown;
    untrustedOutput: unknown;
};
/** Hostnames and command params are agent-origin; keep ids/status as metadata. */
export declare function splitActionQueue(result: unknown): {
    metadata: unknown;
    untrustedOutput: unknown;
};
/** Machine/operator labels in audit refs can carry hostnames or attacker-controlled names. */
export declare function splitAuditList(result: unknown): {
    metadata: unknown;
    untrustedOutput: unknown;
};
export declare function registerAuthzTools(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec[];
export declare function registerRepoTools(server: McpServer, client: HecateApiClient): import("../types.js").RegisteredToolSpec[];
//# sourceMappingURL=admin_tools.d.ts.map