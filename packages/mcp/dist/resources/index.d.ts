import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { HecateApiClient } from "../client.js";
export interface StaticResourceDefinition {
    uri: string;
    name: string;
    description: string;
    relativePath: string;
    mimeType: string;
}
export declare const STATIC_RESOURCES: StaticResourceDefinition[];
export declare const DYNAMIC_PERMISSIONS_RESOURCE: {
    uri: string;
    name: string;
    description: string;
    mimeType: string;
};
export declare const DYNAMIC_AUTHZ_CATALOG_RESOURCE: {
    uri: string;
    name: string;
    description: string;
    mimeType: string;
};
export declare const DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE: {
    uri: string;
    name: string;
    description: string;
    mimeType: string;
};
export declare function registerResources(server: McpServer, client: HecateApiClient): void;
export declare function listAllResourceDefinitions(): {
    uri: string;
    name: string;
    description: string;
    mimeType: string;
}[];
export declare function readStaticResource(relativePath: string): Promise<string>;
export declare function resolveResourcePath(relativePath: string): string;
//# sourceMappingURL=index.d.ts.map