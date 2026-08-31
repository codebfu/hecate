import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { HecateApiClient } from "./client.js";
export interface ServerConfig {
    port: number;
    host: string;
    apiBaseUrl: string;
    internalToken: string;
    allowedHosts: string[];
    /** Public origin for MCP icons (UI static assets), e.g. https://hecate.example:18443 */
    publicBaseUrl?: string;
}
type SessionEntry = {
    transport: StreamableHTTPServerTransport;
    apiKeyHash: string;
};
export declare function loadConfigFromEnv(): ServerConfig;
export declare function extractBearerToken(authHeader: string | undefined): string | undefined;
export declare function hashApiKey(apiKey: string): string;
export declare function verifySessionBearer(entry: SessionEntry, apiKey: string | undefined): boolean;
export declare function createMcpServer(apiClient: HecateApiClient, options?: {
    publicBaseUrl?: string;
}): McpServer;
export declare function hostHeaderValidation(allowedHostnames: string[]): (req: express.Request, res: express.Response, next: express.NextFunction) => void;
export declare function createApp(config: ServerConfig): import("express-serve-static-core").Express;
export declare function startServer(config?: ServerConfig): import("http").Server<typeof import("http").IncomingMessage, typeof import("http").ServerResponse>;
export {};
//# sourceMappingURL=index.d.ts.map