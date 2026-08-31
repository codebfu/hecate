// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later
import { createHash, randomUUID } from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { HecateApiClient } from "./client.js";
import { getServerIcons, resolvePublicBaseUrl } from "./icons.js";
import { registerResources } from "./resources/index.js";
import { registerTools } from "./tools/index.js";
export function loadConfigFromEnv() {
    return {
        port: Number(process.env.MCP_PORT ?? "3100"),
        host: process.env.MCP_HOST ?? "127.0.0.1",
        apiBaseUrl: process.env.HECATE_API_URL ?? "http://127.0.0.1:8080",
        internalToken: process.env.HECATE_INTERNAL_TOKEN ?? "",
        allowedHosts: (process.env.MCP_ALLOWED_HOSTS ?? "127.0.0.1,localhost,[::1]")
            .split(",")
            .map((value) => value.trim())
            .filter(Boolean),
        publicBaseUrl: process.env.HECATE_PUBLIC_BASE_URL?.trim() || undefined,
    };
}
export function extractBearerToken(authHeader) {
    if (!authHeader?.startsWith("Bearer ")) {
        return undefined;
    }
    const token = authHeader.slice("Bearer ".length).trim();
    return token.length > 0 ? token : undefined;
}
export function hashApiKey(apiKey) {
    return createHash("sha256").update(apiKey).digest("hex");
}
export function verifySessionBearer(entry, apiKey) {
    if (!apiKey) {
        return false;
    }
    return entry.apiKeyHash === hashApiKey(apiKey);
}
export function createMcpServer(apiClient, options = {}) {
    const icons = options.publicBaseUrl ? getServerIcons(options.publicBaseUrl) : [];
    const server = new McpServer({
        name: "hecate-mcp",
        version: "0.1.0",
        ...(icons.length > 0 ? { icons } : {}),
    });
    registerTools(server, apiClient);
    registerResources(server, apiClient);
    return server;
}
export function hostHeaderValidation(allowedHostnames) {
    return (req, res, next) => {
        const host = req.headers.host?.split(":")[0]?.toLowerCase();
        if (!host || !allowedHostnames.map((h) => h.toLowerCase()).includes(host)) {
            res.status(403).json({
                jsonrpc: "2.0",
                error: { code: -32000, message: "Forbidden: invalid Host header" },
                id: null,
            });
            return;
        }
        next();
    };
}
export function createApp(config) {
    const app = express();
    app.use(express.json({ limit: "2mb" }));
    app.use(hostHeaderValidation(config.allowedHosts));
    const sessions = new Map();
    app.get("/health", (_req, res) => {
        res.json({ status: "ok", service: "hecate-mcp" });
    });
    app.post("/mcp", async (req, res) => {
        if (!config.internalToken) {
            res.status(503).json({
                jsonrpc: "2.0",
                error: { code: -32000, message: "MCP server misconfigured: missing internal token" },
                id: null,
            });
            return;
        }
        const apiKey = extractBearerToken(req.headers.authorization);
        if (!apiKey) {
            res.status(401).json({
                jsonrpc: "2.0",
                error: { code: -32000, message: "Unauthorized: Bearer API key required" },
                id: null,
            });
            return;
        }
        const sessionId = req.headers["mcp-session-id"];
        let transport;
        if (sessionId && sessions.has(sessionId)) {
            const entry = sessions.get(sessionId);
            if (!verifySessionBearer(entry, apiKey)) {
                res.status(401).json({
                    jsonrpc: "2.0",
                    error: { code: -32000, message: "Unauthorized: Bearer API key mismatch" },
                    id: null,
                });
                return;
            }
            transport = entry.transport;
        }
        else if (!sessionId && isInitializeRequest(req.body)) {
            transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
                onsessioninitialized: (newSessionId) => {
                    sessions.set(newSessionId, {
                        transport,
                        apiKeyHash: hashApiKey(apiKey),
                    });
                },
            });
            transport.onclose = () => {
                if (transport.sessionId) {
                    sessions.delete(transport.sessionId);
                }
            };
            const apiClient = new HecateApiClient({
                baseUrl: config.apiBaseUrl,
                internalToken: config.internalToken,
                apiKey,
            });
            const publicBaseUrl = resolvePublicBaseUrl(config.publicBaseUrl, req.headers.host, typeof req.headers["x-forwarded-proto"] === "string"
                ? req.headers["x-forwarded-proto"]
                : undefined);
            const server = createMcpServer(apiClient, { publicBaseUrl });
            await server.connect(transport);
        }
        else {
            res.status(400).json({
                jsonrpc: "2.0",
                error: { code: -32000, message: "Bad Request: invalid or missing session" },
                id: null,
            });
            return;
        }
        await transport.handleRequest(req, res, req.body);
    });
    app.get("/mcp", async (req, res) => {
        const apiKey = extractBearerToken(req.headers.authorization);
        const sessionId = req.headers["mcp-session-id"];
        if (!sessionId || !sessions.has(sessionId)) {
            res.status(400).json({
                jsonrpc: "2.0",
                error: { code: -32000, message: "Bad Request: no valid session ID" },
                id: null,
            });
            return;
        }
        const entry = sessions.get(sessionId);
        if (!verifySessionBearer(entry, apiKey)) {
            res.status(401).json({
                jsonrpc: "2.0",
                error: { code: -32000, message: "Unauthorized: Bearer API key required" },
                id: null,
            });
            return;
        }
        await entry.transport.handleRequest(req, res);
    });
    app.delete("/mcp", async (req, res) => {
        const apiKey = extractBearerToken(req.headers.authorization);
        const sessionId = req.headers["mcp-session-id"];
        if (!sessionId || !sessions.has(sessionId)) {
            res.status(400).json({
                jsonrpc: "2.0",
                error: { code: -32000, message: "Bad Request: no valid session ID" },
                id: null,
            });
            return;
        }
        const entry = sessions.get(sessionId);
        if (!verifySessionBearer(entry, apiKey)) {
            res.status(401).json({
                jsonrpc: "2.0",
                error: { code: -32000, message: "Unauthorized: Bearer API key required" },
                id: null,
            });
            return;
        }
        await entry.transport.handleRequest(req, res);
    });
    return app;
}
export function startServer(config = loadConfigFromEnv()) {
    const app = createApp(config);
    return app.listen(config.port, config.host, () => {
        console.log(`Hecate MCP listening on http://${config.host}:${config.port}/mcp`);
    });
}
import { pathToFileURL } from "node:url";
const entrypoint = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (entrypoint && import.meta.url === entrypoint) {
    startServer();
}
//# sourceMappingURL=index.js.map