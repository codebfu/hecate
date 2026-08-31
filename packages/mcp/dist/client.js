// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later
export class HecateApiError extends Error {
    status;
    body;
    constructor(message, status, body) {
        super(message);
        this.status = status;
        this.body = body;
        this.name = "HecateApiError";
    }
}
export class HecateApiClient {
    baseUrl;
    internalToken;
    apiKey;
    fetchImpl;
    constructor(options) {
        this.baseUrl = options.baseUrl.replace(/\/$/, "");
        this.internalToken = options.internalToken;
        this.apiKey = options.apiKey;
        this.fetchImpl = options.fetchImpl ?? fetch;
    }
    withApiKey(apiKey) {
        return new HecateApiClient({
            baseUrl: this.baseUrl,
            internalToken: this.internalToken,
            apiKey,
            fetchImpl: this.fetchImpl,
        });
    }
    async listMachines() {
        const response = await this.request("GET", "/internal/machines");
        return response.machines;
    }
    async getMachine(machineId) {
        return this.request("GET", `/internal/machines/${encodeURIComponent(machineId)}`);
    }
    async executeCommand(body) {
        return this.request("POST", "/internal/commands", body);
    }
    async getCommand(commandId, wait = false, waitTimeoutSecs) {
        const params = new URLSearchParams();
        if (wait) {
            params.set("wait", "1");
            if (waitTimeoutSecs !== undefined) {
                params.set("wait_timeout_secs", String(waitTimeoutSecs));
            }
        }
        const query = params.toString();
        const path = `/internal/commands/${encodeURIComponent(commandId)}${query ? `?${query}` : ""}`;
        return this.request("GET", path);
    }
    async listCommands(filters) {
        const params = new URLSearchParams();
        if (filters?.machineId) {
            params.set("machine_id", filters.machineId);
        }
        if (filters?.status) {
            params.set("status", filters.status);
        }
        if (filters?.limit !== undefined) {
            params.set("limit", String(filters.limit));
        }
        if (filters?.offset !== undefined) {
            params.set("offset", String(filters.offset));
        }
        const query = params.toString();
        const path = `/internal/commands${query ? `?${query}` : ""}`;
        const response = await this.request("GET", path);
        if (Array.isArray(response)) {
            return response;
        }
        return response.commands ?? [];
    }
    async cancelCommand(commandId) {
        return this.request("POST", `/internal/commands/${encodeURIComponent(commandId)}/cancel`);
    }
    async getAiContext() {
        return this.request("GET", "/internal/ai-context");
    }
    /** S12 self-service catalog: assignable grants visible to the authenticated identity. */
    async getSelfServiceAuthzCatalog() {
        return this.request("GET", "/internal/authz-catalog");
    }
    /** Effective rights matrix for the authenticated identity (self only). */
    async getSelfEffectiveRights() {
        return this.request("GET", "/internal/effective-rights");
    }
    async executePlatformCommand(commandName, params = {}) {
        return this.request("POST", "/internal/platform-commands", {
            command_name: commandName,
            params,
        });
    }
    async executeAdminCommand(commandName, params = {}) {
        return this.request("POST", "/internal/admin-commands", {
            command_name: commandName,
            params,
        });
    }
    async uploadCommandArtifact(content, filename, sha256) {
        const headers = {
            Accept: "application/json",
            "Content-Type": "application/octet-stream",
            "X-Internal-Token": this.internalToken,
            "X-Filename": filename,
        };
        if (this.apiKey) {
            headers["X-AI-API-Key"] = this.apiKey;
        }
        if (sha256) {
            headers["X-SHA256"] = sha256;
        }
        const response = await this.fetchImpl(`${this.baseUrl}/internal/command-artifacts`, {
            method: "POST",
            headers,
            body: content,
        });
        const text = await response.text();
        const parsed = text.length > 0 ? safeJsonParse(text) : undefined;
        if (!response.ok) {
            throw new HecateApiError(`API POST /internal/command-artifacts failed with ${response.status}${formatErrorDetail(parsed ?? text)}`, response.status, parsed ?? text);
        }
        return parsed;
    }
    async downloadCommandArtifact(commandId) {
        const headers = {
            Accept: "application/octet-stream",
            "X-Internal-Token": this.internalToken,
        };
        if (this.apiKey) {
            headers["X-AI-API-Key"] = this.apiKey;
        }
        const response = await this.fetchImpl(`${this.baseUrl}/internal/commands/${encodeURIComponent(commandId)}/artifact`, { method: "GET", headers });
        if (!response.ok) {
            const text = await response.text();
            const parsed = safeJsonParse(text);
            throw new HecateApiError(`API GET /internal/commands/${commandId}/artifact failed with ${response.status}${formatErrorDetail(parsed)}`, response.status, parsed);
        }
        const sha256 = response.headers.get("x-sha256") ?? "";
        const bytes = Buffer.from(await response.arrayBuffer());
        return {
            command_id: commandId,
            sha256,
            size_bytes: bytes.length,
            content_base64: bytes.toString("base64"),
        };
    }
    async request(method, path, body) {
        const headers = {
            Accept: "application/json",
            "X-Internal-Token": this.internalToken,
        };
        if (this.apiKey) {
            headers["X-AI-API-Key"] = this.apiKey;
        }
        let payload;
        if (body !== undefined) {
            headers["Content-Type"] = "application/json";
            payload = JSON.stringify(body);
        }
        const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
            method,
            headers,
            body: payload,
        });
        const text = await response.text();
        const parsed = text.length > 0 ? safeJsonParse(text) : undefined;
        if (!response.ok) {
            throw new HecateApiError(`API ${method} ${path} failed with ${response.status}${formatErrorDetail(parsed ?? text)}`, response.status, parsed ?? text);
        }
        return parsed;
    }
}
function formatErrorDetail(body) {
    if (body == null || body === "") {
        return "";
    }
    if (typeof body === "string") {
        return `: ${body}`;
    }
    if (typeof body === "object" && body !== null) {
        const record = body;
        if (typeof record.message === "string" && record.message.length > 0) {
            return `: ${record.message}`;
        }
    }
    try {
        return `: ${JSON.stringify(body)}`;
    }
    catch {
        return "";
    }
}
function safeJsonParse(text) {
    try {
        return JSON.parse(text);
    }
    catch {
        return text;
    }
}
//# sourceMappingURL=client.js.map