// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type {
  AiContextResponse,
  AuthzCatalogResponse,
  CommandArtifactDownloadResponse,
  CommandArtifactUploadResponse,
  CommandDetail,
  CommandEnqueueResponse,
  EffectiveRightsReport,
  MachineSummary,
  AdminCommandResponse,
  PlatformCommandResponse,
} from "./types.js";

export interface HecateApiClientOptions {
  baseUrl: string;
  internalToken: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
}

export class HecateApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "HecateApiError";
  }
}

export class HecateApiClient {
  private readonly baseUrl: string;
  private readonly internalToken: string;
  private readonly apiKey?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: HecateApiClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.internalToken = options.internalToken;
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  withApiKey(apiKey: string): HecateApiClient {
    return new HecateApiClient({
      baseUrl: this.baseUrl,
      internalToken: this.internalToken,
      apiKey,
      fetchImpl: this.fetchImpl,
    });
  }

  async listMachines(): Promise<MachineSummary[]> {
    const response = await this.request<{ machines: MachineSummary[] }>("GET", "/internal/machines");
    return response.machines;
  }

  async getMachine(machineId: string): Promise<MachineSummary> {
    return this.request<MachineSummary>("GET", `/internal/machines/${encodeURIComponent(machineId)}`);
  }

  async executeCommand(body: ExecuteCommandRequest): Promise<CommandEnqueueResponse> {
    return this.request<CommandEnqueueResponse>("POST", "/internal/commands", body);
  }

  async getCommand(commandId: string, wait = false, waitTimeoutSecs?: number): Promise<CommandDetail> {
    const params = new URLSearchParams();
    if (wait) {
      params.set("wait", "1");
      if (waitTimeoutSecs !== undefined) {
        params.set("wait_timeout_secs", String(waitTimeoutSecs));
      }
    }
    const query = params.toString();
    const path = `/internal/commands/${encodeURIComponent(commandId)}${query ? `?${query}` : ""}`;
    return this.request<CommandDetail>("GET", path);
  }

  async listCommands(filters?: ListCommandsFilters): Promise<CommandDetail[]> {
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
    const response = await this.request<CommandDetail[] | { commands?: CommandDetail[] }>(
      "GET",
      path,
    );
    if (Array.isArray(response)) {
      return response;
    }
    return response.commands ?? [];
  }

  async cancelCommand(commandId: string): Promise<{ ok: boolean }> {
    return this.request<{ ok: boolean }>(
      "POST",
      `/internal/commands/${encodeURIComponent(commandId)}/cancel`,
    );
  }

  async getAiContext(): Promise<AiContextResponse> {
    return this.request<AiContextResponse>("GET", "/internal/ai-context");
  }

  /** S12 self-service catalog: assignable grants visible to the authenticated identity. */
  async getSelfServiceAuthzCatalog(): Promise<AuthzCatalogResponse> {
    return this.request<AuthzCatalogResponse>("GET", "/internal/authz-catalog");
  }

  /** Effective rights matrix for the authenticated identity (self only). */
  async getSelfEffectiveRights(): Promise<EffectiveRightsReport> {
    return this.request<EffectiveRightsReport>("GET", "/internal/effective-rights");
  }

  async executePlatformCommand(
    commandName: string,
    params: Record<string, unknown> = {},
  ): Promise<PlatformCommandResponse> {
    return this.request<PlatformCommandResponse>("POST", "/internal/platform-commands", {
      command_name: commandName,
      params,
    });
  }

  async executeAdminCommand(
    commandName: string,
    params: Record<string, unknown> = {},
  ): Promise<AdminCommandResponse> {
    return this.request<AdminCommandResponse>("POST", "/internal/admin-commands", {
      command_name: commandName,
      params,
    });
  }

  async uploadCommandArtifact(
    content: Buffer,
    filename: string,
    sha256?: string,
  ): Promise<CommandArtifactUploadResponse> {
    const headers: Record<string, string> = {
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
      throw new HecateApiError(
        `API POST /internal/command-artifacts failed with ${response.status}${formatErrorDetail(parsed ?? text)}`,
        response.status,
        parsed ?? text,
      );
    }
    return parsed as CommandArtifactUploadResponse;
  }

  async downloadCommandArtifact(commandId: string): Promise<CommandArtifactDownloadResponse> {
    const headers: Record<string, string> = {
      Accept: "application/octet-stream",
      "X-Internal-Token": this.internalToken,
    };
    if (this.apiKey) {
      headers["X-AI-API-Key"] = this.apiKey;
    }

    const response = await this.fetchImpl(
      `${this.baseUrl}/internal/commands/${encodeURIComponent(commandId)}/artifact`,
      { method: "GET", headers },
    );

    if (!response.ok) {
      const text = await response.text();
      const parsed = safeJsonParse(text);
      throw new HecateApiError(
        `API GET /internal/commands/${commandId}/artifact failed with ${response.status}${formatErrorDetail(parsed)}`,
        response.status,
        parsed,
      );
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

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      "X-Internal-Token": this.internalToken,
    };

    if (this.apiKey) {
      headers["X-AI-API-Key"] = this.apiKey;
    }

    let payload: string | undefined;
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
      throw new HecateApiError(
        `API ${method} ${path} failed with ${response.status}${formatErrorDetail(parsed ?? text)}`,
        response.status,
        parsed ?? text,
      );
    }

    return parsed as T;
  }
}

export interface ExecuteCommandRequest {
  machine_id: string;
  command_name: string;
  params: Record<string, unknown>;
}

export interface ListCommandsFilters {
  machineId?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

function formatErrorDetail(body: unknown): string {
  if (body == null || body === "") {
    return "";
  }
  if (typeof body === "string") {
    return `: ${body}`;
  }
  if (typeof body === "object" && body !== null) {
    const record = body as Record<string, unknown>;
    if (typeof record.message === "string" && record.message.length > 0) {
      return `: ${record.message}`;
    }
  }
  try {
    return `: ${JSON.stringify(body)}`;
  } catch {
    return "";
  }
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}
