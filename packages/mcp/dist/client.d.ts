import type { AiContextResponse, AuthzCatalogResponse, CommandArtifactDownloadResponse, CommandArtifactUploadResponse, CommandDetail, CommandEnqueueResponse, EffectiveRightsReport, MachineSummary, AdminCommandResponse, PlatformCommandResponse } from "./types.js";
export interface HecateApiClientOptions {
    baseUrl: string;
    internalToken: string;
    apiKey?: string;
    fetchImpl?: typeof fetch;
}
export declare class HecateApiError extends Error {
    readonly status: number;
    readonly body?: unknown;
    constructor(message: string, status: number, body?: unknown);
}
export declare class HecateApiClient {
    private readonly baseUrl;
    private readonly internalToken;
    private readonly apiKey?;
    private readonly fetchImpl;
    constructor(options: HecateApiClientOptions);
    withApiKey(apiKey: string): HecateApiClient;
    listMachines(): Promise<MachineSummary[]>;
    getMachine(machineId: string): Promise<MachineSummary>;
    executeCommand(body: ExecuteCommandRequest): Promise<CommandEnqueueResponse>;
    getCommand(commandId: string, wait?: boolean, waitTimeoutSecs?: number): Promise<CommandDetail>;
    listCommands(filters?: ListCommandsFilters): Promise<CommandDetail[]>;
    cancelCommand(commandId: string): Promise<{
        ok: boolean;
    }>;
    getAiContext(): Promise<AiContextResponse>;
    /** S12 self-service catalog: assignable grants visible to the authenticated identity. */
    getSelfServiceAuthzCatalog(): Promise<AuthzCatalogResponse>;
    /** Effective rights matrix for the authenticated identity (self only). */
    getSelfEffectiveRights(): Promise<EffectiveRightsReport>;
    executePlatformCommand(commandName: string, params?: Record<string, unknown>): Promise<PlatformCommandResponse>;
    executeAdminCommand(commandName: string, params?: Record<string, unknown>): Promise<AdminCommandResponse>;
    uploadCommandArtifact(content: Buffer, filename: string, sha256?: string): Promise<CommandArtifactUploadResponse>;
    downloadCommandArtifact(commandId: string): Promise<CommandArtifactDownloadResponse>;
    private request;
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
//# sourceMappingURL=client.d.ts.map