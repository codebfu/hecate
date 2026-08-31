/**
 * Wrap remote-origin data so MCP clients treat it as untrusted (indirect prompt injection).
 * Metadata is server/API-authored; untrusted_output may come from agents, hostnames, or artifacts.
 */
export declare function formatUntrustedToolResult(metadata: unknown, untrustedOutput: unknown): {
    content: Array<{
        type: "text";
        text: string;
    }>;
};
//# sourceMappingURL=untrusted.d.ts.map