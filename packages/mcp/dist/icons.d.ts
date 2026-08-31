import type { Icon } from "@modelcontextprotocol/sdk/types.js";
/**
 * Server identity icons for MCP initialize (SEP-973).
 * Use HTTPS URLs to UI static assets — Cursor clients render these
 * (Home Assistant pattern); large data URIs are often ignored.
 */
export declare function getServerIcons(publicBaseUrl: string): Icon[];
/** Prefer configured public URL; else derive from the initialize request Host. */
export declare function resolvePublicBaseUrl(configured: string | undefined, hostHeader: string | undefined, forwardedProto: string | undefined): string | undefined;
//# sourceMappingURL=icons.d.ts.map