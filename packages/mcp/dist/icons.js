// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Server identity icons for MCP initialize (SEP-973).
 * Use HTTPS URLs to UI static assets — Cursor clients render these
 * (Home Assistant pattern); large data URIs are often ignored.
 */
export function getServerIcons(publicBaseUrl) {
    const base = publicBaseUrl.replace(/\/$/, "");
    if (!base) {
        return [];
    }
    return [
        {
            src: `${base}/icon.svg`,
            mimeType: "image/svg+xml",
        },
        {
            src: `${base}/icon-192.png`,
            mimeType: "image/png",
            sizes: ["192x192"],
        },
    ];
}
/** Prefer configured public URL; else derive from the initialize request Host. */
export function resolvePublicBaseUrl(configured, hostHeader, forwardedProto) {
    if (configured?.trim()) {
        return configured.trim().replace(/\/$/, "");
    }
    if (!hostHeader?.trim()) {
        return undefined;
    }
    const proto = forwardedProto?.split(",")[0]?.trim() ||
        (hostHeader.includes("localhost") || hostHeader.startsWith("127.") ? "http" : "https");
    return `${proto}://${hostHeader.trim()}`;
}
//# sourceMappingURL=icons.js.map