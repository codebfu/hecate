// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from "vitest";
import { getServerIcons, resolvePublicBaseUrl } from "./icons.js";

describe("getServerIcons", () => {
  it("returns HTTPS SVG and PNG icons relative to the public base URL", () => {
    const icons = getServerIcons("https://hecate.example:18443");
    expect(icons).toEqual([
      {
        src: "https://hecate.example:18443/icon.svg",
        mimeType: "image/svg+xml",
      },
      {
        src: "https://hecate.example:18443/icon-192.png",
        mimeType: "image/png",
        sizes: ["192x192"],
      },
    ]);
  });

  it("returns no icons when the base URL is empty", () => {
    expect(getServerIcons("")).toEqual([]);
  });
});

describe("resolvePublicBaseUrl", () => {
  it("prefers the configured public base URL", () => {
    expect(
      resolvePublicBaseUrl("https://hecate.example:18443/", "ignored.example", "http"),
    ).toBe("https://hecate.example:18443");
  });

  it("derives https from Host when not configured", () => {
    expect(resolvePublicBaseUrl(undefined, "hecate.example:18443", undefined)).toBe(
      "https://hecate.example:18443",
    );
  });

  it("honors X-Forwarded-Proto", () => {
    expect(resolvePublicBaseUrl(undefined, "hecate.example", "https, http")).toBe(
      "https://hecate.example",
    );
  });
});
