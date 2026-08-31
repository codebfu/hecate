// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from "vitest";
import { formatJsonFull, formatJsonPreview } from "./jsonDisplay.js";

describe("jsonDisplay", () => {
  it("truncates long JSON previews", () => {
    const preview = formatJsonPreview({ argv: ["/usr/bin/echo", "hello-world-from-a-long-string"] }, 20);
    expect(preview.endsWith("…")).toBe(true);
    expect(preview.length).toBeLessThanOrEqual(20);
  });

  it("pretty-prints full JSON", () => {
    expect(formatJsonFull({ elevated: true })).toBe('{\n  "elevated": true\n}');
  });
});
