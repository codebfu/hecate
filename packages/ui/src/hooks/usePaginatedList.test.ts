// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from "vitest";
import { listQueryParams, paginationFromResponse } from "./usePaginatedList.js";

describe("usePaginatedList", () => {
  it("builds query params for fixed page sizes", () => {
    expect(listQueryParams(20, 2)).toEqual({ limit: 20, offset: 20 });
  });

  it("builds query params for all mode", () => {
    expect(listQueryParams("all", 3)).toEqual({ limit: 0, offset: 0 });
  });

  it("derives pagination metadata from API responses", () => {
    const view = paginationFromResponse({
      items: [1, 2],
      total: 42,
      limit: 20,
      offset: 20,
    });

    expect(view.page).toBe(2);
    expect(view.totalPages).toBe(3);
    expect(view.visibleStart).toBe(21);
    expect(view.visibleEnd).toBe(22);
  });
});
