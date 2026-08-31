// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { PaginatedResponse } from "../api/client.js";

export const LIST_PAGE_SIZE_OPTIONS = [10, 20, 50, 100, "all"] as const;

export type ListPageSize = (typeof LIST_PAGE_SIZE_OPTIONS)[number];

export interface PaginatedListView<T> {
  items: T[];
  totalItems: number;
  page: number;
  totalPages: number;
  visibleStart: number;
  visibleEnd: number;
  limit: number;
  offset: number;
}

export function listQueryParams(
  pageSize: ListPageSize,
  page: number,
): { limit: number; offset: number } {
  if (pageSize === "all") {
    return { limit: 0, offset: 0 };
  }
  return {
    limit: pageSize,
    offset: (page - 1) * pageSize,
  };
}

export function paginationFromResponse<T>(response: PaginatedResponse<T>): PaginatedListView<T> {
  const { items, total, limit, offset } = response;

  if (limit === 0 || total === 0) {
    return {
      items,
      totalItems: total,
      page: 1,
      totalPages: 1,
      visibleStart: total === 0 ? 0 : 1,
      visibleEnd: total,
      limit,
      offset,
    };
  }

  const page = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  return {
    items,
    totalItems: total,
    page,
    totalPages,
    visibleStart: total === 0 ? 0 : offset + 1,
    visibleEnd: Math.min(offset + items.length, total),
    limit,
    offset,
  };
}
