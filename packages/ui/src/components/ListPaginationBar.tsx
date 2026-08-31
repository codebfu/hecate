// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  LIST_PAGE_SIZE_OPTIONS,
  type ListPageSize,
} from "../hooks/usePaginatedList.js";

interface ListPaginationBarProps {
  pageSize: ListPageSize;
  onPageSizeChange: (pageSize: ListPageSize) => void;
  page: number;
  onPageChange: (page: number) => void;
  totalItems: number;
  visibleStart: number;
  visibleEnd: number;
  totalPages: number;
}

export function ListPaginationBar({
  pageSize,
  onPageSizeChange,
  page,
  onPageChange,
  totalItems,
  visibleStart,
  visibleEnd,
  totalPages,
}: ListPaginationBarProps) {
  const showPager = pageSize !== "all" && totalPages > 1;

  return (
    <div className="list-pagination-bar">
      <label className="list-pagination-size">
        Show
        <select
          value={pageSize}
          onChange={(event) => onPageSizeChange(event.target.value as ListPageSize)}
        >
          {LIST_PAGE_SIZE_OPTIONS.map((option) => (
            <option key={option} value={option}>
              {option === "all" ? "All" : option}
            </option>
          ))}
        </select>
        items
      </label>

      <p className="list-pagination-summary muted">
        {totalItems === 0
          ? "No items"
          : `Showing ${visibleStart}–${visibleEnd} of ${totalItems}`}
      </p>

      {showPager ? (
        <div className="list-pagination-controls">
          <button type="button" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
            Previous
          </button>
          <span className="muted">
            Page {page} of {totalPages}
          </span>
          <button
            type="button"
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
          >
            Next
          </button>
        </div>
      ) : null}
    </div>
  );
}
