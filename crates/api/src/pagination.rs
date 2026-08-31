//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};

pub const DEFAULT_LIST_LIMIT: i64 = 20;
pub const MAX_LIST_LIMIT: i64 = 100;
pub const MAX_LIST_ALL: i64 = 10_000;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CommandListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub command_id: Option<uuid::Uuid>,
    pub machine_id: Option<uuid::Uuid>,
    /// When true, also include terminal commands finished in the last 24 hours.
    pub include_recent: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

pub fn resolve_list_pagination(limit: Option<i64>, offset: Option<i64>) -> (i64, i64) {
    let resolved_limit = match limit.unwrap_or(DEFAULT_LIST_LIMIT) {
        0 => MAX_LIST_ALL,
        n => n.clamp(1, MAX_LIST_LIMIT),
    };
    let resolved_offset = offset.unwrap_or(0).max(0);
    (resolved_limit, resolved_offset)
}

pub fn page_offset_for_index(index: i64, limit: i64) -> i64 {
    if limit <= 0 {
        return 0;
    }
    (index / limit) * limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_list_pagination_defaults() {
        assert_eq!(resolve_list_pagination(None, None), (20, 0));
    }

    #[test]
    fn resolve_list_pagination_all_mode() {
        assert_eq!(resolve_list_pagination(Some(0), None), (MAX_LIST_ALL, 0));
    }

    #[test]
    fn page_offset_for_index_aligns_to_pages() {
        assert_eq!(page_offset_for_index(0, 20), 0);
        assert_eq!(page_offset_for_index(19, 20), 0);
        assert_eq!(page_offset_for_index(20, 20), 20);
    }
}
