//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use hecate_protocol::backup::BACKUP_FORMAT_VERSION_CURRENT;
use serde::Serialize;

use crate::error::ApiResult;
use crate::state::AppState;

#[derive(Serialize)]
pub struct VersionResponse {
    pub hecate_version: String,
    pub schema_version: i64,
    pub backup_format_version_current: u32,
    pub api_version: String,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/system/version", get(version))
}

async fn version(State(state): State<AppState>) -> ApiResult<Json<VersionResponse>> {
    let schema_version: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    Ok(Json(VersionResponse {
        hecate_version: hecate_protocol::HECATE_VERSION.to_string(),
        schema_version,
        backup_format_version_current: BACKUP_FORMAT_VERSION_CURRENT,
        api_version: hecate_protocol::API_VERSION.to_string(),
    }))
}
