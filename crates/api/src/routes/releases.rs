//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Public bootstrap downloads for the latest pinned feature-repo installers.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::error::{ApiError, ApiResult};
use crate::feature_repo::releases;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/api/v1/releases/{os}/{arch}/{component}/latest",
        get(download_latest_release),
    )
}

async fn download_latest_release(
    State(state): State<AppState>,
    Path((os, arch, component)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    releases::validate_release_path_segment("os", &os)?;
    releases::validate_release_path_segment("arch", &arch)?;
    releases::validate_release_path_segment("component", &component)?;

    let Some(release) =
        releases::get_latest_release_artifact(&state.pool, &os, &arch, &component).await?
    else {
        return Err(ApiError::NotFound);
    };

    let bytes = releases::read_cached_artifact_bytes(
        &state.config.release_artifacts_dir,
        &release.artifact_path,
    )
    .await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let disposition = format!(
        "attachment; filename=\"{}\"",
        sanitize_content_disposition_filename(&release.filename)
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).map_err(|error| {
            ApiError::Internal(anyhow::anyhow!("content-disposition header: {error}"))
        })?,
    );
    headers.insert(
        header::HeaderName::from_static("x-hecate-release-version"),
        HeaderValue::from_str(&release.version).map_err(|error| {
            ApiError::Internal(anyhow::anyhow!("release version header: {error}"))
        })?,
    );
    headers.insert(
        header::HeaderName::from_static("x-hecate-release-sha256"),
        HeaderValue::from_str(&release.sha256).map_err(|error| {
            ApiError::Internal(anyhow::anyhow!("release sha256 header: {error}"))
        })?,
    );

    Ok((StatusCode::OK, headers, bytes).into_response())
}

fn sanitize_content_disposition_filename(name: &str) -> String {
    name.chars()
        .map(|ch| match ch {
            '"' | '\\' | '\r' | '\n' => '_',
            _ => ch,
        })
        .collect()
}
