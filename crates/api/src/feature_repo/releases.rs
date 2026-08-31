//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Fleet package offers backed by installed feature-repo pins + local artifact cache.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};

const FEATURE_COMPONENTS: &[&str] = &["agent", "desktop", "proxmox"];

#[derive(Debug, Clone, sqlx::FromRow)]
struct CachedArtifactRow {
    version: String,
    sha256: String,
    local_path: String,
    filename: String,
    public_key_b64: String,
    update_signature: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PinnedRelease {
    pub version: String,
    pub sha256: String,
    pub signature: String,
    pub local_path: String,
    pub filename: String,
    pub public_key_b64: String,
}

#[derive(Debug, Clone)]
pub struct LatestReleaseArtifact {
    pub version: String,
    pub artifact_path: String,
    pub sha256: String,
    pub filename: String,
}

pub fn validate_release_path_segment(kind: &str, value: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.chars().any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.'))
    {
        return Err(ApiError::BadRequest(format!("invalid {kind}")));
    }
    Ok(())
}

pub fn latest_release_download_path(os: &str, arch: &str, component: &str) -> String {
    format!("/api/v1/releases/{os}/{arch}/{component}/latest")
}

/// Pinned feature version that has a mirrored artifact for this OS/arch.
pub async fn get_pinned_release(
    pool: &PgPool,
    feature_id: &str,
    os: &str,
    arch: &str,
) -> ApiResult<Option<PinnedRelease>> {
    if !FEATURE_COMPONENTS.contains(&feature_id) {
        return Ok(None);
    }
    let row: Option<CachedArtifactRow> = sqlx::query_as(
        "SELECT c.version, c.sha256, c.local_path, c.filename, s.public_key_b64, c.update_signature
         FROM installed_features f
         JOIN feature_artifact_cache c
           ON c.feature_id = f.id AND c.version = f.pinned_version
         JOIN repo_sources s ON s.id = f.source_id
         WHERE f.id = $1 AND c.os = $2 AND c.arch = $3",
    )
    .bind(feature_id)
    .bind(os)
    .bind(arch)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    // Prefer canonical update signatures so older agents (pre content-.sig) can upgrade.
    let signature = match row
        .update_signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value.to_string(),
        None => load_content_signature_b64(&row.local_path).await?,
    };
    Ok(Some(PinnedRelease {
        version: row.version,
        sha256: row.sha256,
        signature,
        local_path: row.local_path,
        filename: row.filename,
        public_key_b64: row.public_key_b64,
    }))
}

pub async fn latest_component_version(
    pool: &PgPool,
    os: &str,
    arch: &str,
    component: &str,
) -> ApiResult<Option<String>> {
    Ok(get_pinned_release(pool, component, os, arch)
        .await?
        .map(|release| release.version))
}

pub async fn get_pinned_release_for_download(
    pool: &PgPool,
    feature_id: &str,
    os: &str,
    arch: &str,
    version: &str,
) -> ApiResult<Option<PinnedRelease>> {
    let release = get_pinned_release(pool, feature_id, os, arch).await?;
    Ok(release.filter(|entry| entry.version == version))
}

pub async fn get_latest_release_artifact(
    pool: &PgPool,
    os: &str,
    arch: &str,
    component: &str,
) -> ApiResult<Option<LatestReleaseArtifact>> {
    let Some(release) = get_pinned_release(pool, component, os, arch).await? else {
        return Ok(None);
    };
    Ok(Some(LatestReleaseArtifact {
        version: release.version,
        artifact_path: release.local_path,
        sha256: release.sha256,
        filename: release.filename,
    }))
}

pub async fn list_latest_releases(pool: &PgPool) -> ApiResult<Vec<serde_json::Value>> {
    let rows: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT f.id, c.os, c.arch, c.version, c.filename, c.sha256
         FROM installed_features f
         JOIN feature_artifact_cache c
           ON c.feature_id = f.id AND c.version = f.pinned_version
         WHERE f.id = ANY($1)
         ORDER BY f.id, c.os, c.arch",
    )
    .bind(FEATURE_COMPONENTS)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(component, os, arch, version, filename, sha256)| {
            json!({
                "version": version,
                "os": os,
                "arch": arch,
                "component": component,
                "filename": filename,
                "sha256": sha256,
                "download_path": latest_release_download_path(&os, &arch, &component),
            })
        })
        .collect())
}

pub async fn read_cached_artifact_bytes(
    jail_dir: &std::path::Path,
    local_path: &str,
) -> ApiResult<Vec<u8>> {
    let jail = tokio::fs::canonicalize(jail_dir).await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "canonicalize release artifacts dir: {error}"
        ))
    })?;
    let candidate = std::path::PathBuf::from(local_path);
    let canonical = if candidate.exists() {
        tokio::fs::canonicalize(&candidate).await.map_err(|error| {
            ApiError::Internal(anyhow::anyhow!(
                "canonicalize release artifact {}: {error}",
                local_path
            ))
        })?
    } else {
        return Err(ApiError::NotFound);
    };
    if !canonical.starts_with(&jail) {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "release artifact path escapes artifacts directory"
        )));
    }
    tokio::fs::read(&canonical).await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to read release artifact {}: {error}",
            local_path
        ))
    })
}

async fn load_content_signature_b64(local_path: &str) -> ApiResult<String> {
    let path = std::path::Path::new(local_path);
    let adjacent = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => path.with_file_name(format!("{name}.sig")),
        None => {
            return Err(ApiError::Internal(anyhow::anyhow!(
                "invalid artifact path for signature lookup"
            )));
        }
    };
    let bytes = tokio::fs::read(&adjacent).await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to read artifact signature {}: {error}",
            adjacent.display()
        ))
    })?;
    Ok(BASE64.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_release_path_segment_rejects_traversal() {
        assert!(validate_release_path_segment("os", "linux").is_ok());
        assert!(validate_release_path_segment("component", "proxmox").is_ok());
        assert!(validate_release_path_segment("os", "../etc").is_err());
        assert!(validate_release_path_segment("arch", "x86/64").is_err());
    }
}
