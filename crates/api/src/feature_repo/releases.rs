//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Fleet package offers backed by installed feature-repo pins + local artifact cache.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};

const FEATURE_COMPONENTS: &[&str] = &["agent", "desktop", "proxmox"];

const RPM_DISTROS: &[&str] = &[
    "fedora",
    "rhel",
    "centos",
    "rocky",
    "almalinux",
    "alma",
    "ol",
    "oracle",
    "amzn",
    "amazon",
    "sles",
    "opensuse",
    "suse",
];

const DEB_DISTROS: &[&str] = &[
    "debian",
    "ubuntu",
    "raspbian",
    "linuxmint",
    "pop",
    "elementary",
    "kali",
    "devuan",
];

#[derive(Debug, Clone, sqlx::FromRow)]
struct CachedArtifactRow {
    version: String,
    sha256: String,
    local_path: String,
    filename: String,
    public_key_b64: String,
    update_signature: Option<String>,
    installer_type: String,
}

#[derive(Debug, Clone)]
pub struct PinnedRelease {
    pub version: String,
    pub sha256: String,
    pub signature: String,
    pub local_path: String,
    pub filename: String,
    pub public_key_b64: String,
    pub installer_type: String,
}

#[derive(Debug, Clone)]
pub struct LatestReleaseArtifact {
    pub version: String,
    pub artifact_path: String,
    pub sha256: String,
    pub filename: String,
    pub installer_type: String,
}

pub fn validate_release_path_segment(kind: &str, value: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.'))
    {
        return Err(ApiError::BadRequest(format!("invalid {kind}")));
    }
    Ok(())
}

pub fn latest_release_download_path(os: &str, arch: &str, component: &str) -> String {
    format!("/api/v1/releases/{os}/{arch}/{component}/latest")
}

/// Resolve which installer format to serve for a machine.
///
/// Priority: explicit `preferred` → distro tags → OS defaults (`msi`/`pkg`/`deb`).
pub fn resolve_installer_type(
    os: &str,
    preferred: Option<&str>,
    tags: &[String],
) -> String {
    if let Some(value) = preferred.map(str::trim).filter(|v| !v.is_empty()) {
        let lower = value.to_ascii_lowercase();
        if matches!(lower.as_str(), "deb" | "rpm" | "msi" | "pkg" | "raw") {
            return lower;
        }
    }
    let os_norm = os.trim().to_ascii_lowercase();
    match os_norm.as_str() {
        "windows" => "msi".into(),
        "macos" | "darwin" => "pkg".into(),
        "linux" => linux_installer_from_tags(tags).unwrap_or("deb").into(),
        _ => "raw".into(),
    }
}

fn linux_installer_from_tags(tags: &[String]) -> Option<&'static str> {
    let distro = tags.iter().find_map(|tag| {
        let lower = tag.to_ascii_lowercase();
        lower
            .strip_prefix("distro:")
            .map(|value| value.to_string())
    })?;
    if RPM_DISTROS.iter().any(|id| distro == *id || distro.starts_with(&format!("{id}-"))) {
        return Some("rpm");
    }
    if DEB_DISTROS.iter().any(|id| distro == *id || distro.starts_with(&format!("{id}-"))) {
        return Some("deb");
    }
    None
}

/// Pinned feature version that has a mirrored artifact for this OS/arch/installer.
pub async fn get_pinned_release(
    pool: &PgPool,
    feature_id: &str,
    os: &str,
    arch: &str,
    installer_type: &str,
) -> ApiResult<Option<PinnedRelease>> {
    if !FEATURE_COMPONENTS.contains(&feature_id) {
        return Ok(None);
    }
    let installer = installer_type.trim().to_ascii_lowercase();
    let row: Option<CachedArtifactRow> = sqlx::query_as(
        "SELECT c.version, c.sha256, c.local_path, c.filename, s.public_key_b64, c.update_signature,
                c.installer_type
         FROM installed_features f
         JOIN feature_artifact_cache c
           ON c.feature_id = f.id AND c.version = f.pinned_version
         JOIN repo_sources s ON s.id = f.source_id
         WHERE f.id = $1 AND c.os = $2 AND c.arch = $3 AND c.installer_type = $4",
    )
    .bind(feature_id)
    .bind(os)
    .bind(arch)
    .bind(&installer)
    .fetch_optional(pool)
    .await?;

    // Fallback: older agents / missing preferred type — try any row for os/arch,
    // preferring deb on linux when multiple exist.
    let row = match row {
        Some(row) => Some(row),
        None => {
            let rows: Vec<CachedArtifactRow> = sqlx::query_as(
                "SELECT c.version, c.sha256, c.local_path, c.filename, s.public_key_b64,
                        c.update_signature, c.installer_type
                 FROM installed_features f
                 JOIN feature_artifact_cache c
                   ON c.feature_id = f.id AND c.version = f.pinned_version
                 JOIN repo_sources s ON s.id = f.source_id
                 WHERE f.id = $1 AND c.os = $2 AND c.arch = $3
                 ORDER BY CASE c.installer_type
                   WHEN 'deb' THEN 0
                   WHEN 'rpm' THEN 1
                   ELSE 2
                 END,
                 c.filename",
            )
            .bind(feature_id)
            .bind(os)
            .bind(arch)
            .fetch_all(pool)
            .await?;
            rows.into_iter().next()
        }
    };

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
        installer_type: row.installer_type,
    }))
}

pub async fn latest_component_version(
    pool: &PgPool,
    os: &str,
    arch: &str,
    component: &str,
    installer_type: &str,
) -> ApiResult<Option<String>> {
    Ok(
        get_pinned_release(pool, component, os, arch, installer_type)
            .await?
            .map(|release| release.version),
    )
}

pub async fn get_pinned_release_for_download(
    pool: &PgPool,
    feature_id: &str,
    os: &str,
    arch: &str,
    version: &str,
    installer_type: &str,
) -> ApiResult<Option<PinnedRelease>> {
    let release = get_pinned_release(pool, feature_id, os, arch, installer_type).await?;
    Ok(release.filter(|entry| entry.version == version))
}

pub async fn get_latest_release_artifact(
    pool: &PgPool,
    os: &str,
    arch: &str,
    component: &str,
    installer_type: &str,
) -> ApiResult<Option<LatestReleaseArtifact>> {
    let Some(release) = get_pinned_release(pool, component, os, arch, installer_type).await? else {
        return Ok(None);
    };
    Ok(Some(LatestReleaseArtifact {
        version: release.version,
        artifact_path: release.local_path,
        sha256: release.sha256,
        filename: release.filename,
        installer_type: release.installer_type,
    }))
}

pub async fn list_latest_releases(pool: &PgPool) -> ApiResult<Vec<serde_json::Value>> {
    let rows: Vec<(String, String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT f.id, c.os, c.arch, c.version, c.filename, c.sha256, c.installer_type
         FROM installed_features f
         JOIN feature_artifact_cache c
           ON c.feature_id = f.id AND c.version = f.pinned_version
         WHERE f.id = ANY($1)
         ORDER BY f.id, c.os, c.arch, c.installer_type",
    )
    .bind(FEATURE_COMPONENTS)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(component, os, arch, version, filename, sha256, installer_type)| {
                json!({
                    "version": version,
                    "os": os,
                    "arch": arch,
                    "component": component,
                    "filename": filename,
                    "sha256": sha256,
                    "installer_type": installer_type,
                    "download_path": latest_release_download_path(&os, &arch, &component),
                })
            },
        )
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

    #[test]
    fn resolve_installer_prefers_explicit() {
        assert_eq!(
            resolve_installer_type("linux", Some("rpm"), &["distro:ubuntu".into()]),
            "rpm"
        );
    }

    #[test]
    fn resolve_installer_from_distro_tag() {
        assert_eq!(
            resolve_installer_type("linux", None, &["distro:fedora".into()]),
            "rpm"
        );
        assert_eq!(
            resolve_installer_type("linux", None, &["distro:debian".into()]),
            "deb"
        );
    }

    #[test]
    fn resolve_installer_os_defaults() {
        assert_eq!(resolve_installer_type("windows", None, &[]), "msi");
        assert_eq!(resolve_installer_type("macos", None, &[]), "pkg");
        assert_eq!(resolve_installer_type("linux", None, &[]), "deb");
    }
}
