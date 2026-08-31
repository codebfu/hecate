//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};
use crate::state::AppConfig;

use super::fetch::{self, ARTIFACT_MAX_BYTES, METADATA_MAX_BYTES};
use super::sources::{self, RepoSource};
use super::types::{
    FeatureArtifact, FeatureIndexEntry, FeatureManifest, FeatureVersion, FeaturesIndex, Release,
};
use super::verify;

struct Catalogue {
    source: RepoSource,
    release: Release,
    index: FeaturesIndex,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct InstalledFeature {
    pub id: String,
    pub pinned_version: String,
    pub source_id: String,
    pub track_latest: bool,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub feature_json: Value,
}

pub async fn list(pool: &PgPool) -> ApiResult<Value> {
    let installed: Vec<InstalledFeature> = sqlx::query_as(
        "SELECT id, pinned_version, source_id, track_latest, installed_at, feature_json
         FROM installed_features
         ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let client = fetch::build_client()?;
    let mut available = Vec::new();
    let mut errors = Vec::new();
    for source in sources::list(pool)
        .await?
        .into_iter()
        .filter(|source| source.enabled)
    {
        match fetch_catalogue(&client, &source).await {
            Ok(catalogue) => {
                let source_id = source.id.clone();
                available.extend(catalogue.index.features.into_iter().map(|feature| {
                    serde_json::json!({
                        "source_id": source_id.clone(),
                        "feature": feature,
                    })
                }));
            }
            Err(error) => errors.push(serde_json::json!({
                "source_id": source.id,
                "error": api_error_message(&error),
            })),
        }
    }
    Ok(serde_json::json!({
        "available": available,
        "installed": installed,
        "errors": errors,
    }))
}

pub async fn status(pool: &PgPool) -> ApiResult<Value> {
    let source_rows = sources::list(pool).await?;
    let installed: Vec<InstalledFeature> = sqlx::query_as(
        "SELECT id, pinned_version, source_id, track_latest, installed_at, feature_json
         FROM installed_features
         ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let cached_artifacts: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM feature_artifact_cache")
            .fetch_one(pool)
            .await?;
    Ok(serde_json::json!({
        "sources": source_rows,
        "installed": installed,
        "cached_artifacts": cached_artifacts,
    }))
}

pub async fn refresh(pool: &PgPool, config: &AppConfig) -> ApiResult<Value> {
    let client = fetch::build_client()?;
    let mut refreshed = Vec::new();
    let mut errors = Vec::new();
    for source in sources::list(pool)
        .await?
        .into_iter()
        .filter(|source| source.enabled)
    {
        match fetch_catalogue(&client, &source).await {
            Ok(catalogue) => {
                let generated_at = parse_index_generated_at(&catalogue.index)?;
                sources::mark_sync(pool, &source.id, None, Some(generated_at)).await?;
                refreshed.push(serde_json::json!({
                    "source_id": source.id,
                    "features": catalogue.index.features.len(),
                    "generated_at": catalogue.index.generated_at,
                }));
            }
            Err(error) => {
                let message = api_error_message(&error);
                sources::mark_sync(pool, &source.id, Some(&message), None).await?;
                errors.push(serde_json::json!({
                    "source_id": source.id,
                    "error": message,
                }));
            }
        }
    }

    let signature_updates = match sync_installed_update_signatures(pool).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(error = %error, "refresh could not sync fleet update signatures");
            0
        }
    };

    let artifact_sync = match sync_installed_artifact_cache(pool, config).await {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(error = %error, "refresh could not sync mirrored artifacts");
            serde_json::json!({
                "mirrored": 0,
                "errors": [api_error_message(&error)],
            })
        }
    };

    Ok(serde_json::json!({
        "refreshed": refreshed,
        "errors": errors,
        "update_signatures_synced": signature_updates,
        "artifact_sync": artifact_sync,
    }))
}

/// Fetch installed feature manifests and copy any `update_signature` fields into the local cache.
///
/// Deployments that installed packages before canonical fleet signatures were published still get
/// working `agent.update` offers after the next API boot (or an explicit reinstall/upgrade).
pub async fn sync_installed_update_signatures(pool: &PgPool) -> ApiResult<u64> {
    let client = fetch::build_client()?;
    let installed: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, pinned_version, source_id FROM installed_features ORDER BY id",
    )
    .fetch_all(pool)
    .await?;

    let mut updated = 0u64;
    for (feature_id, pinned_version, source_id) in installed {
        let source = match sources::get(pool, &source_id).await {
            Ok(source) if source.enabled => source,
            Ok(_) => continue,
            Err(error) => {
                tracing::warn!(
                    feature_id = %feature_id,
                    source_id = %source_id,
                    error = %error,
                    "skip update-signature sync: source unavailable"
                );
                continue;
            }
        };
        let catalogue = match fetch_catalogue(&client, &source).await {
            Ok(catalogue) => catalogue,
            Err(error) => {
                tracing::warn!(
                    feature_id = %feature_id,
                    source_id = %source_id,
                    error = %error,
                    "skip update-signature sync: catalogue fetch failed"
                );
                continue;
            }
        };
        let Some(feature) = catalogue
            .index
            .features
            .iter()
            .find(|entry| entry.id == feature_id)
        else {
            continue;
        };
        let Some(version) = feature
            .versions
            .iter()
            .find(|entry| entry.version == pinned_version)
        else {
            continue;
        };
        let manifest_path = normalize_manifest_path(&version.manifest);
        let manifest_bytes = match fetch_signed_file(
            &client,
            &catalogue,
            &manifest_path,
            METADATA_MAX_BYTES,
            false,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(
                    feature_id = %feature_id,
                    version = %pinned_version,
                    error = %error,
                    "skip update-signature sync: manifest fetch failed"
                );
                continue;
            }
        };
        let manifest: FeatureManifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(
                    feature_id = %feature_id,
                    version = %pinned_version,
                    error = %error,
                    "skip update-signature sync: invalid manifest"
                );
                continue;
            }
        };
        updated += apply_manifest_update_signatures(pool, &manifest).await?;
    }
    if updated > 0 {
        tracing::info!(updated, "synced fleet update signatures from feature manifests");
    }
    Ok(updated)
}

async fn apply_manifest_update_signatures(
    pool: &PgPool,
    manifest: &FeatureManifest,
) -> ApiResult<u64> {
    let mut updated = 0u64;
    for artifact in &manifest.artifacts {
        let Some(signature) = artifact
            .update_signature
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let result = sqlx::query(
            "UPDATE feature_artifact_cache
             SET update_signature = $1
             WHERE feature_id = $2
               AND version = $3
               AND os = $4
               AND arch = $5
               AND sha256 = $6
               AND (update_signature IS DISTINCT FROM $1)",
        )
        .bind(signature)
        .bind(&manifest.id)
        .bind(&manifest.version)
        .bind(&artifact.os)
        .bind(&artifact.arch)
        .bind(artifact.sha256.to_ascii_lowercase())
        .execute(pool)
        .await?;
        updated += result.rows_affected();
    }
    Ok(updated)
}

/// Upgrade every installed feature that tracks latest to the newest published version.
/// Pinned features are left unchanged.
pub async fn upgrade_all(pool: &PgPool, config: &AppConfig) -> ApiResult<Value> {
    let client = fetch::build_client()?;
    let tracking: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, pinned_version, source_id
         FROM installed_features
         WHERE track_latest = true
         ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut upgraded = Vec::new();
    let mut unchanged = Vec::new();
    let mut errors = Vec::new();

    for (feature_id, current_version, source_id) in tracking {
        match follow_latest(pool, config, &client, &feature_id, &current_version, &source_id)
            .await
        {
            Ok(Some(version)) => upgraded.push(serde_json::json!({
                "id": feature_id,
                "from": current_version,
                "to": version,
            })),
            Ok(None) => unchanged.push(serde_json::json!({
                "id": feature_id,
                "version": current_version,
            })),
            Err(error) => errors.push(serde_json::json!({
                "feature_id": feature_id,
                "error": api_error_message(&error),
            })),
        }
    }

    let pinned_skipped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM installed_features WHERE track_latest = false",
    )
    .fetch_one(pool)
    .await?;

    Ok(serde_json::json!({
        "upgraded": upgraded,
        "unchanged": unchanged,
        "pinned_skipped": pinned_skipped,
        "errors": errors,
    }))
}

pub async fn reconcile(pool: &PgPool) -> ApiResult<Value> {
    let client = fetch::build_client()?;
    let installed: Vec<(String, String, String, bool)> = sqlx::query_as(
        "SELECT id, pinned_version, source_id, track_latest FROM installed_features ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut rows = Vec::with_capacity(installed.len());
    for (id, pinned_version, source_id, track_latest) in installed {
        let source = sources::get(pool, &source_id).await?;
        let latest = match fetch_catalogue(&client, &source).await {
            Ok(catalogue) => catalogue
                .index
                .features
                .iter()
                .find(|feature| feature.id == id)
                .and_then(latest_version)
                .map(str::to_string),
            Err(_) => None,
        };
        let upgrade_available = latest
            .as_deref()
            .is_some_and(|version| version != pinned_version.as_str());
        rows.push(serde_json::json!({
            "id": id,
            "pinned_version": pinned_version,
            "track_latest": track_latest,
            "latest_version": latest,
            "upgrade_available": upgrade_available && !track_latest,
            "source_id": source_id,
        }));
    }
    Ok(serde_json::json!({ "features": rows }))
}

pub async fn install(
    pool: &PgPool,
    config: &AppConfig,
    feature_id: &str,
    requested_version: Option<&str>,
    requested_source: Option<&str>,
) -> ApiResult<Value> {
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM installed_features WHERE id = $1)",
    )
    .bind(feature_id)
    .fetch_one(pool)
    .await?
    {
        return Err(ApiError::Conflict(format!(
            "feature {feature_id} is already installed"
        )));
    }
    install_or_upgrade(
        pool,
        config,
        feature_id,
        requested_version,
        requested_source,
        false,
    )
    .await
    .map_err(|error| {
        tracing::error!(
            feature_id,
            error = %api_error_message(&error),
            "feature install failed"
        );
        error
    })
}

pub async fn upgrade(
    pool: &PgPool,
    config: &AppConfig,
    feature_id: &str,
    requested_version: Option<&str>,
) -> ApiResult<Value> {
    let source_id: Option<String> =
        sqlx::query_scalar("SELECT source_id FROM installed_features WHERE id = $1")
            .bind(feature_id)
            .fetch_optional(pool)
            .await?;
    let source_id = source_id.ok_or(ApiError::NotFound)?;
    install_or_upgrade(
        pool,
        config,
        feature_id,
        requested_version,
        Some(&source_id),
        true,
    )
    .await
}

/// Pin an installed feature to an explicit version (stops tracking latest).
pub async fn pin(
    pool: &PgPool,
    config: &AppConfig,
    feature_id: &str,
    version: &str,
) -> ApiResult<Value> {
    let source_id: Option<String> =
        sqlx::query_scalar("SELECT source_id FROM installed_features WHERE id = $1")
            .bind(feature_id)
            .fetch_optional(pool)
            .await?;
    let source_id = source_id.ok_or(ApiError::NotFound)?;
    let mut result = install_or_upgrade(
        pool,
        config,
        feature_id,
        Some(version),
        Some(&source_id),
        true,
    )
    .await?;
    if let Some(object) = result.as_object_mut() {
        object.insert("operation".into(), Value::String("pinned".into()));
        object.insert("track_latest".into(), Value::Bool(false));
    }
    Ok(result)
}

/// Remove a version pin and resume tracking the newest published release.
pub async fn unpin(pool: &PgPool, config: &AppConfig, feature_id: &str) -> ApiResult<Value> {
    let row: Option<(String, bool)> = sqlx::query_as(
        "SELECT source_id, track_latest FROM installed_features WHERE id = $1",
    )
    .bind(feature_id)
    .fetch_optional(pool)
    .await?;
    let (source_id, track_latest) = row.ok_or(ApiError::NotFound)?;
    if track_latest {
        return Err(ApiError::BadRequest(format!(
            "feature {feature_id} is not pinned"
        )));
    }
    let mut result = install_or_upgrade(
        pool,
        config,
        feature_id,
        None,
        Some(&source_id),
        true,
    )
    .await?;
    if let Some(object) = result.as_object_mut() {
        object.insert("operation".into(), Value::String("unpinned".into()));
        object.insert("track_latest".into(), Value::Bool(true));
    }
    Ok(result)
}

async fn install_or_upgrade(
    pool: &PgPool,
    config: &AppConfig,
    feature_id: &str,
    requested_version: Option<&str>,
    requested_source: Option<&str>,
    is_upgrade: bool,
) -> ApiResult<Value> {
    validate_feature_id(feature_id)?;
    let client = fetch::build_client()?;
    let (catalogue, feature, version) = find_feature(
        pool,
        &client,
        feature_id,
        requested_version,
        requested_source,
    )
    .await?;
    let manifest_path = normalize_manifest_path(&version.manifest);
    // Pool objects are authenticated by adjacent .sig files; Release only covers suite metadata.
    let manifest_bytes = fetch_signed_file(
        &client,
        &catalogue,
        &manifest_path,
        METADATA_MAX_BYTES,
        false,
    )
    .await?;
    let manifest: FeatureManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ApiError::BadRequest(format!("invalid feature manifest: {error}")))?;
    if manifest.id != feature_id || manifest.version != version.version {
        return Err(ApiError::BadRequest(
            "feature manifest id or version does not match the index".into(),
        ));
    }

    // Explicit version => pin. No version => follow newest on refresh.
    let track_latest = requested_version.is_none();
    prepare_feature_mirror(pool, config, &manifest).await?;
    mirror_artifacts(pool, config, &client, &catalogue, &manifest).await?;
    persist_feature(pool, &catalogue.source.id, &manifest, track_latest).await?;
    let generated_at = parse_index_generated_at(&catalogue.index)?;
    sources::mark_sync(pool, &catalogue.source.id, None, Some(generated_at)).await?;

    Ok(serde_json::json!({
        "id": manifest.id,
        "version": manifest.version,
        "source_id": catalogue.source.id,
        "track_latest": track_latest,
        "operation": if is_upgrade { "upgraded" } else { "installed" },
        "commands": manifest.commands.iter().map(|command| &command.name).collect::<Vec<_>>(),
        "artifacts": manifest.artifacts.len(),
        "index_description": feature.description,
    }))
}

/// Pull the newest published version when an install tracks latest.
async fn follow_latest(
    pool: &PgPool,
    config: &AppConfig,
    client: &reqwest::Client,
    feature_id: &str,
    current_version: &str,
    source_id: &str,
) -> ApiResult<Option<String>> {
    let Some(latest) = resolve_latest_version(pool, client, feature_id, source_id).await? else {
        return Ok(None);
    };
    if latest == current_version {
        return Ok(None);
    }
    install_or_upgrade(
        pool,
        config,
        feature_id,
        None,
        Some(source_id),
        true,
    )
    .await?;
    Ok(Some(latest))
}

async fn resolve_latest_version(
    pool: &PgPool,
    client: &reqwest::Client,
    feature_id: &str,
    source_id: &str,
) -> ApiResult<Option<String>> {
    let source = sources::get(pool, source_id).await?;
    let catalogue = fetch_catalogue(client, &source).await?;
    Ok(catalogue
        .index
        .features
        .iter()
        .find(|entry| entry.id == feature_id)
        .and_then(latest_version)
        .map(str::to_string))
}

pub async fn uninstall(pool: &PgPool, config: &AppConfig, feature_id: &str) -> ApiResult<Value> {
    let feature_json: Option<Value> =
        sqlx::query_scalar("SELECT feature_json FROM installed_features WHERE id = $1")
            .bind(feature_id)
            .fetch_optional(pool)
            .await?;
    let feature_json = feature_json.ok_or(ApiError::NotFound)?;
    let removed_names = command_names(&feature_json);

    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM installed_features WHERE id = $1")
        .bind(feature_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM feature_artifact_cache WHERE feature_id = $1")
        .bind(feature_id)
        .execute(&mut *transaction)
        .await?;

    let remaining_json: Vec<Value> =
        sqlx::query_scalar("SELECT feature_json FROM installed_features")
            .fetch_all(&mut *transaction)
            .await?;
    let retained: HashSet<String> = remaining_json.iter().flat_map(command_names).collect();
    let deletable: Vec<String> = removed_names
        .into_iter()
        .filter(|name| !retained.contains(name))
        .collect();
    if !deletable.is_empty() {
        sqlx::query("DELETE FROM command_definitions WHERE name = ANY($1)")
            .bind(&deletable)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    remove_feature_mirror_dir(config, feature_id).await?;
    Ok(serde_json::json!({ "id": feature_id, "uninstalled": true }))
}

async fn remove_feature_mirror_dir(config: &AppConfig, feature_id: &str) -> ApiResult<()> {
    let path = config.hecate_repo_mirror_dir.join(feature_id);
    if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return Ok(());
    }
    tokio::fs::remove_dir_all(&path).await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to remove feature mirror directory {}: {error}",
            path.display()
        ))
    })?;
    tracing::info!(feature_id, path = %path.display(), "removed feature mirror directory");
    Ok(())
}

/// Drop stale cache rows and on-disk installers before mirroring a target version.
async fn prepare_feature_mirror(
    pool: &PgPool,
    config: &AppConfig,
    manifest: &FeatureManifest,
) -> ApiResult<()> {
    let expected_os_arch: HashSet<(String, String)> = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.os.clone(), artifact.arch.clone()))
        .collect();
    let expected_filenames: HashSet<(String, String, String)> = manifest
        .artifacts
        .iter()
        .filter_map(|artifact| {
            Path::new(&artifact.filename)
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .map(|filename| {
                    (
                        artifact.os.clone(),
                        artifact.arch.clone(),
                        filename.to_string(),
                    )
                })
        })
        .collect();

    let cached_rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT version, os, arch, local_path
         FROM feature_artifact_cache
         WHERE feature_id = $1",
    )
    .bind(&manifest.id)
    .fetch_all(pool)
    .await?;

    for (cached_version, os, arch, local_path) in &cached_rows {
        let keep = cached_version == manifest.version
            && expected_os_arch.contains(&(os.clone(), arch.clone()));
        if keep {
            continue;
        }
        remove_cached_artifact_files(local_path).await;
        sqlx::query(
            "DELETE FROM feature_artifact_cache
             WHERE feature_id = $1 AND version = $2 AND os = $3 AND arch = $4",
        )
        .bind(&manifest.id)
        .bind(cached_version)
        .bind(os)
        .bind(arch)
        .execute(pool)
        .await?;
    }

    prune_feature_mirror_tree(
        &config.hecate_repo_mirror_dir.join(&manifest.id),
        &manifest.version,
        &expected_os_arch,
        &expected_filenames,
    )
    .await?;

    Ok(())
}

async fn remove_cached_artifact_files(local_path: &str) {
    let path = Path::new(local_path);
    remove_mirror_file(path).await;
    if let Some(filename) = path.file_name().and_then(|name| name.to_str()) {
        remove_mirror_file(&path.with_file_name(format!("{filename}.sig"))).await;
    }
}

async fn remove_mirror_file(path: &Path) {
    if !tokio::fs::try_exists(path).await.unwrap_or(false) {
        return;
    }
    if let Err(error) = tokio::fs::remove_file(path).await {
        tracing::warn!(
            path = %path.display(),
            error = %error,
            "failed to remove mirrored artifact file"
        );
    }
}

async fn prune_feature_mirror_tree(
    feature_root: &Path,
    keep_version: &str,
    expected_os_arch: &HashSet<(String, String)>,
    expected_filenames: &HashSet<(String, String, String)>,
) -> ApiResult<()> {
    if !tokio::fs::try_exists(feature_root).await.unwrap_or(false) {
        return Ok(());
    }

    let mut version_dirs = tokio::fs::read_dir(feature_root).await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to read feature mirror directory {}: {error}",
            feature_root.display()
        ))
    })?;

    while let Some(version_entry) = version_dirs.next_entry().await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to read feature mirror directory {}: {error}",
            feature_root.display()
        ))
    })? {
        let version_name = version_entry.file_name().to_string_lossy().to_string();
        if version_name != keep_version {
            tokio::fs::remove_dir_all(version_entry.path())
                .await
                .map_err(|error| {
                    ApiError::Internal(anyhow::anyhow!(
                        "failed to remove stale feature mirror version {}: {error}",
                        version_entry.path().display()
                    ))
                })?;
            tracing::info!(
                path = %version_entry.path().display(),
                keep_version,
                "removed stale mirrored feature version"
            );
            continue;
        }

        let version_path = version_entry.path();
        let mut os_dirs = tokio::fs::read_dir(&version_path).await.map_err(|error| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to read mirrored feature version directory {}: {error}",
                version_path.display()
            ))
        })?;

        while let Some(os_entry) = os_dirs.next_entry().await.map_err(|error| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to read mirrored feature version directory {}: {error}",
                version_path.display()
            ))
        })? {
            let os = os_entry.file_name().to_string_lossy().to_string();
            let os_path = os_entry.path();
            let mut arch_dirs = tokio::fs::read_dir(&os_path).await.map_err(|error| {
                ApiError::Internal(anyhow::anyhow!(
                    "failed to read mirrored feature OS directory {}: {error}",
                    os_path.display()
                ))
            })?;

            while let Some(arch_entry) = arch_dirs.next_entry().await.map_err(|error| {
                ApiError::Internal(anyhow::anyhow!(
                    "failed to read mirrored feature OS directory {}: {error}",
                    os_path.display()
                ))
            })? {
                let arch = arch_entry.file_name().to_string_lossy().to_string();
                let arch_path = arch_entry.path();
                if !expected_os_arch.contains(&(os.clone(), arch.clone())) {
                    tokio::fs::remove_dir_all(&arch_path).await.map_err(|error| {
                        ApiError::Internal(anyhow::anyhow!(
                            "failed to remove stale mirrored artifact directory {}: {error}",
                            arch_path.display()
                        ))
                    })?;
                    continue;
                }

                let mut files = tokio::fs::read_dir(&arch_path).await.map_err(|error| {
                    ApiError::Internal(anyhow::anyhow!(
                        "failed to read mirrored artifact directory {}: {error}",
                        arch_path.display()
                    ))
                })?;
                while let Some(file_entry) = files.next_entry().await.map_err(|error| {
                    ApiError::Internal(anyhow::anyhow!(
                        "failed to read mirrored artifact directory {}: {error}",
                        arch_path.display()
                    ))
                })? {
                    let file_name = file_entry.file_name().to_string_lossy().to_string();
                    let keep = if file_name.ends_with(".sig") {
                        let base = file_name.trim_end_matches(".sig");
                        expected_filenames
                            .contains(&(os.clone(), arch.clone(), base.to_string()))
                    } else {
                        expected_filenames.contains(&(os.clone(), arch.clone(), file_name))
                    };
                    if !keep {
                        remove_mirror_file(&file_entry.path()).await;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn find_feature(
    pool: &PgPool,
    client: &reqwest::Client,
    feature_id: &str,
    requested_version: Option<&str>,
    requested_source: Option<&str>,
) -> ApiResult<(Catalogue, FeatureIndexEntry, FeatureVersion)> {
    let source_rows = if let Some(source_id) = requested_source {
        vec![sources::get(pool, source_id).await?]
    } else {
        sources::list(pool).await?
    };
    let mut failures = Vec::new();
    for source in source_rows.into_iter().filter(|source| source.enabled) {
        match fetch_catalogue(client, &source).await {
            Ok(catalogue) => {
                if let Some(feature) = catalogue
                    .index
                    .features
                    .iter()
                    .find(|feature| feature.id == feature_id)
                    .cloned()
                {
                    let version = feature.resolve_version(requested_version)?;
                    return Ok((catalogue, feature, version));
                }
            }
            Err(error) => failures.push(format!("{}: {}", source.id, api_error_message(&error))),
        }
    }
    if failures.is_empty() {
        Err(ApiError::NotFound)
    } else {
        Err(ApiError::BadRequest(format!(
            "feature lookup failed: {}",
            failures.join("; ")
        )))
    }
}

fn resolve_channel(source_url: &str) -> String {
    // Allow embedding the suite in the source URL: …/dists/stable
    if let Ok(url) = reqwest::Url::parse(source_url) {
        let segments: Vec<&str> = url
            .path_segments()
            .map(|segments| segments.filter(|segment| !segment.is_empty()).collect())
            .unwrap_or_default();
        if segments.len() >= 2 && segments[segments.len() - 2] == "dists" {
            return segments[segments.len() - 1].to_string();
        }
    }
    std::env::var("HECATE_REPO_CHANNEL").unwrap_or_else(|_| "stable".into())
}

fn source_points_at_suite(source_url: &str) -> bool {
    reqwest::Url::parse(source_url)
        .ok()
        .and_then(|url| {
            let segments: Vec<&str> = url
                .path_segments()?
                .filter(|segment| !segment.is_empty())
                .collect();
            Some(segments.len() >= 2 && segments[segments.len() - 2] == "dists")
        })
        .unwrap_or(false)
}

/// Suite directory under the repository root (apt-like `dists/<channel>/`).
fn suite_file(source_url: &str, file: &str) -> String {
    if source_points_at_suite(source_url) {
        file.to_string()
    } else {
        format!("dists/{}/{}", resolve_channel(source_url), file)
    }
}

fn normalize_manifest_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.ends_with("feature.json") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/feature.json")
    }
}

fn artifact_relative_path(
    manifest: &FeatureManifest,
    artifact: &FeatureArtifact,
) -> ApiResult<String> {
    if let Some(url) = artifact
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(url.trim_start_matches('/').to_string());
    }
    let filename = Path::new(&artifact.filename)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ApiError::BadRequest("invalid artifact filename".into()))?;
    Ok(format!(
        "pool/{}/{}/{}/{}/{}",
        manifest.id, manifest.version, artifact.os, artifact.arch, filename
    ))
}

async fn fetch_catalogue(client: &reqwest::Client, source: &RepoSource) -> ApiResult<Catalogue> {
    let release_rel = suite_file(&source.url, "Release");
    let release_bytes = fetch::fetch_bytes(
        client,
        fetch::join_url(&source.url, &release_rel)?,
        METADATA_MAX_BYTES,
    )
    .await?;
    let release_sig = fetch::fetch_bytes(
        client,
        fetch::join_url(&source.url, &format!("{release_rel}.sig"))?,
        64,
    )
    .await?;
    verify::verify_file_signature(&source.public_key_b64, &release_bytes, &release_sig)?;
    let release = Release::parse(&release_bytes)?;

    let index_rel = suite_file(&source.url, "features.json");
    let index_bytes = fetch::fetch_bytes(
        client,
        fetch::join_url(&source.url, &index_rel)?,
        METADATA_MAX_BYTES,
    )
    .await?;
    // Release checksums are relative to the suite directory (features.json, not dists/…/features.json).
    verify::verify_release_file(&release, "features.json", &index_bytes)?;
    let index_sig = fetch::fetch_bytes(
        client,
        fetch::join_url(&source.url, &format!("{index_rel}.sig"))?,
        64,
    )
    .await?;
    verify::verify_file_signature(&source.public_key_b64, &index_bytes, &index_sig)?;
    let index: FeaturesIndex = serde_json::from_slice(&index_bytes)
        .map_err(|error| ApiError::BadRequest(format!("invalid features.json: {error}")))?;
    let generated_at = parse_index_generated_at(&index)?;
    if let Some(previous) = source.last_index_generated_at {
        if generated_at < previous {
            return Err(ApiError::BadRequest(format!(
                "features.json generated_at {generated_at} is older than last accepted index {previous}"
            )));
        }
    }
    Ok(Catalogue {
        source: source.clone(),
        release,
        index,
    })
}

fn parse_index_generated_at(index: &FeaturesIndex) -> ApiResult<chrono::DateTime<chrono::Utc>> {
    let raw = index.generated_at.as_deref().ok_or_else(|| {
        ApiError::BadRequest("features.json missing required generated_at (RFC3339)".into())
    })?;
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|_| {
            ApiError::BadRequest(format!(
                "features.json generated_at is not valid RFC3339: {raw}"
            ))
        })
}

async fn fetch_signed_file(
    client: &reqwest::Client,
    catalogue: &Catalogue,
    path: &str,
    max_bytes: usize,
    require_release_entry: bool,
) -> ApiResult<Vec<u8>> {
    let bytes = fetch::fetch_bytes(
        client,
        fetch::join_url(&catalogue.source.url, path)?,
        max_bytes,
    )
    .await?;
    if require_release_entry || catalogue.release.checksum(path).is_some() {
        verify::verify_release_file(&catalogue.release, path, &bytes)?;
    }
    let signature = fetch::fetch_bytes(
        client,
        fetch::join_url(&catalogue.source.url, &format!("{path}.sig"))?,
        64,
    )
    .await?;
    verify::verify_file_signature(&catalogue.source.public_key_b64, &bytes, &signature)?;
    Ok(bytes)
}

/// Mirror any missing or stale artifacts for installed features (same pinned version).
pub async fn sync_installed_artifact_cache(
    pool: &PgPool,
    config: &AppConfig,
) -> ApiResult<Value> {
    let client = fetch::build_client()?;
    let installed: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, pinned_version, source_id FROM installed_features ORDER BY id",
    )
    .fetch_all(pool)
    .await?;

    let mut mirrored = 0u64;
    let mut unchanged = 0u64;
    let mut errors = Vec::new();

    for (feature_id, pinned_version, source_id) in installed {
        let source = match sources::get(pool, &source_id).await {
            Ok(source) if source.enabled => source,
            Ok(_) => continue,
            Err(error) => {
                errors.push(serde_json::json!({
                    "feature_id": feature_id,
                    "error": api_error_message(&error),
                }));
                continue;
            }
        };
        let catalogue = match fetch_catalogue(&client, &source).await {
            Ok(catalogue) => catalogue,
            Err(error) => {
                errors.push(serde_json::json!({
                    "feature_id": feature_id,
                    "error": api_error_message(&error),
                }));
                continue;
            }
        };
        let Some(feature) = catalogue
            .index
            .features
            .iter()
            .find(|entry| entry.id == feature_id)
        else {
            continue;
        };
        let Some(version) = feature
            .versions
            .iter()
            .find(|entry| entry.version == pinned_version)
        else {
            continue;
        };
        let manifest_path = normalize_manifest_path(&version.manifest);
        let manifest_bytes = match fetch_signed_file(
            &client,
            &catalogue,
            &manifest_path,
            METADATA_MAX_BYTES,
            false,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(serde_json::json!({
                    "feature_id": feature_id,
                    "error": api_error_message(&error),
                }));
                continue;
            }
        };
        let manifest: FeatureManifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                errors.push(serde_json::json!({
                    "feature_id": feature_id,
                    "error": format!("invalid feature manifest: {error}"),
                }));
                continue;
            }
        };
        let before = count_cached_artifacts(pool, &feature_id, &pinned_version).await?;
        prepare_feature_mirror(pool, config, &manifest).await?;
        match mirror_artifacts(pool, config, &client, &catalogue, &manifest).await {
            Ok(()) => {
                let after = count_cached_artifacts(pool, &feature_id, &pinned_version).await?;
                if after > before {
                    mirrored += after - before;
                } else {
                    unchanged += manifest.artifacts.len() as u64;
                }
            }
            Err(error) => errors.push(serde_json::json!({
                "feature_id": feature_id,
                "error": api_error_message(&error),
            })),
        }
    }

    Ok(serde_json::json!({
        "mirrored": mirrored,
        "unchanged": unchanged,
        "errors": errors,
    }))
}

async fn count_cached_artifacts(
    pool: &PgPool,
    feature_id: &str,
    version: &str,
) -> ApiResult<u64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM feature_artifact_cache
         WHERE feature_id = $1 AND version = $2",
    )
    .bind(feature_id)
    .bind(version)
    .fetch_one(pool)
    .await?;
    Ok(count.max(0) as u64)
}

async fn cached_artifact_is_current(
    pool: &PgPool,
    manifest: &FeatureManifest,
    artifact: &FeatureArtifact,
) -> ApiResult<bool> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT sha256, local_path FROM feature_artifact_cache
         WHERE feature_id = $1 AND version = $2 AND os = $3 AND arch = $4",
    )
    .bind(&manifest.id)
    .bind(&manifest.version)
    .bind(&artifact.os)
    .bind(&artifact.arch)
    .fetch_optional(pool)
    .await?;

    let Some((cached_sha256, local_path)) = row else {
        return Ok(false);
    };
    if cached_sha256.to_ascii_lowercase() != artifact.sha256.to_ascii_lowercase() {
        return Ok(false);
    }
    Ok(tokio::fs::try_exists(&local_path).await.unwrap_or(false))
}

async fn write_mirrored_file(path: &Path, bytes: &[u8]) -> ApiResult<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(|error| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to write mirrored artifact {}: {error}",
                path.display()
            ))
        })?;
    file.write_all(bytes).await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to write mirrored artifact {}: {error}",
            path.display()
        ))
    })?;
    Ok(())
}

async fn mirror_artifacts(
    pool: &PgPool,
    config: &AppConfig,
    client: &reqwest::Client,
    catalogue: &Catalogue,
    manifest: &FeatureManifest,
) -> ApiResult<()> {
    for artifact in &manifest.artifacts {
        if cached_artifact_is_current(pool, manifest, artifact).await? {
            continue;
        }

        let relative_path = artifact_relative_path(manifest, artifact)?;
        let bytes =
            fetch_signed_file(client, catalogue, &relative_path, ARTIFACT_MAX_BYTES, false).await?;
        verify::verify_sha256(&artifact.sha256, &bytes)?;
        let signature = fetch::fetch_bytes(
            client,
            fetch::join_url(&catalogue.source.url, &format!("{relative_path}.sig"))?,
            64,
        )
        .await?;
        verify::verify_file_signature(&catalogue.source.public_key_b64, &bytes, &signature)?;

        let filename = Path::new(&artifact.filename)
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ApiError::BadRequest("invalid artifact filename".into()))?;
        let directory = config
            .hecate_repo_mirror_dir
            .join(&manifest.id)
            .join(&manifest.version)
            .join(&artifact.os)
            .join(&artifact.arch);
        tokio::fs::create_dir_all(&directory)
            .await
            .map_err(|error| {
                ApiError::Internal(anyhow::anyhow!(
                    "failed to create repository mirror directory {}: {error}",
                    directory.display()
                ))
            })?;
        let local_path = directory.join(filename);
        write_mirrored_file(&local_path, &bytes).await?;
        write_mirrored_file(
            &local_path.with_file_name(format!("{filename}.sig")),
            &signature,
        )
        .await?;

        sqlx::query(
            "INSERT INTO feature_artifact_cache
                (feature_id, version, os, arch, filename, sha256, local_path, update_signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (feature_id, version, os, arch) DO UPDATE
             SET filename = EXCLUDED.filename,
                 sha256 = EXCLUDED.sha256,
                 local_path = EXCLUDED.local_path,
                 update_signature = CASE
                   WHEN EXCLUDED.update_signature IS NULL OR BTRIM(EXCLUDED.update_signature) = ''
                     THEN feature_artifact_cache.update_signature
                   ELSE EXCLUDED.update_signature
                 END",
        )
        .bind(&manifest.id)
        .bind(&manifest.version)
        .bind(&artifact.os)
        .bind(&artifact.arch)
        .bind(filename)
        .bind(artifact.sha256.to_ascii_lowercase())
        .bind(local_path.to_string_lossy().to_string())
        .bind(
            artifact
                .update_signature
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        )
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn persist_feature(
    pool: &PgPool,
    source_id: &str,
    manifest: &FeatureManifest,
    track_latest: bool,
) -> ApiResult<()> {
    let mut feature_json =
        serde_json::to_value(manifest).map_err(|error| ApiError::Internal(error.into()))?;
    feature_json["_hecate_command_names"] = Value::Array(
        manifest
            .commands
            .iter()
            .map(|command| Value::String(command.name.clone()))
            .collect(),
    );

    let mut transaction = pool.begin().await?;
    for command in &manifest.commands {
        if !matches!(command.risk_level.as_str(), "low" | "high") {
            return Err(ApiError::BadRequest(format!(
                "invalid risk level for command {}",
                command.name
            )));
        }
        sqlx::query(
            "INSERT INTO command_definitions (name, description, input_schema, risk_level)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (name) DO UPDATE
             SET description = EXCLUDED.description,
                 input_schema = EXCLUDED.input_schema,
                 risk_level = EXCLUDED.risk_level",
        )
        .bind(&command.name)
        .bind(&command.description)
        .bind(&command.input_schema)
        .bind(&command.risk_level)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "INSERT INTO installed_features
            (id, pinned_version, source_id, track_latest, installed_at, feature_json)
         VALUES ($1, $2, $3, $4, now(), $5)
         ON CONFLICT (id) DO UPDATE
         SET pinned_version = EXCLUDED.pinned_version,
             source_id = EXCLUDED.source_id,
             track_latest = EXCLUDED.track_latest,
             installed_at = now(),
             feature_json = EXCLUDED.feature_json",
    )
    .bind(&manifest.id)
    .bind(&manifest.version)
    .bind(source_id)
    .bind(track_latest)
    .bind(feature_json)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

fn command_names(feature_json: &Value) -> Vec<String> {
    feature_json
        .get("_hecate_command_names")
        .and_then(Value::as_array)
        .or_else(|| feature_json.get("commands").and_then(Value::as_array))
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .as_str()
                .or_else(|| entry.get("name").and_then(Value::as_str))
                .map(str::to_string)
        })
        .collect()
}

fn latest_version(feature: &FeatureIndexEntry) -> Option<&str> {
    feature
        .latest
        .as_deref()
        .or(feature.version.as_deref())
        .or_else(|| feature.versions.first().map(|entry| entry.version.as_str()))
}

fn validate_feature_id(id: &str) -> ApiResult<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApiError::BadRequest("invalid feature id".into()));
    }
    Ok(())
}

fn api_error_message(error: &ApiError) -> String {
    match error {
        ApiError::BadRequest(message) | ApiError::Conflict(message) => message.clone(),
        ApiError::Internal(error) => error.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_file_uses_dists_stable_for_repo_root() {
        assert_eq!(
            suite_file("https://repo.hecate-mcp.com", "Release"),
            "dists/stable/Release"
        );
        assert_eq!(
            suite_file("https://repo.hecate-mcp.com/", "features.json"),
            "dists/stable/features.json"
        );
    }

    #[test]
    fn suite_file_respects_embedded_channel() {
        assert_eq!(
            suite_file("https://example.com/dists/testing", "Release"),
            "Release"
        );
    }

    #[test]
    fn normalize_manifest_appends_feature_json() {
        assert_eq!(
            normalize_manifest_path("pool/agent/1.0.17"),
            "pool/agent/1.0.17/feature.json"
        );
        assert_eq!(
            normalize_manifest_path("pool/agent/1.0.17/feature.json"),
            "pool/agent/1.0.17/feature.json"
        );
    }
}
