//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Temporary command artifact storage for file push/pull workflows.

use std::path::Path;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::append_audit;
use crate::crypto::{constant_time_eq_hex, sha256_hex};
use crate::error::{ApiError, ApiResult};
use crate::state::AppConfig;

pub const COMMAND_ARTIFACT_PATH_PREFIX: &str = "/api/v1/agent/commands";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CommandArtifactRow {
    pub id: Uuid,
    pub storage_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct StoredInputArtifact {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub size_bytes: i64,
    pub original_name: String,
}

pub fn command_artifact_api_path(command_id: Uuid) -> String {
    format!("{COMMAND_ARTIFACT_PATH_PREFIX}/{command_id}/artifact")
}

pub fn command_requires_operator_approval(command_name: &str) -> bool {
    // Deny-by-default evaluation helper for unit tests / legacy call sites.
    // Production enqueue uses command_definitions.risk_level instead.
    !matches!(
        command_name,
        "desktop.info"
            | "desktop.window.list"
            | "desktop.window.wait"
            | "proxmox.info"
            | "proxmox.vm.list"
            | "system.info"
    )
}

async fn content_scan_rules(
    pool: &PgPool,
    ai_identity_id: Uuid,
) -> ApiResult<hecate_protocol::permissions::CapabilityProfileRules> {
    use hecate_protocol::permissions::{
        CapabilityProfileRules, ElevationPolicy, ShellPolicy, ALLOWLIST_WILDCARD,
        DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT_SECS,
    };

    let assignments =
        crate::authz::store::load_enabled_assignment_details(pool, ai_identity_id).await?;
    let mut rules = CapabilityProfileRules {
        allowed_commands: vec![],
        allowed_admin_commands: vec![],
        shell_policy: ShellPolicy::default(),
        elevation_policy: ElevationPolicy::default(),
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
        max_concurrent: DEFAULT_MAX_CONCURRENT,
    };
    for (_, detail) in assignments {
        let profile = detail.capability_profile;
        if profile.shell_policy.allowed_binaries.iter().any(|b| b == ALLOWLIST_WILDCARD) {
            rules.shell_policy.allowed_binaries = vec![ALLOWLIST_WILDCARD.into()];
        } else {
            for bin in profile.shell_policy.allowed_binaries {
                if !rules.shell_policy.allowed_binaries.contains(&bin) {
                    rules.shell_policy.allowed_binaries.push(bin);
                }
            }
        }
        rules.max_output_bytes = rules.max_output_bytes.max(profile.max_output_bytes);
        rules.max_file_bytes = rules.max_file_bytes.max(profile.max_file_bytes);
    }
    Ok(rules)
}

pub async fn load_artifact_bytes_for_scan(pool: &PgPool, artifact_id: Uuid) -> ApiResult<Vec<u8>> {
    let path: Option<String> = sqlx::query_scalar(
        "SELECT storage_path FROM command_artifacts WHERE id = $1 AND direction = 'input'",
    )
    .bind(artifact_id)
    .fetch_optional(pool)
    .await?;
    let Some(path) = path else {
        return Err(ApiError::NotFound);
    };
    tokio::fs::read(&path)
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("read artifact for scan: {error}")))
}

pub async fn store_input_artifact(
    pool: &PgPool,
    config: &AppConfig,
    ai_identity_id: Uuid,
    original_name: &str,
    body: &[u8],
    expected_sha256: Option<&str>,
) -> ApiResult<StoredInputArtifact> {
    if body.is_empty() {
        return Err(ApiError::BadRequest("artifact body must not be empty".into()));
    }
    crate::content_policy::ensure_not_locked(pool, ai_identity_id).await?;
    let rules = content_scan_rules(pool, ai_identity_id).await?;
    crate::content_policy::enforce_content_policy(
        pool,
        ai_identity_id,
        &rules,
        "file.push",
        &serde_json::json!({}),
        Some(body),
    )
    .await?;
    if body.len() > config.command_artifact_max_bytes() {
        return Err(ApiError::BadRequest(format!(
            "artifact exceeds max size of {} bytes",
            config.command_artifact_max_bytes()
        )));
    }

    let sha256 = sha256_hex(body);
    if let Some(expected) = expected_sha256 {
        if !expected.is_empty() && !constant_time_eq_hex(&sha256, expected) {
            return Err(ApiError::BadRequest("sha256 mismatch".into()));
        }
    }

    let artifact_id = Uuid::new_v4();
    let storage_path = config
        .command_artifacts_dir
        .join(ai_identity_id.to_string())
        .join(format!("{artifact_id}.bin"));
    write_artifact_file(&storage_path, body).await?;

    let expires_at = artifact_expires_at(config);
    sqlx::query(
        "INSERT INTO command_artifacts
         (id, command_id, ai_identity_id, direction, storage_path, sha256, size_bytes, original_name, expires_at)
         VALUES ($1, NULL, $2, 'input', $3, $4, $5, $6, $7)",
    )
    .bind(artifact_id)
    .bind(ai_identity_id)
    .bind(storage_path.to_string_lossy().to_string())
    .bind(&sha256)
    .bind(body.len() as i64)
    .bind(original_name)
    .bind(expires_at)
    .execute(pool)
    .await?;

    append_audit(
        pool,
        &ai_identity_id.to_string(),
        "artifact.upload",
        &artifact_id.to_string(),
        "",
        &serde_json::json!({
            "direction": "input",
            "size_bytes": body.len(),
            "sha256": sha256,
        }),
    )
    .await?;

    Ok(StoredInputArtifact {
        artifact_id,
        sha256,
        size_bytes: body.len() as i64,
        original_name: original_name.to_string(),
    })
}

pub async fn link_input_artifact_to_command(
    pool: &PgPool,
    ai_identity_id: Uuid,
    command_id: Uuid,
    artifact_id: Uuid,
    expected_sha256: &str,
) -> ApiResult<()> {
    let row: Option<CommandArtifactRow> = sqlx::query_as(
        "SELECT id, storage_path, sha256
         FROM command_artifacts
         WHERE id = $1 AND ai_identity_id = $2 AND direction = 'input' AND command_id IS NULL",
    )
    .bind(artifact_id)
    .bind(ai_identity_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Err(ApiError::BadRequest("artifact not found or already linked".into()));
    };

    if !expected_sha256.is_empty() && !constant_time_eq_hex(&row.sha256, expected_sha256) {
        return Err(ApiError::BadRequest("artifact sha256 mismatch".into()));
    }

    let updated = sqlx::query(
        "UPDATE command_artifacts SET command_id = $1
         WHERE id = $2 AND command_id IS NULL",
    )
    .bind(command_id)
    .bind(artifact_id)
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::Conflict("artifact already linked".into()));
    }

    Ok(())
}

pub async fn store_output_artifact(
    pool: &PgPool,
    config: &AppConfig,
    command_id: Uuid,
    ai_identity_id: Uuid,
    original_name: &str,
    body: &[u8],
    expected_sha256: Option<&str>,
) -> ApiResult<StoredInputArtifact> {
    if body.is_empty() {
        return Err(ApiError::BadRequest("artifact body must not be empty".into()));
    }
    if body.len() > config.command_artifact_max_bytes() {
        return Err(ApiError::BadRequest(format!(
            "artifact exceeds max size of {} bytes",
            config.command_artifact_max_bytes()
        )));
    }

    let sha256 = sha256_hex(body);
    if let Some(expected) = expected_sha256 {
        if !expected.is_empty() && !constant_time_eq_hex(&sha256, expected) {
            return Err(ApiError::BadRequest("sha256 mismatch".into()));
        }
    }

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM command_artifacts WHERE command_id = $1 AND direction = 'output'",
    )
    .bind(command_id)
    .fetch_optional(pool)
    .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict("output artifact already stored".into()));
    }

    let artifact_id = Uuid::new_v4();
    let storage_path = config
        .command_artifacts_dir
        .join(ai_identity_id.to_string())
        .join(format!("{artifact_id}.bin"));
    write_artifact_file(&storage_path, body).await?;

    let expires_at = artifact_expires_at(config);
    sqlx::query(
        "INSERT INTO command_artifacts
         (id, command_id, ai_identity_id, direction, storage_path, sha256, size_bytes, original_name, expires_at)
         VALUES ($1, $2, $3, 'output', $4, $5, $6, $7, $8)",
    )
    .bind(artifact_id)
    .bind(command_id)
    .bind(ai_identity_id)
    .bind(storage_path.to_string_lossy().to_string())
    .bind(&sha256)
    .bind(body.len() as i64)
    .bind(original_name)
    .bind(expires_at)
    .execute(pool)
    .await?;

    append_audit(
        pool,
        "agent",
        "artifact.upload",
        &artifact_id.to_string(),
        "",
        &serde_json::json!({
            "command_id": command_id,
            "direction": "output",
            "size_bytes": body.len(),
            "sha256": sha256,
        }),
    )
    .await?;

    Ok(StoredInputArtifact {
        artifact_id,
        sha256,
        size_bytes: body.len() as i64,
        original_name: original_name.to_string(),
    })
}

pub async fn load_agent_input_artifact(
    pool: &PgPool,
    command_id: Uuid,
    machine_id: Uuid,
) -> ApiResult<(CommandArtifactRow, Vec<u8>)> {
    let row: Option<CommandArtifactRow> = sqlx::query_as(
        "SELECT a.id, a.storage_path, a.sha256
         FROM command_artifacts a
         JOIN command_queue q ON q.id = a.command_id
         WHERE a.command_id = $1
           AND a.direction = 'input'
           AND q.machine_id = $2
           AND q.command_name IN ('file.push', 'desktop.clipboard.set')
           AND q.status IN ('dispatched', 'running')",
    )
    .bind(command_id)
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;

    let row = row.ok_or(ApiError::NotFound)?;
    let bytes = read_artifact_file(&row.storage_path).await?;
    if !constant_time_eq_hex(&sha256_hex(&bytes), &row.sha256) {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "stored artifact checksum mismatch"
        )));
    }
    Ok((row, bytes))
}

pub async fn load_internal_output_artifact(
    pool: &PgPool,
    ai_identity_id: Uuid,
    command_id: Uuid,
) -> ApiResult<(CommandArtifactRow, Vec<u8>)> {
    let row: Option<CommandArtifactRow> = sqlx::query_as(
        "SELECT a.id, a.storage_path, a.sha256
         FROM command_artifacts a
         JOIN command_queue q ON q.id = a.command_id
         WHERE a.command_id = $1
           AND a.direction = 'output'
           AND q.ai_identity_id = $2
           AND q.status = 'completed'",
    )
    .bind(command_id)
    .bind(ai_identity_id)
    .fetch_optional(pool)
    .await?;

    let row = row.ok_or(ApiError::NotFound)?;
    let bytes = read_artifact_file(&row.storage_path).await?;
    append_audit(
        pool,
        &ai_identity_id.to_string(),
        "artifact.download",
        &row.id.to_string(),
        "",
        &serde_json::json!({
            "command_id": command_id,
            "direction": "output",
        }),
    )
    .await?;
    Ok((row, bytes))
}

pub async fn verify_command_allows_output_upload(
    pool: &PgPool,
    command_id: Uuid,
    machine_id: Uuid,
) -> ApiResult<(Uuid, String)> {
    let row: Option<(Option<Uuid>, String)> = sqlx::query_as(
        "SELECT ai_identity_id, command_name
         FROM command_queue
         WHERE id = $1
           AND machine_id = $2
           AND status IN ('dispatched', 'running')
           AND command_name IN (
             'file.pull',
             'remote.download',
             'desktop.screenshot',
             'desktop.session.frame',
             'desktop.clipboard.get'
           )",
    )
    .bind(command_id)
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;

    let Some((ai_identity_id, command_name)) = row else {
        return Err(ApiError::Conflict("command not awaiting artifact upload".into()));
    };
    let ai_identity_id = ai_identity_id.ok_or(ApiError::Conflict(
        "command has no owning AI identity".into(),
    ))?;
    Ok((ai_identity_id, command_name))
}

pub async fn cleanup_expired_artifacts(pool: &PgPool) -> ApiResult<u64> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "DELETE FROM command_artifacts
         WHERE expires_at <= now()
         RETURNING storage_path",
    )
    .fetch_all(pool)
    .await?;

    let mut removed = 0u64;
    for (storage_path,) in rows {
        if tokio::fs::remove_file(&storage_path).await.is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn spawn_artifact_cleanup_loop(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            if let Err(error) = cleanup_expired_artifacts(&pool).await {
                tracing::warn!(error = %error, "command artifact cleanup failed");
            }
        }
    });
}

fn artifact_expires_at(config: &AppConfig) -> chrono::DateTime<Utc> {
    Utc::now() + ChronoDuration::hours(config.command_artifact_ttl_hours)
}

async fn write_artifact_file(path: &Path, body: &[u8]) -> ApiResult<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to create artifact directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .map_err(|error| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to create artifact {}: {error}",
                path.display()
            ))
        })?;
    use tokio::io::AsyncWriteExt;
    file.write_all(body).await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to write artifact {}: {error}",
            path.display()
        ))
    })?;
    file.sync_all().await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to sync artifact {}: {error}",
            path.display()
        ))
    })?;
    Ok(())
}

async fn read_artifact_file(path: &str) -> ApiResult<Vec<u8>> {
    tokio::fs::read(path).await.map_err(|error| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to read artifact {path}: {error}"
        ))
    })
}

impl AppConfig {
    pub fn command_artifact_max_bytes(&self) -> usize {
        hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_artifact_api_path_format() {
        let id = Uuid::from_u128(42);
        assert_eq!(
            command_artifact_api_path(id),
            format!("/api/v1/agent/commands/{id}/artifact")
        );
    }

    #[test]
    fn file_commands_require_operator_approval() {
        assert!(command_requires_operator_approval("file.pull"));
        assert!(command_requires_operator_approval("file.copy"));
        assert!(command_requires_operator_approval("folder.mkdir"));
        assert!(command_requires_operator_approval("desktop.screenshot"));
        assert!(command_requires_operator_approval("desktop.session.open"));
        assert!(command_requires_operator_approval("desktop.app.launch"));
        assert!(command_requires_operator_approval("desktop.window.focus"));
        assert!(command_requires_operator_approval("desktop.shell.run"));
        assert!(command_requires_operator_approval("system.reboot"));
        assert!(command_requires_operator_approval("agent.update"));
        assert!(command_requires_operator_approval("helper.install"));
        assert!(!command_requires_operator_approval("desktop.info"));
        assert!(!command_requires_operator_approval("desktop.window.list"));
        assert!(!command_requires_operator_approval("desktop.window.wait"));
        assert!(command_requires_operator_approval("proxmox.console.open"));
        assert!(command_requires_operator_approval("proxmox.console.frame"));
        assert!(command_requires_operator_approval("proxmox.console.input"));
        assert!(command_requires_operator_approval("proxmox.console.close"));
        assert!(!command_requires_operator_approval("proxmox.info"));
        assert!(!command_requires_operator_approval("proxmox.vm.list"));
        assert!(!command_requires_operator_approval("system.info"));
    }
}
