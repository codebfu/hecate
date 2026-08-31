//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;

use hecate_protocol::backup::{
    BackupManifest, BackupSectionData, BackupSectionId, BackupSectionMeta,
    BACKUP_FORMAT, BACKUP_FORMAT_VERSION_CURRENT,
};
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};

pub fn exportable_sections() -> Vec<BackupSectionMeta> {
    BackupSectionId::all_exportable()
        .iter()
        .map(|s| BackupSectionMeta {
            id: s.as_str().to_string(),
            label: section_label(s.as_str()),
            default_selected: true,
            exportable: true,
        })
        .collect()
}

fn section_label(id: &str) -> String {
    match id {
        "server_settings" => "Settings".into(),
        other => other.replace('_', " "),
    }
}

pub async fn export_sections(pool: &PgPool, section_ids: &[String]) -> ApiResult<BackupManifest> {
    let mut sections = HashMap::new();
    for id in section_ids {
        let data = export_one(pool, id).await?;
        sections.insert(
            id.clone(),
            BackupSectionData {
                section_format_version: 1,
                data,
            },
        );
    }
    let schema_version: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    Ok(BackupManifest::new(schema_version, sections))
}

async fn export_one(pool: &PgPool, id: &str) -> ApiResult<serde_json::Value> {
    match id {
        "ai_identities" => {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM (SELECT id, name, description, active, requires_approval_for_shell, requires_approval_for_elevated FROM ai_identities) t",
            )
            .fetch_all(pool)
            .await?;
            Ok(serde_json::Value::Array(rows))
        }
        "ai_permissions" => {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM ai_permissions t",
            )
            .fetch_all(pool)
            .await?;
            Ok(serde_json::Value::Array(rows))
        }
        "operators" => {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM (SELECT id, login, role, must_change_password, onboarding_complete, disabled_at FROM operators) t",
            )
            .fetch_all(pool)
            .await?;
            Ok(serde_json::Value::Array(rows))
        }
        "operator_webauthn" => {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM (SELECT id, operator_id, name, encode(credential_id, 'base64') as credential_id, encode(public_key, 'base64') as public_key, sign_count, created_at, last_used_at, revoked_at FROM operator_webauthn_credentials) t",
            )
            .fetch_all(pool)
            .await?;
            Ok(serde_json::Value::Array(rows))
        }
        "fleet" => {
            let machines: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM machines t",
            )
            .fetch_all(pool)
            .await?;
            let agents: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM agents t",
            )
            .fetch_all(pool)
            .await?;
            Ok(serde_json::json!({ "machines": machines, "agents": agents }))
        }
        "command_definitions" => {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM command_definitions t",
            )
            .fetch_all(pool)
            .await?;
            Ok(serde_json::Value::Array(rows))
        }
        "agent_releases" => {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM agent_releases t",
            )
            .fetch_all(pool)
            .await?;
            Ok(serde_json::Value::Array(rows))
        }
        "server_settings" => {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT row_to_json(t) FROM server_settings t",
            )
            .fetch_all(pool)
            .await?;
            Ok(serde_json::Value::Array(rows))
        }
        _ => Err(ApiError::BadRequest(format!("unknown section: {id}"))),
    }
}

pub fn upgrade_backup(mut manifest: BackupManifest) -> ApiResult<BackupManifest> {
    while manifest.backup_format_version < BACKUP_FORMAT_VERSION_CURRENT {
        manifest.backup_format_version += 1;
    }
    manifest.format = BACKUP_FORMAT.to_string();
    Ok(manifest)
}

pub fn parse_manifest(bytes: &[u8]) -> ApiResult<BackupManifest> {
    let manifest: BackupManifest = serde_json::from_slice(bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid backup: {e}")))?;
    if manifest.format != BACKUP_FORMAT {
        return Err(ApiError::BadRequest("invalid backup format".into()));
    }
    Ok(manifest)
}

pub struct PreviewSection {
    pub id: String,
    pub label: String,
    pub present: bool,
    pub restorable: bool,
    pub default_selected: bool,
    pub warnings: Vec<String>,
}

pub fn preview_sections(manifest: &BackupManifest) -> Vec<PreviewSection> {
    exportable_sections()
        .into_iter()
        .map(|meta| {
            let present = manifest.sections.contains_key(&meta.id);
            let mut warnings = Vec::new();
            if meta.id == "fleet" && present {
                warnings.push(
                    "Fleet backup includes agent signing material (encrypted at rest with the backup password)."
                        .into(),
                );
            }
            if meta.id == "operators" && present {
                warnings.push(
                    "Operator password hashes are not exported; restore will not import password_hash and forces password reset."
                        .into(),
                );
            }
            if meta.id == "operator_webauthn" && present {
                warnings.push(
                    "WebAuthn credentials cannot be safely restored from backup; re-register passkeys after restore."
                        .into(),
                );
            }
            if meta.id == "agent_releases" && present {
                warnings.push(
                    "Release artifact_path values must remain under the server release artifacts directory."
                        .into(),
                );
            }
            PreviewSection {
                id: meta.id.clone(),
                label: meta.label,
                default_selected: present,
                restorable: present && meta.id != "operator_webauthn",
                present,
                warnings,
            }
        })
        .filter(|s| s.present)
        .collect()
}

pub async fn restore_sections(
    pool: &PgPool,
    section_ids: &[String],
    manifest: &BackupManifest,
    release_artifacts_dir: &std::path::Path,
) -> ApiResult<Vec<String>> {
    let mut tx = pool.begin().await?;
    let mut restored = Vec::new();
    for section_id in section_ids {
        let section = manifest
            .sections
            .get(section_id)
            .ok_or_else(|| ApiError::BadRequest(format!("section not in manifest: {section_id}")))?;
        restore_one(&mut tx, section_id, &section.data, release_artifacts_dir).await?;
        restored.push(section_id.clone());
    }
    tx.commit().await?;
    Ok(restored)
}

async fn restore_one(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    data: &serde_json::Value,
    release_artifacts_dir: &std::path::Path,
) -> ApiResult<()> {
    match id {
        "ai_identities" => restore_rows(
            tx,
            data,
            "INSERT INTO ai_identities (id, name, description, active, requires_approval_for_shell, requires_approval_for_elevated)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO UPDATE SET
               name = EXCLUDED.name,
               description = EXCLUDED.description,
               active = EXCLUDED.active,
               requires_approval_for_shell = EXCLUDED.requires_approval_for_shell,
               requires_approval_for_elevated = EXCLUDED.requires_approval_for_elevated",
            &["id", "name", "description", "active", "requires_approval_for_shell", "requires_approval_for_elevated"],
        )
        .await,
        "ai_permissions" => restore_rows(
            tx,
            data,
            "INSERT INTO ai_permissions (ai_identity_id, rules)
             VALUES ($1, $2)
             ON CONFLICT (ai_identity_id) DO UPDATE SET rules = EXCLUDED.rules",
            &["ai_identity_id", "rules"],
        )
        .await,
        "operators" => restore_operators(tx, data).await,
        "operator_webauthn" => Err(ApiError::BadRequest(
            "operator_webauthn restore is disabled; re-register WebAuthn credentials after restore"
                .into(),
        )),
        "fleet" => restore_fleet(tx, data).await,
        "command_definitions" => restore_rows(
            tx,
            data,
            "INSERT INTO command_definitions (name, description, input_schema, risk_level)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (name) DO UPDATE SET
               description = EXCLUDED.description,
               input_schema = EXCLUDED.input_schema,
               risk_level = EXCLUDED.risk_level",
            &["name", "description", "input_schema", "risk_level"],
        )
        .await,
        "agent_releases" => restore_agent_releases(tx, data, release_artifacts_dir).await,
        "server_settings" => restore_rows(
            tx,
            data,
            "INSERT INTO server_settings (key, value)
             VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &["key", "value"],
        )
        .await,
        _ => Err(ApiError::BadRequest(format!("unknown section: {id}"))),
    }
}

async fn restore_rows(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    data: &serde_json::Value,
    sql: &str,
    fields: &[&str],
) -> ApiResult<()> {
    let rows = data
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("section data must be a JSON array".into()))?;
    for row in rows {
        let obj = row
            .as_object()
            .ok_or_else(|| ApiError::BadRequest("section row must be an object".into()))?;
        let mut query = sqlx::query(sql);
        for field in fields {
            let value = obj
                .get(*field)
                .ok_or_else(|| ApiError::BadRequest(format!("missing field: {field}")))?;
            query = query.bind(value.clone());
        }
        query.execute(&mut **tx).await?;
    }
    Ok(())
}

async fn restore_operators(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    data: &serde_json::Value,
) -> ApiResult<()> {
    let rows = data
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("section data must be a JSON array".into()))?;
    for row in rows {
        let obj = row
            .as_object()
            .ok_or_else(|| ApiError::BadRequest("section row must be an object".into()))?;
        if obj.contains_key("password_hash") {
            return Err(ApiError::BadRequest(
                "operators restore must not include password_hash; use password reset after restore"
                    .into(),
            ));
        }
        let id = obj
            .get("id")
            .ok_or_else(|| ApiError::BadRequest("missing field: id".into()))?;
        let login = obj
            .get("login")
            .ok_or_else(|| ApiError::BadRequest("missing field: login".into()))?;
        let role = obj
            .get("role")
            .ok_or_else(|| ApiError::BadRequest("missing field: role".into()))?;
        let disabled_at = obj.get("disabled_at").cloned().unwrap_or(serde_json::Value::Null);
        // Placeholder hash forces password reset; never import external hashes.
        let placeholder = crate::crypto::hash_password(&format!(
            "restore-reset-{}",
            uuid::Uuid::new_v4()
        ))
        .map_err(ApiError::Internal)?;
        sqlx::query(
            "INSERT INTO operators (id, login, password_hash, role, must_change_password, onboarding_complete, disabled_at)
             VALUES ($1, $2, $3, $4::operator_role, true, false, $5)
             ON CONFLICT (id) DO UPDATE SET
               login = EXCLUDED.login,
               role = EXCLUDED.role,
               must_change_password = true,
               onboarding_complete = false,
               disabled_at = EXCLUDED.disabled_at",
        )
        .bind(id.clone())
        .bind(login.clone())
        .bind(placeholder)
        .bind(role.clone())
        .bind(disabled_at)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn restore_agent_releases(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    data: &serde_json::Value,
    release_artifacts_dir: &std::path::Path,
) -> ApiResult<()> {
    let rows = data
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("section data must be a JSON array".into()))?;
    for row in rows {
        let obj = row
            .as_object()
            .ok_or_else(|| ApiError::BadRequest("section row must be an object".into()))?;
        let version = obj
            .get("version")
            .ok_or_else(|| ApiError::BadRequest("missing field: version".into()))?;
        let os = obj
            .get("os")
            .ok_or_else(|| ApiError::BadRequest("missing field: os".into()))?;
        let arch = obj
            .get("arch")
            .ok_or_else(|| ApiError::BadRequest("missing field: arch".into()))?;
        let artifact_path = obj
            .get("artifact_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::BadRequest("missing field: artifact_path".into()))?;
        let jailed =
            crate::routes::agent::jail_release_artifact_path(release_artifacts_dir, artifact_path)?;
        let sha256 = obj
            .get("sha256")
            .ok_or_else(|| ApiError::BadRequest("missing field: sha256".into()))?;
        let signature = obj
            .get("signature")
            .ok_or_else(|| ApiError::BadRequest("missing field: signature".into()))?;
        let component = obj
            .get("component")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::String("agent".into()));
        sqlx::query(
            "INSERT INTO agent_releases (version, os, arch, component, artifact_path, sha256, signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (version, os, arch, component) DO UPDATE SET
               artifact_path = EXCLUDED.artifact_path,
               sha256 = EXCLUDED.sha256,
               signature = EXCLUDED.signature",
        )
        .bind(version.clone())
        .bind(os.clone())
        .bind(arch.clone())
        .bind(component)
        .bind(jailed)
        .bind(sha256.clone())
        .bind(signature.clone())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn restore_fleet(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    data: &serde_json::Value,
) -> ApiResult<()> {
    let machines = data
        .get("machines")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ApiError::BadRequest("fleet.machines required".into()))?;
    for row in machines {
        let obj = row
            .as_object()
            .ok_or_else(|| ApiError::BadRequest("machine row must be an object".into()))?;
        sqlx::query(
            "INSERT INTO machines (id, hostname, os, arch, tags, operator_tags, status, agent_version, desktop_version, proxmox_version, last_seen_at, attestation_json)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (id) DO UPDATE SET
               hostname = EXCLUDED.hostname,
               os = EXCLUDED.os,
               arch = EXCLUDED.arch,
               tags = EXCLUDED.tags,
               operator_tags = EXCLUDED.operator_tags,
               status = EXCLUDED.status,
               agent_version = EXCLUDED.agent_version,
               desktop_version = EXCLUDED.desktop_version,
               proxmox_version = EXCLUDED.proxmox_version,
               last_seen_at = EXCLUDED.last_seen_at,
               attestation_json = EXCLUDED.attestation_json",
        )
        .bind(obj.get("id").cloned().unwrap_or(serde_json::Value::Null))
        .bind(obj.get("hostname").cloned().unwrap_or(serde_json::Value::Null))
        .bind(obj.get("os").cloned().unwrap_or(serde_json::Value::Null))
        .bind(obj.get("arch").cloned().unwrap_or(serde_json::Value::Null))
        .bind(obj.get("tags").cloned().unwrap_or(serde_json::json!([])))
        .bind(obj.get("operator_tags").cloned().unwrap_or(serde_json::json!([])))
        .bind(obj.get("status").cloned().unwrap_or(serde_json::json!("offline")))
        .bind(obj.get("agent_version").cloned())
        .bind(obj.get("desktop_version").cloned())
        .bind(obj.get("proxmox_version").cloned())
        .bind(obj.get("last_seen_at").cloned())
        .bind(
            obj.get("attestation_json")
                .cloned()
                .unwrap_or(serde_json::json!({})),
        )
        .execute(&mut **tx)
        .await?;
    }
    if let Some(agents) = data.get("agents").and_then(|v| v.as_array()) {
        for row in agents {
            let obj = row
                .as_object()
                .ok_or_else(|| ApiError::BadRequest("agent row must be an object".into()))?;
            sqlx::query(
                "INSERT INTO agents (machine_id, credential_pubkey, task_signing_privkey, state, enrolled_at, revoked_at, last_nonce_window)
                 VALUES ($1, $2, $3, $4::agent_state, $5, $6, $7)
                 ON CONFLICT (machine_id) DO UPDATE SET
                   credential_pubkey = EXCLUDED.credential_pubkey,
                   task_signing_privkey = EXCLUDED.task_signing_privkey,
                   state = EXCLUDED.state,
                   enrolled_at = EXCLUDED.enrolled_at,
                   revoked_at = EXCLUDED.revoked_at,
                   last_nonce_window = EXCLUDED.last_nonce_window",
            )
            .bind(obj.get("machine_id").cloned().unwrap_or(serde_json::Value::Null))
            .bind(
                obj.get("credential_pubkey")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .bind(
                obj.get("task_signing_privkey")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .bind(
                obj.get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("pending_approval"),
            )
            .bind(obj.get("enrolled_at").cloned())
            .bind(obj.get("revoked_at").cloned())
            .bind(obj.get("last_nonce_window").cloned())
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}
