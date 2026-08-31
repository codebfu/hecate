//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use chrono::{DateTime, Duration, Utc};
use hecate_protocol::machine_tags::{merge_authz_tags, merge_effective_tags, AuthzTagSources};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::server_settings;

/// Time without heartbeat before an active agent is considered offline.
pub const OFFLINE_AFTER_SECS: i64 = 30;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MachineRow {
    pub id: Uuid,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub tags: Vec<String>,
    pub operator_tags: Vec<String>,
    pub agent_version: Option<String>,
    pub desktop_version: Option<String>,
    pub proxmox_version: Option<String>,
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub agent_healthy: Option<bool>,
    pub agent_secs_since_last_pull: Option<i64>,
    pub agent_current_command_id: Option<Uuid>,
}

pub fn effective_tags(
    agent_tags: &[String],
    operator_tags: &[String],
) -> ApiResult<Vec<String>> {
    merge_effective_tags(agent_tags, operator_tags).map_err(|error| ApiError::BadRequest(error.to_string()))
}

/// Resolve machine connectivity status: pending -> online <-> offline.
pub fn effective_status(
    last_seen_at: Option<DateTime<Utc>>,
    agent_state: Option<&str>,
) -> &'static str {
    if agent_state == Some("pending_approval") {
        return "pending";
    }
    if agent_state == Some("revoked") {
        return "offline";
    }
    match last_seen_at {
        None => "offline",
        Some(ts) if Utc::now().signed_duration_since(ts) > Duration::seconds(OFFLINE_AFTER_SECS) => {
            "offline"
        }
        Some(_) => "online",
    }
}

/// Static agent runtime hints for MCP models (live details come from system.info).
pub fn agent_runtime_for_os(os: &str) -> Value {
    match os {
        "linux" => json!({
            "platform": "linux",
            "runs_as_service_user": true,
            "elevation_method": "sudo",
            "elevated_flag_required": true,
            "note": "Use shell.run with elevated=true for root commands; never pass sudo in argv."
        }),
        "macos" => json!({
            "platform": "macos",
            "runs_as_service_user": true,
            "elevation_method": "sudo",
            "elevated_flag_required": true,
            "note": "Use shell.run with elevated=true for root commands; never pass sudo in argv."
        }),
        "windows" => json!({
            "platform": "windows",
            "runs_as_service_user": true,
            "elevation_method": "windows_admin",
            "elevated_flag_required": true,
            "note": "Use shell.run with elevated=true; requires the agent service to run as Administrator or LocalSystem."
        }),
        other => json!({
            "platform": other,
            "runs_as_service_user": true,
            "elevation_method": "none",
            "elevated_flag_required": true,
            "note": "Call system.info for live elevation availability."
        }),
    }
}

pub fn machine_row_to_json(
    row: &MachineRow,
    agent_state: Option<&str>,
    extra: Option<Value>,
) -> ApiResult<Value> {
    let tags = effective_tags(&row.tags, &row.operator_tags)?;
    let status = effective_status(row.last_seen_at, agent_state);
    let mut value = json!({
        "id": row.id,
        "hostname": row.hostname,
        "os": row.os,
        "arch": row.arch,
        "tags": tags,
        "agent_tags": row.tags,
        "operator_tags": row.operator_tags,
        "status": status,
        "agent_version": row.agent_version,
        "desktop_version": row.desktop_version,
        "proxmox_version": row.proxmox_version,
        "last_seen_at": row.last_seen_at,
        "agent_healthy": row.agent_healthy,
        "agent_secs_since_last_pull": row.agent_secs_since_last_pull,
        "agent_current_command_id": row.agent_current_command_id,
        "agent_runtime": agent_runtime_for_os(&row.os),
    });
    if let Some(extra_fields) = extra {
        if let (Some(obj), Some(extra_obj)) = (value.as_object_mut(), extra_fields.as_object()) {
            for (key, val) in extra_obj {
                obj.insert(key.clone(), val.clone());
            }
        }
    }
    Ok(value)
}

pub async fn load_machine_row(pool: &PgPool, id: Uuid) -> ApiResult<MachineRow> {
    sqlx::query_as::<_, MachineRow>(
        "SELECT id, hostname, os, arch, tags, operator_tags, agent_version, desktop_version, proxmox_version,
                last_seen_at, agent_healthy, agent_secs_since_last_pull, agent_current_command_id
         FROM machines WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)
}

pub async fn load_effective_tags(pool: &PgPool, machine_id: Uuid) -> ApiResult<Vec<String>> {
    let row = load_machine_row(pool, machine_id).await?;
    effective_tags(&row.tags, &row.operator_tags)
}

/// Tags used for AI machine authorization (filtered by admin source toggles).
pub async fn load_authz_tags(pool: &PgPool, machine_id: Uuid) -> ApiResult<Vec<String>> {
    let row = load_machine_row(pool, machine_id).await?;
    let sources = server_settings::authz_tag_sources(pool).await?;
    authz_tags(&row.tags, &row.operator_tags, sources)
}

pub fn authz_tags(
    agent_tags: &[String],
    operator_tags: &[String],
    sources: AuthzTagSources,
) -> ApiResult<Vec<String>> {
    merge_authz_tags(agent_tags, operator_tags, sources)
        .map_err(|error| ApiError::BadRequest(error.to_string()))
}

pub async fn load_agent_state(pool: &PgPool, machine_id: Uuid) -> ApiResult<Option<String>> {
    sqlx::query_scalar("SELECT state::text FROM agents WHERE machine_id = $1")
        .bind(machine_id)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
}

/// Persists offline status for active agents that stopped heartbeating.
pub async fn run_offline_sweeper(pool: PgPool) {
    let tick_secs = (OFFLINE_AFTER_SECS as u64 / 2).max(5);
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(tick_secs));
    loop {
        ticker.tick().await;
        let result = sqlx::query(
            "UPDATE machines m
             SET status = 'offline'
             FROM agents a
             WHERE a.machine_id = m.id
               AND a.state = 'active'
               AND m.status = 'online'
               AND (m.last_seen_at IS NULL
                    OR m.last_seen_at < now() - ($1 * interval '1 second'))",
        )
        .bind(OFFLINE_AFTER_SECS)
        .execute(&pool)
        .await;
        if let Err(error) = result {
            tracing::warn!(error = %error, "offline sweeper failed");
        }
    }
}

pub fn apply_operator_tag_patch(
    current: &[String],
    add: &[String],
    remove: &[String],
) -> ApiResult<Vec<String>> {
    for tag in remove {
        if !current.contains(tag) {
            return Err(ApiError::BadRequest(format!(
                "cannot remove operator tag not present: {tag}"
            )));
        }
    }

    let mut next = current.to_vec();
    for tag in remove {
        next.retain(|existing| existing != tag);
    }
    for tag in add {
        if !next.contains(tag) {
            next.push(tag.clone());
        }
    }

    hecate_protocol::machine_tags::validate_custom_tags(&next)
        .map_err(|error| ApiError::BadRequest(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_operator_tag_patch_adds_and_removes() {
        let current = vec!["env:prod".into()];
        let next = apply_operator_tag_patch(&current, &["role:web".into()], &[]).expect("valid");
        assert_eq!(next, vec!["env:prod", "role:web"]);
        let next = apply_operator_tag_patch(&next, &[], &["env:prod".into()]).expect("valid");
        assert_eq!(next, vec!["role:web"]);
    }

    #[test]
    fn apply_operator_tag_patch_rejects_unknown_remove() {
        let err = apply_operator_tag_patch(&[], &[], &["env:prod".into()]);
        assert!(err.is_err());
    }

    #[test]
    fn effective_tags_merges_agent_and_operator() {
        let tags = effective_tags(
            &["os:linux".into()],
            &["env:prod".into()],
        )
        .expect("valid");
        assert_eq!(tags, vec!["env:prod", "os:linux"]);
    }

    #[test]
    fn effective_status_pending_until_approved() {
        assert_eq!(
            effective_status(None, Some("pending_approval")),
            "pending"
        );
        assert_eq!(
            effective_status(Some(Utc::now()), Some("pending_approval")),
            "pending"
        );
    }

    #[test]
    fn effective_status_online_when_recently_seen() {
        assert_eq!(
            effective_status(Some(Utc::now()), Some("active")),
            "online"
        );
    }

    #[test]
    fn effective_status_offline_when_stale_or_missing() {
        let stale = Utc::now() - Duration::seconds(OFFLINE_AFTER_SECS + 1);
        assert_eq!(effective_status(None, Some("active")), "offline");
        assert_eq!(effective_status(Some(stale), Some("active")), "offline");
        assert_eq!(effective_status(Some(stale), Some("revoked")), "offline");
    }
}
