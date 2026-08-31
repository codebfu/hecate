//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::crypto::{audit_entry_hash, sha256_hex};
use crate::error::ApiResult;

#[derive(Debug, Clone, sqlx::FromRow)]
struct AuditEventRow {
    id: i64,
    actor: String,
    action: String,
    target: String,
    created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditRefKind {
    AiIdentity,
    Operator,
    Machine,
    Command,
    AiApiKey,
    Agent,
}

#[derive(Debug, Serialize)]
pub struct AuditEventRef {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<AuditRefKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditEventListItem {
    pub id: String,
    pub actor: AuditEventRef,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<AuditEventRef>,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TargetEntity {
    Machine,
    Operator,
    AiIdentity,
    AiApiKey,
    Command,
}

fn target_entity(action: &str) -> Option<TargetEntity> {
    if action.starts_with("machine.") || action.starts_with("agent.") {
        Some(TargetEntity::Machine)
    } else if action.starts_with("operator.") || action.starts_with("auth.") {
        Some(TargetEntity::Operator)
    } else if action.starts_with("ai_identity.") || action.starts_with("ai_permissions.") {
        Some(TargetEntity::AiIdentity)
    } else if action.starts_with("ai_api_key.") {
        Some(TargetEntity::AiApiKey)
    } else if action.starts_with("releases.") || action.starts_with("server.") || action.starts_with("settings.") {
        None
    } else if action == "command.enqueue" || action == "command.approve" || action == "command.cancel" {
        Some(TargetEntity::Command)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct CommandTargetInfo {
    command_name: String,
    params: Value,
}

#[derive(Debug, Clone)]
struct AiApiKeyInfo {
    prefix: String,
    ai_identity_id: Uuid,
}

fn entity_ref_kind(entity: TargetEntity) -> AuditRefKind {
    match entity {
        TargetEntity::Machine => AuditRefKind::Machine,
        TargetEntity::Operator => AuditRefKind::Operator,
        TargetEntity::AiIdentity => AuditRefKind::AiIdentity,
        TargetEntity::AiApiKey => AuditRefKind::AiApiKey,
        TargetEntity::Command => AuditRefKind::Command,
    }
}

fn format_actor_ref(
    actor: &str,
    ai_names: &HashMap<Uuid, String>,
    operator_logins: &HashMap<String, Uuid>,
) -> AuditEventRef {
    if actor == "agent" {
        return AuditEventRef {
            label: "agent".into(),
            id: None,
            kind: Some(AuditRefKind::Agent),
            related_id: None,
            detail: None,
        };
    }

    if let Ok(id) = Uuid::parse_str(actor) {
        if let Some(name) = ai_names.get(&id) {
            return AuditEventRef {
                label: name.clone(),
                id: Some(id.to_string()),
                kind: Some(AuditRefKind::AiIdentity),
                related_id: None,
                detail: None,
            };
        }
        return AuditEventRef {
            label: id.to_string(),
            id: Some(id.to_string()),
            kind: None,
            related_id: None,
            detail: None,
        };
    }

    AuditEventRef {
        label: actor.to_string(),
        id: operator_logins.get(actor).map(|id| id.to_string()),
        kind: Some(AuditRefKind::Operator),
        related_id: None,
        detail: None,
    }
}

fn format_entity_target_ref(
    entity: TargetEntity,
    id: Uuid,
    name: Option<String>,
    ai_api_key_info: Option<&AiApiKeyInfo>,
) -> AuditEventRef {
    if entity == TargetEntity::AiApiKey {
        if let Some(info) = ai_api_key_info {
            return AuditEventRef {
                label: format!("{}…", info.prefix),
                id: Some(id.to_string()),
                kind: Some(AuditRefKind::AiApiKey),
                related_id: Some(info.ai_identity_id.to_string()),
                detail: None,
            };
        }
    }

    let label = name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| id.to_string());
    AuditEventRef {
        label,
        id: Some(id.to_string()),
        kind: Some(entity_ref_kind(entity)),
        related_id: None,
        detail: None,
    }
}

fn command_params_detail(params: &Value) -> Option<String> {
    params
        .as_object()
        .filter(|object| !object.is_empty())
        .map(|_| params.to_string())
}

fn format_command_target_ref(id: Uuid, info: &CommandTargetInfo) -> AuditEventRef {
    AuditEventRef {
        label: info.command_name.clone(),
        id: Some(id.to_string()),
        kind: Some(AuditRefKind::Command),
        related_id: None,
        detail: command_params_detail(&info.params),
    }
}

async fn load_target_names(
    pool: &PgPool,
    entity: TargetEntity,
    ids: &[Uuid],
) -> ApiResult<HashMap<Uuid, String>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String)> = match entity {
        TargetEntity::Machine => {
            sqlx::query_as("SELECT id, hostname FROM machines WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(pool)
                .await?
        }
        TargetEntity::Operator => {
            sqlx::query_as("SELECT id, login FROM operators WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(pool)
                .await?
        }
        TargetEntity::AiIdentity => {
            sqlx::query_as("SELECT id, name FROM ai_identities WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(pool)
                .await?
        }
        TargetEntity::AiApiKey => unreachable!("ai api key targets are loaded separately"),
        TargetEntity::Command => unreachable!("command targets are loaded separately"),
    };
    Ok(rows.into_iter().collect())
}

async fn load_operator_ids_by_login(
    pool: &PgPool,
    logins: &[String],
) -> ApiResult<HashMap<String, Uuid>> {
    if logins.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT login, id FROM operators WHERE login = ANY($1)",
    )
    .bind(logins)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().collect())
}

async fn load_ai_api_key_targets(
    pool: &PgPool,
    ids: &[Uuid],
) -> ApiResult<HashMap<Uuid, AiApiKeyInfo>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
        "SELECT id, prefix, ai_identity_id FROM ai_api_keys WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, prefix, ai_identity_id)| {
            (
                id,
                AiApiKeyInfo {
                    prefix,
                    ai_identity_id,
                },
            )
        })
        .collect())
}

async fn load_command_targets(
    pool: &PgPool,
    ids: &[Uuid],
) -> ApiResult<HashMap<Uuid, CommandTargetInfo>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String, Value)> = sqlx::query_as(
        "SELECT id, command_name, params FROM command_queue WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, command_name, params)| {
            (
                id,
                CommandTargetInfo {
                    command_name,
                    params,
                },
            )
        })
        .collect())
}

pub async fn list_events(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> ApiResult<crate::pagination::PaginatedResponse<AuditEventListItem>> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM audit_events")
        .fetch_one(pool)
        .await?;

    let rows: Vec<AuditEventRow> = sqlx::query_as(
        "SELECT id, actor, action, target, created_at
         FROM audit_events
         ORDER BY created_at DESC, id DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    let mut by_entity: HashMap<TargetEntity, HashSet<Uuid>> = HashMap::new();
    let mut actor_ids: HashSet<Uuid> = HashSet::new();
    let mut operator_logins: HashSet<String> = HashSet::new();
    for row in &rows {
        if let Ok(id) = Uuid::parse_str(&row.actor) {
            actor_ids.insert(id);
        } else if row.actor != "agent" {
            operator_logins.insert(row.actor.clone());
        }
        if row.target.is_empty() {
            continue;
        }
        let Some(entity) = target_entity(&row.action) else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(&row.target) else {
            continue;
        };
        by_entity.entry(entity).or_default().insert(id);
    }

    let mut name_maps: HashMap<TargetEntity, HashMap<Uuid, String>> = HashMap::new();
    let mut command_targets: HashMap<Uuid, CommandTargetInfo> = HashMap::new();
    let mut ai_api_key_targets: HashMap<Uuid, AiApiKeyInfo> = HashMap::new();
    for (entity, ids) in by_entity {
        let id_vec: Vec<Uuid> = ids.into_iter().collect();
        match entity {
            TargetEntity::Command => {
                command_targets = load_command_targets(pool, &id_vec).await?;
            }
            TargetEntity::AiApiKey => {
                ai_api_key_targets = load_ai_api_key_targets(pool, &id_vec).await?;
            }
            _ => {
                name_maps.insert(entity, load_target_names(pool, entity, &id_vec).await?);
            }
        }
    }

    let actor_id_vec: Vec<Uuid> = actor_ids.into_iter().collect();
    let actor_names = load_target_names(pool, TargetEntity::AiIdentity, &actor_id_vec).await?;
    let operator_login_vec: Vec<String> = operator_logins.into_iter().collect();
    let operator_ids_by_login = load_operator_ids_by_login(pool, &operator_login_vec).await?;

    let items = rows
        .into_iter()
        .map(|row| {
            let target = if row.target.is_empty() {
                None
            } else if let Some(entity) = target_entity(&row.action) {
                if let Ok(id) = Uuid::parse_str(&row.target) {
                    if entity == TargetEntity::Command {
                        if let Some(info) = command_targets.get(&id) {
                            Some(format_command_target_ref(id, info))
                        } else {
                            Some(AuditEventRef {
                                label: id.to_string(),
                                id: Some(id.to_string()),
                                kind: Some(AuditRefKind::Command),
                                related_id: None,
                                detail: None,
                            })
                        }
                    } else if entity == TargetEntity::AiApiKey {
                        Some(format_entity_target_ref(
                            entity,
                            id,
                            None,
                            ai_api_key_targets.get(&id),
                        ))
                    } else {
                        let name = name_maps
                            .get(&entity)
                            .and_then(|map| map.get(&id))
                            .cloned();
                        Some(format_entity_target_ref(entity, id, name, None))
                    }
                } else {
                    Some(AuditEventRef {
                        label: row.target.clone(),
                        id: None,
                        kind: None,
                        related_id: None,
                        detail: None,
                    })
                }
            } else {
                Some(AuditEventRef {
                    label: row.target.clone(),
                    id: None,
                    kind: None,
                    related_id: None,
                    detail: None,
                })
            };

            AuditEventListItem {
                id: row.id.to_string(),
                actor: format_actor_ref(&row.actor, &actor_names, &operator_ids_by_login),
                action: row.action,
                target,
                created_at: row.created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(crate::pagination::PaginatedResponse {
        items,
        total,
        limit,
        offset,
    })
}

pub async fn append_audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    target: &str,
    ip: &str,
    payload: &serde_json::Value,
) -> ApiResult<()> {
    let payload_hash = sha256_hex(payload.to_string().as_bytes());
    let ts = Utc::now().to_rfc3339();
    let prev: Option<String> = sqlx::query_scalar(
        "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    let prev_hash = prev.unwrap_or_default();
    let entry_hash = audit_entry_hash(&prev_hash, actor, action, target, &payload_hash, &ts);
    sqlx::query(
        "INSERT INTO audit_events (prev_hash, entry_hash, actor, action, target, ip, payload_hash, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now())",
    )
    .bind(&prev_hash)
    .bind(&entry_hash)
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(ip)
    .bind(&payload_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn count_active_admins(pool: &PgPool) -> ApiResult<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM operators WHERE role = 'admin' AND disabled_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn ensure_not_last_admin(pool: &PgPool, operator_id: Uuid) -> ApiResult<()> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role::text FROM operators WHERE id = $1 AND disabled_at IS NULL",
    )
    .bind(operator_id)
    .fetch_optional(pool)
    .await?;
    if role.as_deref() == Some("admin") && count_active_admins(pool).await? <= 1 {
        return Err(crate::error::ApiError::Conflict(
            "last_admin_protected".into(),
        ));
    }
    Ok(())
}

pub fn verify_chain(events: &[(String, String)]) -> bool {
    let mut prev = String::new();
    for (prev_hash, entry_hash) in events {
        if prev_hash != &prev {
            return false;
        }
        prev = entry_hash.clone();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_links() {
        let h1 = audit_entry_hash("", "op", "login", "", "", "t1");
        let h2 = audit_entry_hash(&h1, "op", "logout", "", "", "t2");
        assert!(verify_chain(&[(String::new(), h1.clone()), (h1, h2)]));
    }

    #[test]
    fn target_entity_mapping() {
        assert_eq!(target_entity("machine.delete"), Some(TargetEntity::Machine));
        assert_eq!(target_entity("agent.approve"), Some(TargetEntity::Machine));
        assert_eq!(target_entity("operator.create"), Some(TargetEntity::Operator));
        assert_eq!(target_entity("auth.bootstrap"), Some(TargetEntity::Operator));
        assert_eq!(
            target_entity("ai_identity.create"),
            Some(TargetEntity::AiIdentity)
        );
        assert_eq!(
            target_entity("ai_api_key.revoke"),
            Some(TargetEntity::AiApiKey)
        );
        assert_eq!(
            target_entity("command.enqueue"),
            Some(TargetEntity::Command)
        );
        assert_eq!(
            target_entity("command.approve"),
            Some(TargetEntity::Command)
        );
        assert_eq!(
            target_entity("command.cancel"),
            Some(TargetEntity::Command)
        );
        assert_eq!(target_entity("backup.export"), None);
    }

    #[test]
    fn format_actor_ref_resolves_ai_identity() {
        let mut ai_names = HashMap::new();
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        ai_names.insert(id, "Cursor".into());
        let actor = format_actor_ref(&id.to_string(), &ai_names, &HashMap::new());
        assert_eq!(actor.label, "Cursor");
        assert_eq!(actor.id.as_deref(), Some(id.to_string().as_str()));
        assert_eq!(actor.kind, Some(AuditRefKind::AiIdentity));
    }

    #[test]
    fn format_actor_ref_resolves_operator_login() {
        let mut operator_logins = HashMap::new();
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();
        operator_logins.insert("admin".into(), id);
        let actor = format_actor_ref("admin", &HashMap::new(), &operator_logins);
        assert_eq!(actor.label, "admin");
        assert_eq!(actor.id.as_deref(), Some(id.to_string().as_str()));
        assert_eq!(actor.kind, Some(AuditRefKind::Operator));
    }

    #[test]
    fn format_command_target_ref_splits_name_and_params() {
        let params = serde_json::json!({"argv": ["/usr/bin/true"]});
        let info = CommandTargetInfo {
            command_name: "shell.run".into(),
            params,
        };
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = format_command_target_ref(id, &info);
        assert_eq!(target.label, "shell.run");
        assert_eq!(
            target.detail.as_deref(),
            Some(r#"{"argv":["/usr/bin/true"]}"#)
        );
    }

    #[test]
    fn format_command_target_ref_omits_empty_params() {
        let info = CommandTargetInfo {
            command_name: "system.info".into(),
            params: serde_json::json!({}),
        };
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = format_command_target_ref(id, &info);
        assert_eq!(target.label, "system.info");
        assert!(target.detail.is_none());
    }
}
