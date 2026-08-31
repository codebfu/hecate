//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use hecate_protocol::backup::BackupSectionMeta;
use rand::RngCore;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::admin_auth;
use crate::audit::{append_audit, list_events, AuditEventListItem};
use crate::authz::store;
use crate::backup::{
    export_sections, exportable_sections, preview_sections, restore_sections,
    upgrade_backup,
};
use crate::backup_crypto::{decrypt_backup, encrypt_backup, parse_encrypted_envelope, validate_backup_password};
use crate::command_dispatch::enqueue_agent_update;
use crate::command_queue;
use crate::crypto::hmac_sha256_hex;
use crate::error::{ApiError, ApiResult};
use crate::machines::{self, MachineRow};
use crate::pagination::{self, CommandListQuery, ListQuery, PaginatedResponse};
use crate::permission_requests::{self, PermissionRequestListQuery};
use crate::feature_repo::releases as feature_releases;
use crate::server_settings::{self, UpdateAdminSettingsBody};
use crate::server_update;
use crate::state::AppState;
use crate::updates;
use axum_extra::extract::cookie::CookieJar;

#[derive(Deserialize)]
struct ExportBody {
    sections: Vec<String>,
    password: String,
}

#[derive(Deserialize)]
struct BackupPasswordBody {
    password: String,
    encrypted_backup: serde_json::Value,
}

#[derive(Deserialize)]
struct RestoreBody {
    sections: Vec<String>,
    password: String,
    encrypted_backup: serde_json::Value,
}

#[derive(Deserialize)]
struct CreateOperatorBody {
    login: String,
    password: String,
    role: String,
}

#[derive(Deserialize)]
struct CreateAiIdentityBody {
    name: String,
    description: Option<String>,
}

#[derive(Deserialize, serde::Serialize)]
struct UpdateAiIdentityBody {
    name: Option<String>,
    description: Option<String>,
    active: Option<bool>,
}

#[derive(Deserialize)]
struct UpdateAgentBody {
    action: String,
}

#[derive(Deserialize)]
struct CreateEnrollmentTokenBody {
    bound_tags: Option<Vec<String>>,
    machine_id: Option<Uuid>,
    proxy_id: Option<Uuid>,
}

#[derive(Deserialize, serde::Serialize)]
struct EnrollmentSettingsResponse {
    auto_approve: bool,
}

#[derive(Deserialize)]
struct InstallHelperBody {
    component: String,
}

#[derive(Deserialize)]
struct UpdateEnrollmentSettingsBody {
    auto_approve: bool,
}

#[derive(Deserialize)]
struct AdminCommandBody {
    command_name: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Deserialize, Default)]
struct UpdateMachineTagsBody {
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    remove: Vec<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(super::authz::router())
        .route("/api/v1/admin/machines", get(list_machines))
        .route("/api/v1/admin/machines/{id}", get(get_machine))
        .route("/api/v1/admin/machines/{id}", delete(delete_machine))
        .route("/api/v1/admin/machines/{id}/tags", patch(update_machine_tags))
        .route("/api/v1/admin/machines/{id}/agent", patch(update_machine_agent))
        .route("/api/v1/admin/machines/{id}/update-agent", post(request_machine_agent_update))
        .route("/api/v1/admin/machines/{id}/install-helper", post(request_machine_helper_install))
        .route("/api/v1/admin/machines/update-agents", post(request_all_agent_updates))
        .route("/api/v1/admin/releases/latest", get(list_latest_agent_releases))
        .route("/api/v1/admin/system/update-status", get(get_system_update_status))
        .route("/api/v1/admin/system/update", post(request_system_update))
        .route("/api/v1/admin/command-definitions", get(list_command_definitions))
        .route("/api/v1/admin/commands", get(list_commands))
        .route("/api/v1/admin/commands/{id}/approve", post(approve_command))
        .route("/api/v1/admin/commands/{id}/cancel", post(cancel_command))
        .route(
            "/api/v1/admin/permission-requests",
            get(list_permission_requests),
        )
        .route(
            "/api/v1/admin/permission-requests/{id}/approve",
            post(approve_permission_request),
        )
        .route(
            "/api/v1/admin/permission-requests/{id}/reject",
            post(reject_permission_request),
        )
        .route(
            "/api/v1/admin/enrollment/settings",
            get(get_enrollment_settings).patch(update_enrollment_settings),
        )
        .route(
            "/api/v1/admin/settings",
            get(get_admin_settings).patch(update_admin_settings),
        )
        .route(
            "/api/v1/admin/settings/rotate-task-signing",
            post(rotate_task_signing),
        )
        .route(
            "/api/v1/admin/settings/request-credential-rotation",
            post(request_credential_rotation),
        )
        .route("/api/v1/admin/repo/commands", post(execute_repo_command))
        .route("/api/v1/admin/enrollment-tokens", post(create_enrollment_token))
        .route("/api/v1/admin/proxies", get(list_proxies))
        .route(
            "/api/v1/admin/proxies/{id}",
            get(get_proxy).delete(delete_proxy),
        )
        .route(
            "/api/v1/admin/proxies/{id}/state",
            patch(update_proxy_state),
        )
        .route(
            "/api/v1/admin/proxy-enrollment/settings",
            get(get_proxy_enrollment_settings).patch(update_proxy_enrollment_settings),
        )
        .route(
            "/api/v1/admin/proxy-enrollment-tokens",
            post(create_proxy_enrollment_token),
        )
        .route(
            "/api/v1/admin/ai-identities",
            get(list_ai_identities).post(create_ai_identity),
        )
        .route(
            "/api/v1/admin/ai-identities/{id}",
            patch(update_ai_identity),
        )
        .route(
            "/api/v1/admin/ai-identities/{id}",
            delete(delete_ai_identity),
        )
        .route(
            "/api/v1/admin/ai-identities/{id}/content-policy/unlock",
            post(unlock_ai_content_policy),
        )
        .route(
            "/api/v1/admin/ai-identities/{id}/api-keys",
            get(list_ai_api_keys).post(create_ai_api_key),
        )
        .route(
            "/api/v1/admin/ai-identities/{id}/api-keys/{key_id}",
            delete(revoke_ai_api_key),
        )
        .route("/api/v1/admin/audit/events", get(list_audit_events))
        .route("/api/v1/admin/operators", get(list_operators).post(create_operator))
        .route("/api/v1/admin/operators/{id}", patch(update_operator))
        .route("/api/v1/admin/backup/sections", get(backup_sections))
        .route("/api/v1/admin/backup/export", post(backup_export))
        .route("/api/v1/admin/backup/preview", post(backup_preview))
        .route("/api/v1/admin/backup/restore", post(backup_restore))
}

async fn execute_repo_command(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<AdminCommandBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let ctx = admin_auth::require_admin(&state, &jar, &headers).await?;
    if !body.command_name.starts_with("admin.repo.") {
        return Err(ApiError::BadRequest("only admin.repo commands are accepted".into()));
    }
    let result = crate::admin_commands::execute_repo_command(
        &state.pool,
        &state.config,
        &ctx.session.operator_id.to_string(),
        &body.command_name,
        body.params,
    )
    .await?;
    Ok(Json(serde_json::json!({
        "command_name": body.command_name,
        "result": result,
    })))
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct MachineListRow {
    #[sqlx(flatten)]
    row: MachineRow,
    agent_state: Option<String>,
}

async fn list_machines(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    let ctx = admin_auth::require_operator(&state, &jar).await?;
    let include_updates = ctx.session.role == "admin";
    let rows: Vec<MachineListRow> = sqlx::query_as(
        "SELECT m.id, m.hostname, m.os, m.arch, m.tags, m.operator_tags, m.agent_version,
                m.desktop_version, m.proxmox_version, m.last_seen_at, m.agent_healthy,
                m.agent_secs_since_last_pull, m.agent_current_command_id,
                a.state::text AS agent_state
         FROM machines m
         LEFT JOIN agents a ON a.machine_id = m.id
         WHERE m.deleted_at IS NULL
         ORDER BY m.hostname",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut machines = Vec::with_capacity(rows.len());
    for entry in rows {
        let agent_state = entry.agent_state.as_deref();
        machines.push(
            machine_json_with_updates(
                &state.pool,
                &entry.row,
                agent_state,
                Some(serde_json::json!({ "agent_state": agent_state })),
                include_updates,
            )
            .await?,
        );
    }
    Ok(Json(machines))
}

async fn get_machine(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let ctx = admin_auth::require_operator(&state, &jar).await?;
    let include_updates = ctx.session.role == "admin";
    let machine_row = machines::load_machine_row(&state.pool, id).await?;
    let attestation_json: serde_json::Value = sqlx::query_scalar(
        "SELECT attestation_json FROM machines WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    let agent_meta: Option<(Option<String>, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT a.state::text, a.enrolled_at, a.revoked_at FROM agents a WHERE a.machine_id = $1",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;

    let (agent_state, enrolled_at, revoked_at) = agent_meta
        .map(|(state, enrolled, revoked)| (state, enrolled, revoked))
        .unwrap_or((None, None, None));

    let extra = serde_json::json!({
        "attestation_json": attestation_json,
        "agent_state": agent_state,
        "enrolled_at": enrolled_at,
        "revoked_at": revoked_at,
    });
    Ok(Json(
        machine_json_with_updates(
            &state.pool,
            &machine_row,
            agent_state.as_deref(),
            Some(extra),
            include_updates,
        )
        .await?,
    ))
}

async fn delete_machine(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;

    // Soft-delete machine: hide from UI/API, revoke agent, cancel queued work, and remove explicit
    // machine_id references from AI permission rules.
    let updated = sqlx::query(
        "UPDATE machines SET deleted_at = now(), status = 'offline'
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    sqlx::query("UPDATE agents SET state = 'revoked', revoked_at = now() WHERE machine_id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    sqlx::query(
        "UPDATE command_queue
         SET status = 'cancelled',
             cancel_requested_at = now(),
             finished_at = COALESCE(finished_at, now()),
             reboot_phase = NULL
         WHERE machine_id = $1
           AND status IN ('pending_approval', 'queued', 'dispatched', 'running')",
    )
    .bind(id)
    .execute(&state.pool)
    .await?;

    crate::authz::remove_machine_from_fleet_scopes(&state.pool, id).await?;

    append_audit(
        &state.pool,
        &admin.session.login,
        "machine.delete",
        &id.to_string(),
        "",
        &serde_json::json!({ "machine_id": id }),
    )
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn update_machine_tags(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateMachineTagsBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    if body.add.is_empty() && body.remove.is_empty() {
        return Err(ApiError::BadRequest("add or remove required".into()));
    }

    hecate_protocol::machine_tags::validate_custom_tags(&body.add)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let machine_row = machines::load_machine_row(&state.pool, id).await?;
    let next_operator_tags =
        machines::apply_operator_tag_patch(&machine_row.operator_tags, &body.add, &body.remove)?;
    machines::effective_tags(&machine_row.tags, &next_operator_tags)?;

    sqlx::query("UPDATE machines SET operator_tags = $1 WHERE id = $2")
        .bind(&next_operator_tags)
        .bind(id)
        .execute(&state.pool)
        .await?;

    append_audit(
        &state.pool,
        &admin.session.login,
        "machine.tags.update",
        &id.to_string(),
        "",
        &serde_json::json!({
            "add": body.add,
            "remove": body.remove,
            "operator_tags": next_operator_tags,
        }),
    )
    .await?;

    let updated = machines::load_machine_row(&state.pool, id).await?;
    let agent_state = machines::load_agent_state(&state.pool, id).await?;
    Ok(Json(machines::machine_row_to_json(
        &updated,
        agent_state.as_deref(),
        None,
    )?))
}

async fn list_command_definitions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<crate::command_definitions::CommandDefinitionSummary>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(
        crate::command_definitions::list_command_definitions(&state.pool).await?,
    ))
}

async fn list_commands(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<CommandListQuery>,
) -> ApiResult<Json<PaginatedResponse<serde_json::Value>>> {
    admin_auth::require_operator(&state, &jar).await?;
    Ok(Json(command_queue::list_active_commands(&state.pool, &query).await?))
}

async fn approve_command(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let operator = admin_auth::require_operator_write(&state, &jar, &headers).await?;
    command_queue::approve_pending_command(&state.pool, id, &operator.session.login, None).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn cancel_command(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    command_queue::cancel_queued_command(&state.pool, id, &admin.session.login, true).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
struct RejectPermissionRequestBody {
    reason: Option<String>,
}

async fn list_permission_requests(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<PermissionRequestListQuery>,
) -> ApiResult<Json<PaginatedResponse<hecate_protocol::permission_request::PermissionRequestDetail>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(permission_requests::list_requests(&state.pool, &query).await?))
}

async fn approve_permission_request(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    permission_requests::approve_request(&state.pool, id, &admin.session.login, None).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn reject_permission_request(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<RejectPermissionRequestBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    permission_requests::reject_request(
        &state.pool,
        id,
        &admin.session.login,
        body.reason,
        None,
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn update_machine_agent(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateAgentBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    match body.action.as_str() {
        "approve" => {
            sqlx::query("UPDATE agents SET state = 'active' WHERE machine_id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
            sqlx::query("UPDATE machines SET status = 'offline' WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
        }
        "revoke" => {
            sqlx::query("UPDATE agents SET state = 'revoked', revoked_at = now() WHERE machine_id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
            sqlx::query("UPDATE machines SET status = 'offline' WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
        }
        _ => return Err(ApiError::BadRequest("action must be approve or revoke".into())),
    }
    let audit_action = format!("agent.{}", body.action);
    append_audit(
        &state.pool,
        &admin.session.login,
        &audit_action,
        &id.to_string(),
        "",
        &serde_json::json!({ "machine_id": id, "action": body.action }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn machine_json_with_updates(
    pool: &PgPool,
    row: &MachineRow,
    agent_state: Option<&str>,
    extra: Option<serde_json::Value>,
    include_updates: bool,
) -> ApiResult<serde_json::Value> {
    let merged_extra = if include_updates {
        let update_extra = updates::machine_update_extra(
            pool,
            row.id,
            &row.os,
            &row.arch,
            agent_state,
            row.agent_version.as_deref(),
            row.desktop_version.as_deref(),
            row.proxmox_version.as_deref(),
        )
        .await?;
        match extra {
            Some(mut base) => {
                if let (Some(obj), Some(update_obj)) = (base.as_object_mut(), update_extra.as_object())
                {
                    for (key, value) in update_obj {
                        obj.insert(key.clone(), value.clone());
                    }
                }
                base
            }
            None => update_extra,
        }
    } else {
        extra.unwrap_or_else(|| serde_json::json!({}))
    };
    machines::machine_row_to_json(row, agent_state, Some(merged_extra))
}

async fn request_machine_agent_update(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let machine = machines::load_machine_row(&state.pool, id).await?;
    let agent_state = machines::load_agent_state(&state.pool, id).await?;
    if agent_state.as_deref() != Some("active") {
        return Err(ApiError::BadRequest("agent is not active".into()));
    }
    if updates::has_other_active_commands(&state.pool, id).await? {
        return Err(ApiError::Conflict(
            "machine is busy with commands".into(),
        ));
    }
    if updates::has_pending_agent_update(&state.pool, id).await? {
        return Err(ApiError::Conflict("agent update is already queued".into()));
    }
    let latest_agent =
        updates::latest_component_release_version(&state.pool, &machine.os, &machine.arch, "agent")
            .await?;
    let latest_desktop = updates::latest_component_release_version(
        &state.pool,
        &machine.os,
        &machine.arch,
        "desktop",
    )
    .await?;
    let latest_proxmox = updates::latest_component_release_version(
        &state.pool,
        &machine.os,
        &machine.arch,
        "proxmox",
    )
    .await?;
    let current_agent = machine.agent_version.as_deref();
    let current_desktop = machine.desktop_version.as_deref();
    let current_proxmox = machine.proxmox_version.as_deref();
    let agent_outdated = updates::component_is_outdated(current_agent, latest_agent.as_deref());
    let desktop_outdated =
        updates::component_is_outdated(current_desktop, latest_desktop.as_deref());
    let proxmox_outdated =
        updates::component_is_outdated(current_proxmox, latest_proxmox.as_deref());
    if !agent_outdated && !desktop_outdated && !proxmox_outdated {
        return Err(ApiError::BadRequest(
            "agent and all helpers are already up to date".into(),
        ));
    }

    let command_id = enqueue_agent_update(&state.pool, id, None).await?;

    append_audit(
        &state.pool,
        &admin.session.login,
        "command.enqueue",
        &command_id.to_string(),
        "",
        &serde_json::json!({
            "machine_id": id,
            "command_name": "agent.update",
            "source": "admin",
            "current_agent_version": current_agent,
            "target_agent_version": latest_agent,
            "current_desktop_version": current_desktop,
            "target_desktop_version": latest_desktop,
            "current_proxmox_version": current_proxmox,
            "target_proxmox_version": latest_proxmox,
            "agent_outdated": agent_outdated,
            "desktop_outdated": desktop_outdated,
            "proxmox_outdated": proxmox_outdated,
        }),
    )
    .await?;

    let updated = machines::load_machine_row(&state.pool, id).await?;
    Ok(Json(
        machine_json_with_updates(
            &state.pool,
            &updated,
            agent_state.as_deref(),
            None,
            true,
        )
        .await?,
    ))
}

async fn request_machine_helper_install(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<InstallHelperBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let component = crate::helper_install::parse_helper_component(&serde_json::json!({
        "component": body.component
    }))?;
    let command_id =
        crate::helper_install::enqueue_helper_install(&state.pool, id, None, &component).await?;
    let agent_state = machines::load_agent_state(&state.pool, id).await?;

    append_audit(
        &state.pool,
        &admin.session.login,
        "command.enqueue",
        &command_id.to_string(),
        "",
        &serde_json::json!({
            "machine_id": id,
            "command_name": crate::helper_install::COMMAND_NAME,
            "source": "admin",
            "component": component,
        }),
    )
    .await?;

    let updated = machines::load_machine_row(&state.pool, id).await?;
    Ok(Json(
        machine_json_with_updates(
            &state.pool,
            &updated,
            agent_state.as_deref(),
            None,
            true,
        )
        .await?,
    ))
}

async fn request_all_agent_updates(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let rows: Vec<MachineListRow> = sqlx::query_as(
        "SELECT m.id, m.hostname, m.os, m.arch, m.tags, m.operator_tags, m.agent_version,
                m.desktop_version, m.proxmox_version, m.last_seen_at, m.agent_healthy,
                m.agent_secs_since_last_pull, m.agent_current_command_id,
                a.state::text AS agent_state
         FROM machines m
         JOIN agents a ON a.machine_id = m.id
         WHERE m.deleted_at IS NULL AND a.state = 'active'",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut requested = 0usize;
    let mut skipped_busy = 0usize;
    let mut skipped_up_to_date = 0usize;
    let mut skipped_already_queued = 0usize;

    for entry in rows {
        let latest_agent = updates::latest_component_release_version(
            &state.pool,
            &entry.row.os,
            &entry.row.arch,
            "agent",
        )
        .await?;
        let latest_desktop = updates::latest_component_release_version(
            &state.pool,
            &entry.row.os,
            &entry.row.arch,
            "desktop",
        )
        .await?;
        let latest_proxmox = updates::latest_component_release_version(
            &state.pool,
            &entry.row.os,
            &entry.row.arch,
            "proxmox",
        )
        .await?;
        let agent_outdated = updates::component_is_outdated(
            entry.row.agent_version.as_deref(),
            latest_agent.as_deref(),
        );
        let desktop_outdated = updates::component_is_outdated(
            entry.row.desktop_version.as_deref(),
            latest_desktop.as_deref(),
        );
        let proxmox_outdated = updates::component_is_outdated(
            entry.row.proxmox_version.as_deref(),
            latest_proxmox.as_deref(),
        );
        if !agent_outdated && !desktop_outdated && !proxmox_outdated {
            skipped_up_to_date += 1;
            continue;
        }
        if updates::has_pending_agent_update(&state.pool, entry.row.id).await? {
            skipped_already_queued += 1;
            continue;
        }
        if updates::has_other_active_commands(&state.pool, entry.row.id).await? {
            skipped_busy += 1;
            continue;
        }
        let command_id = enqueue_agent_update(&state.pool, entry.row.id, None).await?;
        append_audit(
            &state.pool,
            &admin.session.login,
            "command.enqueue",
            &command_id.to_string(),
            "",
            &serde_json::json!({
                "machine_id": entry.row.id,
                "command_name": "agent.update",
                "source": "admin",
                "current_agent_version": entry.row.agent_version,
                "target_agent_version": latest_agent,
                "current_desktop_version": entry.row.desktop_version,
                "target_desktop_version": latest_desktop,
                "current_proxmox_version": entry.row.proxmox_version,
                "target_proxmox_version": latest_proxmox,
                "agent_outdated": agent_outdated,
                "desktop_outdated": desktop_outdated,
                "proxmox_outdated": proxmox_outdated,
            }),
        )
        .await?;
        requested += 1;
    }

    append_audit(
        &state.pool,
        &admin.session.login,
        "agent.update_all_requested",
        "",
        "",
        &serde_json::json!({
            "requested": requested,
            "skipped_busy": skipped_busy,
            "skipped_up_to_date": skipped_up_to_date,
            "skipped_already_queued": skipped_already_queued,
        }),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "requested": requested,
        "skipped_busy": skipped_busy,
        "skipped_up_to_date": skipped_up_to_date,
        "skipped_already_queued": skipped_already_queued,
    })))
}

async fn list_latest_agent_releases(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(feature_releases::list_latest_releases(&state.pool).await?))
}

async fn get_system_update_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<serde_json::Value>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    let status = server_update::get_server_update_status(&state.pool, &state.config).await?;
    Ok(Json(serde_json::json!({
        "hecate_version": status.hecate_version,
        "hecate_app_tag": status.hecate_app_tag,
        "update_requested": status.update_requested,
        "update_requested_at": status.update_requested_at,
        "fleet_busy": status.fleet_busy,
        "can_apply": status.can_apply,
    })))
}

async fn request_system_update(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    server_update::request_server_update(&state.pool).await?;
    let applied = server_update::try_apply_server_update(&state.pool, &state.config).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "server.update_requested",
        "",
        "",
        &serde_json::json!({ "applied": applied }),
    )
    .await?;
    let status = server_update::get_server_update_status(&state.pool, &state.config).await?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "update_requested": status.update_requested,
        "fleet_busy": status.fleet_busy,
        "can_apply": status.can_apply,
        "applied": applied,
    })))
}

async fn get_enrollment_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<EnrollmentSettingsResponse>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    let auto_approve = server_settings::enrollment_auto_approve(&state.pool).await?;
    Ok(Json(EnrollmentSettingsResponse { auto_approve }))
}

async fn get_admin_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<server_settings::AdminSettingsView>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(
        server_settings::get_admin_settings(&state.pool, &state.config).await?,
    ))
}

async fn update_admin_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<UpdateAdminSettingsBody>,
) -> ApiResult<Json<server_settings::AdminSettingsView>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let previous_release = server_settings::resolve_release_signing_public_key_b64(
        &state.pool,
        &state.config,
    )
    .await?;
    let updated =
        server_settings::update_admin_settings(&state.pool, &state.config, &body).await?;
    if let Some(new_key) = body.release_signing_public_key_b64.as_ref() {
        if new_key.trim() != previous_release.trim() {
            append_audit(
                &state.pool,
                &admin.session.login,
                "settings.release_key_rotated",
                "",
                "",
                &serde_json::json!({
                    "has_previous": updated.release_signing_public_key_previous_b64.is_some(),
                    "overlap_until": updated.release_signing_key_overlap_until,
                }),
            )
            .await?;
        }
    }
    append_audit(
        &state.pool,
        &admin.session.login,
        "settings.updated",
        "",
        "",
        &serde_json::json!({
            "enrollment_auto_approve": updated.enrollment_auto_approve,
            "enrollment_token_ttl_minutes": updated.enrollment_token_ttl_minutes,
            "proxy_enrollment_token_ttl_minutes": updated.proxy_enrollment_token_ttl_minutes,
            "key_rotation_overlap_secs": updated.key_rotation_overlap_secs,
            "key_rotation_interval_secs": updated.key_rotation_interval_secs,
        }),
    )
    .await?;
    Ok(Json(updated))
}

async fn rotate_task_signing(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<crate::key_rotation::RotateKeysBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let count = if let Some(machine_id) = body.machine_id {
        crate::key_rotation::rotate_task_signing_for_agent(&state.pool, machine_id).await?;
        1u64
    } else {
        crate::key_rotation::rotate_task_signing_all(&state.pool).await?
    };
    append_audit(
        &state.pool,
        &admin.session.login,
        "settings.keys_rotated",
        "",
        "",
        &serde_json::json!({
            "source": "admin",
            "kind": "task_signing",
            "machine_id": body.machine_id,
            "agents": count,
        }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true, "agents": count })))
}

async fn request_credential_rotation(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<crate::key_rotation::RotateKeysBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let count = if let Some(machine_id) = body.machine_id {
        crate::key_rotation::request_credential_rotation_for_agent(&state.pool, machine_id)
            .await?;
        1u64
    } else {
        crate::key_rotation::request_credential_rotation_all(&state.pool).await?
    };
    append_audit(
        &state.pool,
        &admin.session.login,
        "settings.keys_rotated",
        "",
        "",
        &serde_json::json!({
            "source": "admin",
            "kind": "credential",
            "machine_id": body.machine_id,
            "agents": count,
        }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true, "agents": count })))
}

async fn update_enrollment_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<UpdateEnrollmentSettingsBody>,
) -> ApiResult<Json<EnrollmentSettingsResponse>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    crate::server_settings::set_enrollment_auto_approve(&state.pool, body.auto_approve).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "enrollment_settings.update",
        "enrollment_auto_approve",
        "",
        &serde_json::json!({ "auto_approve": body.auto_approve }),
    )
    .await?;
    Ok(Json(EnrollmentSettingsResponse {
        auto_approve: body.auto_approve,
    }))
}

async fn create_enrollment_token(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<CreateEnrollmentTokenBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    if let Some(machine_id) = body.machine_id {
        let agent_state: Option<String> = sqlx::query_scalar(
            "SELECT a.state::text
             FROM agents a
             INNER JOIN machines m ON m.id = a.machine_id
             WHERE a.machine_id = $1 AND m.deleted_at IS NULL",
        )
        .bind(machine_id)
        .fetch_optional(&state.pool)
        .await?;
        let Some(state_text) = agent_state else {
            return Err(ApiError::NotFound);
        };
        if state_text == "revoked" {
            return Err(ApiError::BadRequest(
                "cannot create re-enrollment token for a revoked agent".into(),
            ));
        }
    }
    let ttl_minutes = server_settings::enrollment_token_ttl_minutes(&state.pool).await?;
    let mut raw = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = format!("enr_{}", hex::encode(raw));
    let token_hmac = hmac_sha256_hex(&state.config.api_key_pepper, &token);
    let expires_at = Utc::now() + Duration::minutes(ttl_minutes as i64);
    let bound_tags = body.bound_tags.unwrap_or_default();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO enrollment_tokens (id, token_hmac, expires_at, bound_tags, bound_machine_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&token_hmac)
    .bind(expires_at)
    .bind(&bound_tags)
    .bind(body.machine_id)
    .execute(&state.pool)
    .await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "enrollment_token.create",
        &id.to_string(),
        "",
        &serde_json::json!({
            "expires_at": expires_at,
            "ttl_minutes": ttl_minutes,
            "bound_tags": bound_tags,
            "bound_machine_id": body.machine_id,
        }),
    )
    .await?;
    Ok(Json(serde_json::json!({
        "id": id,
        "token": token,
        "expires_at": expires_at,
        "bound_tags": bound_tags,
        "bound_machine_id": body.machine_id,
    })))
}

async fn list_ai_identities(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    admin_auth::require_operator(&state, &jar).await?;
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT row_to_json(t) FROM (
            SELECT i.id, i.name, i.description, i.active, i.created_at,
                   COALESCE(c.violation_count, 0) AS content_policy_violation_count,
                   c.locked_until AS content_policy_locked_until,
                   (c.locked_until IS NOT NULL AND c.locked_until > now()) AS content_policy_locked
            FROM ai_identities i
            LEFT JOIN ai_content_policy_state c ON c.ai_identity_id = i.id
            WHERE i.deleted_at IS NULL
            ORDER BY i.name
         ) t",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn purge_soft_deleted_ai_identity_by_name(pool: &PgPool, name: &str) -> ApiResult<()> {
    let old_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ai_identities WHERE name = $1 AND deleted_at IS NOT NULL LIMIT 1",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    if let Some(id) = old_id {
        sqlx::query("UPDATE command_queue SET ai_identity_id = NULL WHERE ai_identity_id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM ai_identities WHERE id = $1 AND deleted_at IS NOT NULL")
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn ensure_ai_identity_name_available(
    pool: &PgPool,
    name: &str,
    except_id: Option<Uuid>,
) -> ApiResult<()> {
    purge_soft_deleted_ai_identity_by_name(pool, name).await?;

    let taken: bool = if let Some(id) = except_id {
        sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM ai_identities
                WHERE name = $1 AND deleted_at IS NULL AND id <> $2
             )",
        )
        .bind(name)
        .bind(id)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM ai_identities WHERE name = $1 AND deleted_at IS NULL
             )",
        )
        .bind(name)
        .fetch_one(pool)
        .await?
    };

    if taken {
        return Err(ApiError::Conflict("identity name already in use".into()));
    }
    Ok(())
}

async fn create_ai_identity(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<CreateAiIdentityBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name required".into()));
    }
    ensure_ai_identity_name_available(&state.pool, name, None).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ai_identities (id, name, description, active)
         VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(name)
    .bind(body.description.unwrap_or_default())
    .execute(&state.pool)
    .await?;
    store::ensure_bootstrap_assignment(&state.pool, id).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "ai_identity.create",
        &id.to_string(),
        "",
        &serde_json::json!({ "name": body.name }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "id": id })))
}

async fn update_ai_identity(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateAiIdentityBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ai_identities WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    if let Some(name) = &body.name {
        let name = name.trim();
        if name.is_empty() {
            return Err(ApiError::BadRequest("name required".into()));
        }
        ensure_ai_identity_name_available(&state.pool, name, Some(id)).await?;
        sqlx::query("UPDATE ai_identities SET name = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(name)
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    if let Some(description) = &body.description {
        sqlx::query("UPDATE ai_identities SET description = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(description)
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    if let Some(active) = body.active {
        sqlx::query("UPDATE ai_identities SET active = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(active)
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    append_audit(
        &state.pool,
        &admin.session.login,
        "ai_identity.update",
        &id.to_string(),
        "",
        &serde_json::to_value(&body).unwrap_or_default(),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_ai_identity(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;

    let updated = sqlx::query(
        "UPDATE ai_identities SET deleted_at = now(), active = false WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    sqlx::query("UPDATE ai_api_keys SET revoked_at = now() WHERE ai_identity_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&state.pool)
        .await?;

    append_audit(
        &state.pool,
        &admin.session.login,
        "ai_identity.delete",
        &id.to_string(),
        "",
        &serde_json::json!({ "ai_identity_id": id }),
    )
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn unlock_ai_content_policy(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let _admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ai_identities WHERE id = $1 AND deleted_at IS NULL)",
    )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    crate::content_policy::clear_lockout(&state.pool, id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_ai_api_keys(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT row_to_json(t) FROM (
            SELECT id, prefix, created_at, last_used_at, revoked_at,
                   (revoked_at IS NULL) AS active
            FROM ai_api_keys WHERE ai_identity_id = $1 ORDER BY created_at DESC
         ) t",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn create_ai_api_key(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ai_identities WHERE id = $1 AND deleted_at IS NULL)",
    )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let api_key = format!("hecate_{}", hex::encode(raw));
    let prefix: String = api_key.chars().take(16).collect();
    let key_hmac = hmac_sha256_hex(&state.config.api_key_pepper, &api_key);
    let key_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ai_api_keys (id, ai_identity_id, key_hmac, prefix) VALUES ($1, $2, $3, $4)",
    )
    .bind(key_id)
    .bind(id)
    .bind(&key_hmac)
    .bind(&prefix)
    .execute(&state.pool)
    .await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "ai_api_key.create",
        &key_id.to_string(),
        "",
        &serde_json::json!({ "ai_identity_id": id, "prefix": prefix }),
    )
    .await?;
    Ok(Json(serde_json::json!({
        "id": key_id,
        "api_key": api_key,
        "prefix": prefix,
    })))
}

async fn revoke_ai_api_key(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((identity_id, key_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let updated = sqlx::query(
        "UPDATE ai_api_keys SET revoked_at = now()
         WHERE id = $1 AND ai_identity_id = $2 AND revoked_at IS NULL",
    )
    .bind(key_id)
    .bind(identity_id)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    append_audit(
        &state.pool,
        &admin.session.login,
        "ai_api_key.revoke",
        &key_id.to_string(),
        "",
        &serde_json::json!({ "ai_identity_id": identity_id }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_audit_events(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<PaginatedResponse<AuditEventListItem>>> {
    admin_auth::require_operator(&state, &jar).await?;
    let (limit, offset) = pagination::resolve_list_pagination(query.limit, query.offset);
    Ok(Json(list_events(&state.pool, limit, offset).await?))
}

async fn list_operators(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT row_to_json(t) FROM (
            SELECT id, login, role, (disabled_at IS NULL) AS active, onboarding_complete
            FROM operators ORDER BY login
         ) t",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn create_operator(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<CreateOperatorBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    if body.role != "admin" && body.role != "operator" {
        return Err(ApiError::BadRequest("invalid role".into()));
    }
    let hash = crate::crypto::hash_password(&body.password).map_err(ApiError::Internal)?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO operators (id, login, password_hash, role, must_change_password, onboarding_complete, created_by_id)
         VALUES ($1, $2, $3, $4::operator_role, true, false, $5)",
    )
    .bind(id)
    .bind(&body.login)
    .bind(&hash)
    .bind(&body.role)
    .bind(admin.session.operator_id)
    .execute(&state.pool)
    .await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "operator.create",
        &id.to_string(),
        "",
        &serde_json::json!({ "login": body.login, "role": body.role }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "id": id })))
}

async fn update_operator(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let demoting_admin = body.get("role").and_then(|v| v.as_str()) == Some("operator");
    let disabling = body.get("active").and_then(|v| v.as_bool()) == Some(false)
        || (body.get("disabled_at").is_some() && !body.get("disabled_at").unwrap().is_null());
    if demoting_admin || disabling {
        crate::audit::ensure_not_last_admin(&state.pool, id).await?;
    }
    if let Some(role) = body.get("role").and_then(|v| v.as_str()) {
        if role != "admin" && role != "operator" {
            return Err(ApiError::BadRequest("invalid role".into()));
        }
        sqlx::query("UPDATE operators SET role = $1::operator_role WHERE id = $2")
            .bind(role)
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    if let Some(active) = body.get("active").and_then(|v| v.as_bool()) {
        if active {
            sqlx::query("UPDATE operators SET disabled_at = NULL WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
        } else {
            sqlx::query("UPDATE operators SET disabled_at = now() WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
        }
    } else if body.get("disabled_at").is_some() {
        if body.get("disabled_at").unwrap().is_null() {
            sqlx::query("UPDATE operators SET disabled_at = NULL WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
        } else {
            sqlx::query("UPDATE operators SET disabled_at = now() WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await?;
        }
    }
    append_audit(
        &state.pool,
        &admin.session.login,
        "operator.update",
        &id.to_string(),
        "",
        &body,
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn backup_sections(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<BackupSectionMeta>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(exportable_sections()))
}

async fn backup_export(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<ExportBody>,
) -> ApiResult<Json<hecate_protocol::backup::EncryptedBackupEnvelope>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    if body.sections.is_empty() {
        return Err(ApiError::BadRequest("sections required".into()));
    }
    validate_backup_password(&body.password)?;
    let manifest = export_sections(&state.pool, &body.sections).await?;
    let envelope = encrypt_backup(&manifest, &body.password)?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "backup.export",
        "",
        "",
        &serde_json::json!({ "sections": body.sections }),
    )
    .await?;
    Ok(Json(envelope))
}

async fn backup_preview(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<BackupPasswordBody>,
) -> ApiResult<Json<serde_json::Value>> {
    admin_auth::require_admin(&state, &jar, &headers).await?;
    let bytes = serde_json::to_vec(&body.encrypted_backup)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if body.encrypted_backup.get("format") == Some(&serde_json::json!(hecate_protocol::backup::BACKUP_FORMAT)) {
        return Err(ApiError::BadRequest(
            "plaintext JSON backups are no longer accepted; export a password-protected .hecate-backup file".into(),
        ));
    }
    let envelope = parse_encrypted_envelope(&bytes)?;
    let manifest = decrypt_backup(&envelope, &body.password)?;
    let sections: Vec<_> = preview_sections(&manifest)
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "label": s.label,
                "present": s.present,
                "restorable": s.restorable,
                "default_selected": s.default_selected,
                "warnings": s.warnings,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "backup_format_version": manifest.backup_format_version,
        "hecate_version": manifest.hecate_version,
        "schema_version_at_export": manifest.schema_version_at_export,
        "upgrade_required": manifest.backup_format_version < hecate_protocol::backup::BACKUP_FORMAT_VERSION_CURRENT,
        "sections": sections,
    })))
}

async fn backup_restore(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<RestoreBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    if body.sections.is_empty() {
        return Err(ApiError::BadRequest("sections required".into()));
    }
    let bytes = serde_json::to_vec(&body.encrypted_backup)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if body.encrypted_backup.get("format") == Some(&serde_json::json!(hecate_protocol::backup::BACKUP_FORMAT)) {
        return Err(ApiError::BadRequest(
            "plaintext JSON backups are no longer accepted; use a password-protected .hecate-backup file".into(),
        ));
    }
    let envelope = parse_encrypted_envelope(&bytes)?;
    let manifest = upgrade_backup(decrypt_backup(&envelope, &body.password)?)?;
    let restored = restore_sections(
        &state.pool,
        &body.sections,
        &manifest,
        &state.config.release_artifacts_dir,
    )
    .await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "backup.restore",
        "",
        "",
        &serde_json::json!({ "sections": restored, "from_version": manifest.backup_format_version }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true, "sections_restored": restored })))
}

fn proxy_json(
    id: Uuid,
    hostname: &str,
    state: &str,
    version: Option<&str>,
    enrolled_at: chrono::DateTime<Utc>,
    last_seen_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    attestation: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "id": id,
        "hostname": hostname,
        "state": state,
        "version": version,
        "enrolled_at": enrolled_at.to_rfc3339(),
        "last_seen_at": last_seen_at.map(|ts| ts.to_rfc3339()),
        "revoked_at": revoked_at.map(|ts| ts.to_rfc3339()),
    });
    if let Some(attestation) = attestation {
        value["attestation"] = attestation;
    }
    value
}

async fn list_proxies(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    admin_auth::require_operator(&state, &jar).await?;
    let rows: Vec<(
        Uuid,
        String,
        String,
        Option<String>,
        chrono::DateTime<Utc>,
        Option<chrono::DateTime<Utc>>,
        Option<chrono::DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT id, hostname, state::text, version, enrolled_at, last_seen_at, revoked_at
         FROM proxies
         ORDER BY enrolled_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, hostname, st, version, enrolled_at, last_seen_at, revoked_at)| {
                proxy_json(
                    id,
                    &hostname,
                    &st,
                    version.as_deref(),
                    enrolled_at,
                    last_seen_at,
                    revoked_at,
                    None,
                )
            })
            .collect(),
    ))
}

async fn get_proxy(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    admin_auth::require_operator(&state, &jar).await?;
    let row: Option<(
        Uuid,
        String,
        String,
        Option<String>,
        chrono::DateTime<Utc>,
        Option<chrono::DateTime<Utc>>,
        Option<chrono::DateTime<Utc>>,
        serde_json::Value,
    )> = sqlx::query_as(
        "SELECT id, hostname, state::text, version, enrolled_at, last_seen_at, revoked_at, attestation_json
         FROM proxies WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;

    let Some((id, hostname, st, version, enrolled_at, last_seen_at, revoked_at, attestation)) =
        row
    else {
        return Err(ApiError::NotFound);
    };

    Ok(Json(proxy_json(
        id,
        &hostname,
        &st,
        version.as_deref(),
        enrolled_at,
        last_seen_at,
        revoked_at,
        Some(attestation),
    )))
}

async fn update_proxy_state(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateAgentBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    match body.action.as_str() {
        "approve" => {
            let updated = sqlx::query(
                "UPDATE proxies SET state = 'active', revoked_at = NULL WHERE id = $1",
            )
            .bind(id)
            .execute(&state.pool)
            .await?;
            if updated.rows_affected() == 0 {
                return Err(ApiError::NotFound);
            }
        }
        "revoke" => {
            let updated = sqlx::query(
                "UPDATE proxies SET state = 'revoked', revoked_at = now() WHERE id = $1",
            )
            .bind(id)
            .execute(&state.pool)
            .await?;
            if updated.rows_affected() == 0 {
                return Err(ApiError::NotFound);
            }
        }
        _ => return Err(ApiError::BadRequest("action must be approve or revoke".into())),
    }
    append_audit(
        &state.pool,
        &admin.session.login,
        &format!("proxy.{}", body.action),
        &id.to_string(),
        "",
        &serde_json::json!({ "proxy_id": id, "action": body.action }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_proxy(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let updated = sqlx::query(
        "UPDATE proxies SET state = 'revoked', revoked_at = COALESCE(revoked_at, now()) WHERE id = $1",
    )
    .bind(id)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    append_audit(
        &state.pool,
        &admin.session.login,
        "proxy.delete",
        &id.to_string(),
        "",
        &serde_json::json!({ "proxy_id": id }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_proxy_enrollment_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<EnrollmentSettingsResponse>> {
    admin_auth::require_operator(&state, &jar).await?;
    let auto_approve =
        server_settings::proxy_enrollment_auto_approve(&state.pool).await?;
    Ok(Json(EnrollmentSettingsResponse { auto_approve }))
}

async fn update_proxy_enrollment_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<UpdateEnrollmentSettingsBody>,
) -> ApiResult<Json<EnrollmentSettingsResponse>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    server_settings::set_proxy_enrollment_auto_approve(&state.pool, body.auto_approve).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "proxy_enrollment_settings.update",
        "proxy_enrollment_auto_approve",
        "",
        &serde_json::json!({ "auto_approve": body.auto_approve }),
    )
    .await?;
    Ok(Json(EnrollmentSettingsResponse {
        auto_approve: body.auto_approve,
    }))
}

async fn create_proxy_enrollment_token(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<CreateEnrollmentTokenBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    if let Some(proxy_id) = body.proxy_id {
        let proxy_state: Option<String> =
            sqlx::query_scalar("SELECT state::text FROM proxies WHERE id = $1")
                .bind(proxy_id)
                .fetch_optional(&state.pool)
                .await?;
        let Some(state_text) = proxy_state else {
            return Err(ApiError::NotFound);
        };
        if state_text == "revoked" {
            return Err(ApiError::BadRequest(
                "cannot create re-enrollment token for a revoked proxy".into(),
            ));
        }
    }
    let ttl_minutes = server_settings::proxy_enrollment_token_ttl_minutes(&state.pool).await?;
    let mut raw = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = format!("penr_{}", hex::encode(raw));
    let token_hmac = hmac_sha256_hex(&state.config.api_key_pepper, &token);
    let expires_at = Utc::now() + Duration::minutes(ttl_minutes as i64);
    let bound_tags = body.bound_tags.unwrap_or_default();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO proxy_enrollment_tokens (id, token_hmac, expires_at, bound_tags, bound_proxy_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&token_hmac)
    .bind(expires_at)
    .bind(&bound_tags)
    .bind(body.proxy_id)
    .execute(&state.pool)
    .await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "proxy_enrollment_token.create",
        &id.to_string(),
        "",
        &serde_json::json!({
            "expires_at": expires_at,
            "ttl_minutes": ttl_minutes,
            "bound_tags": bound_tags,
            "bound_proxy_id": body.proxy_id,
        }),
    )
    .await?;
    Ok(Json(serde_json::json!({
        "id": id,
        "token": token,
        "expires_at": expires_at,
        "bound_tags": bound_tags,
        "bound_proxy_id": body.proxy_id,
    })))
}
