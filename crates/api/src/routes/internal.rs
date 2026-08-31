//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use hecate_protocol::command::{CommandDetail, CommandEnqueueResponse, CommandStatus};
use hecate_protocol::permissions::{
    AiContextAdminCapabilities, AiContextCapabilities, AiContextResponse,
};
use hecate_protocol::authz::{AuthzCatalogResponse, EffectiveRightsReport};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

use crate::admin_commands;
use crate::audit::append_audit;
use crate::command_artifacts;
use crate::desktop_sessions;
use crate::command_dispatch::AGENT_UPDATE_TIMEOUT_SECS;
use crate::error::{ApiError, ApiResult};
use crate::helper_install;
use crate::internal_auth::verify_internal_token;
use crate::machines::{self, MachineRow};
use crate::permissions;
use crate::proxmox_sessions;
use crate::server_settings;
use crate::state::AppState;
use crate::updates::{has_pending_system_reboot, is_machine_busy};

/// Default queue timeout for system.reboot (agent offline → online cycle).
const SYSTEM_REBOOT_TIMEOUT_SECS: i32 = 900;
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 30;
const MAX_WAIT_TIMEOUT_SECS: u64 = 300;
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Deserialize)]
struct EnqueueBody {
    machine_id: Uuid,
    command_name: String,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct ListQuery {
    machine_id: Option<Uuid>,
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Deserialize)]
struct GetCommandQuery {
    wait: Option<String>,
    wait_timeout_secs: Option<u64>,
}

#[derive(Serialize)]
struct ListCommandsResponse {
    commands: Vec<CommandDetail>,
}

#[derive(Deserialize)]
struct PlatformCommandBody {
    command_name: String,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct AdminCommandBody {
    command_name: String,
    params: serde_json::Value,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/internal/machines", get(list_machines))
        .route("/internal/machines/{id}", get(get_machine))
        .route("/internal/commands", post(enqueue_command).get(list_commands))
        .route("/internal/commands/{id}", get(get_command))
        .route("/internal/commands/{id}/artifact", get(download_command_artifact))
        .route("/internal/commands/{id}/cancel", post(cancel_command))
        .route("/internal/command-artifacts", post(upload_command_artifact))
        .route("/internal/platform-commands", post(execute_platform_command))
        .route("/internal/admin-commands", post(execute_admin_command))
        .route("/internal/ai-context", get(ai_context))
        .route("/internal/authz-catalog", get(authz_catalog))
        .route("/internal/effective-rights", get(effective_rights))
}

async fn execute_platform_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PlatformCommandBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    let result = admin_commands::execute_platform_command(
        &state.pool,
        identity_id,
        &body.command_name,
        body.params,
    )
    .await?;
    Ok(Json(serde_json::json!({
        "command_name": body.command_name,
        "result": result,
    })))
}

async fn execute_admin_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AdminCommandBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    let result = admin_commands::execute_admin_command(
        &state.pool,
        &state.config,
        identity_id,
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
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
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

    let mut machines = Vec::new();
    for entry in rows {
        if crate::authz::identity_can_access_machine(&state.pool, identity_id, entry.row.id)
            .await?
        {
            let extra = serde_json::json!({
                "installable_helpers": helper_install::installable_helpers_for_machine(
                    &state.pool,
                    entry.row.id,
                    &entry.row.os,
                    &entry.row.arch,
                    entry.agent_state.as_deref(),
                    entry.row.desktop_version.as_deref(),
                    entry.row.proxmox_version.as_deref(),
                )
                .await?,
            });
            machines.push(machines::machine_row_to_json(
                &entry.row,
                entry.agent_state.as_deref(),
                Some(extra),
            )?);
        }
    }
    Ok(Json(serde_json::json!({ "machines": machines })))
}

async fn get_machine(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    let row = machines::load_machine_row(&state.pool, id).await?;
    if !crate::authz::identity_can_access_machine(&state.pool, identity_id, id).await? {
        return Err(ApiError::Forbidden);
    }
    let agent_state = machines::load_agent_state(&state.pool, id).await?;
    let extra = serde_json::json!({
        "installable_helpers": helper_install::installable_helpers_for_machine(
            &state.pool,
            row.id,
            &row.os,
            &row.arch,
            agent_state.as_deref(),
            row.desktop_version.as_deref(),
            row.proxmox_version.as_deref(),
        )
        .await?,
    });
    Ok(Json(machines::machine_row_to_json(
        &row,
        agent_state.as_deref(),
        Some(extra),
    )?))
}

fn parse_command_status(s: &str) -> CommandStatus {
    match s {
        "pending_approval" => CommandStatus::PendingApproval,
        "queued" => CommandStatus::Queued,
        "dispatched" => CommandStatus::Dispatched,
        "running" => CommandStatus::Running,
        "completed" => CommandStatus::Completed,
        "failed" => CommandStatus::Failed,
        "expired" => CommandStatus::Expired,
        "cancelled" => CommandStatus::Cancelled,
        _ => CommandStatus::Queued,
    }
}

fn command_status_is_terminal(status: CommandStatus) -> bool {
    matches!(
        status,
        CommandStatus::Completed
            | CommandStatus::Failed
            | CommandStatus::Expired
            | CommandStatus::Cancelled
    )
}

fn wait_requested(query: &GetCommandQuery) -> bool {
    matches!(
        query.wait.as_deref().map(str::trim),
        Some("1") | Some("true") | Some("yes")
    )
}

async fn load_command_detail(
    state: &AppState,
    identity_id: Uuid,
    id: Uuid,
) -> ApiResult<CommandDetail> {
    let row: Option<(Uuid, Uuid, String, String)> = sqlx::query_as(
        "SELECT id, machine_id, command_name, status::text FROM command_queue
         WHERE id = $1 AND ai_identity_id = $2",
    )
    .bind(id)
    .bind(identity_id)
    .fetch_optional(&state.pool)
    .await?;

    let (command_id, machine_id, command_name, status_str) = row.ok_or(ApiError::NotFound)?;
    let status = parse_command_status(&status_str);

    let result: Option<(String, String, Option<i32>, bool)> = sqlx::query_as(
        "SELECT stdout, stderr, exit_code, truncated FROM command_results WHERE command_id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;

    Ok(CommandDetail {
        command_id,
        machine_id,
        command_name,
        status,
        result: result.map(|(stdout, stderr, exit_code, truncated)| {
            hecate_protocol::command::CommandResultPayload {
                command_id: id,
                stdout,
                stderr,
                exit_code,
                truncated,
            }
        }),
    })
}

async fn enqueue_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnqueueBody>,
) -> ApiResult<(axum::http::StatusCode, Json<CommandEnqueueResponse>)> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    if body.command_name == "remote.download" && body.params.get("connect_ip").is_some() {
        return Err(ApiError::BadRequest(
            "connect_ip is server-assigned and must not be supplied by the client".into(),
        ));
    }
    if body.params.get("artifact_download_path").is_some() {
        return Err(ApiError::BadRequest(
            "artifact_download_path is server-assigned and must not be supplied by the client"
                .into(),
        ));
    }
    let matched = permissions::authorize_command(
        &state.pool,
        identity_id,
        body.machine_id,
        &body.command_name,
        &body.params,
    )
    .await?;

    if body.command_name == "system.reboot" {
        if has_pending_system_reboot(&state.pool, body.machine_id).await? {
            return Err(ApiError::Conflict(
                "system reboot is already queued".into(),
            ));
        }
        if is_machine_busy(&state.pool, body.machine_id).await? {
            return Err(ApiError::Conflict(
                "machine is busy with commands".into(),
            ));
        }
    } else if has_pending_system_reboot(&state.pool, body.machine_id).await? {
        return Err(ApiError::Conflict(
            "machine is rebooting; wait for system.reboot to finish".into(),
        ));
    }

    let mut params = body.params.clone();
    if body.command_name == "remote.download" {
        permissions::pin_remote_download_connect_ip(&mut params).await?;
    }
    if body.command_name == helper_install::COMMAND_NAME {
        let component = helper_install::parse_helper_component(&params)?;
        helper_install::ensure_can_install(&state.pool, body.machine_id, &component).await?;
        params = serde_json::json!({ "component": component });
    }

    // Allocate session_id server-side for session.open.
    if body.command_name == "desktop.session.open" {
        let session_id = desktop_sessions::create_session(
            &state.pool,
            body.machine_id,
            identity_id,
            &params,
        )
        .await?;
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "session_id".into(),
                serde_json::Value::String(session_id.to_string()),
            );
        }
    }
    if body.command_name == "proxmox.console.open" {
        let session_id = proxmox_sessions::create_session(
            &state.pool,
            body.machine_id,
            identity_id,
            &params,
        )
        .await?;
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "session_id".into(),
                serde_json::Value::String(session_id.to_string()),
            );
        }
    }

    // Validate follow-up session commands against tracked sessions.
    if desktop_sessions::is_session_followup(&body.command_name) {
        let session_id = desktop_sessions::required_session_id(&params)?;
        desktop_sessions::ensure_open_session(
            &state.pool,
            session_id,
            body.machine_id,
            identity_id,
        )
        .await?;
        if body.command_name == "desktop.session.close" {
            desktop_sessions::close_session(
                &state.pool,
                session_id,
                body.machine_id,
                identity_id,
            )
            .await?;
        }
    }
    if proxmox_sessions::is_session_followup(&body.command_name) {
        let session_id = proxmox_sessions::required_session_id(&params)?;
        proxmox_sessions::ensure_open_session(
            &state.pool,
            session_id,
            body.machine_id,
            identity_id,
        )
        .await?;
        if body.command_name == "proxmox.console.close" {
            proxmox_sessions::close_session(
                &state.pool,
                session_id,
                body.machine_id,
                identity_id,
            )
            .await?;
        }
    }

    let session_followup_approved = desktop_sessions::is_session_followup(&body.command_name)
        || proxmox_sessions::is_session_followup(&body.command_name);

    let status = {
        let requires_approval = if session_followup_approved {
            // approve-once: open was already gated; follow-ups auto-queue
            false
        } else {
            permissions::command_enqueue_requires_approval(
                &state.pool,
                &matched,
                &body.command_name,
                &params,
            )
            .await?
        };
        if requires_approval {
            CommandStatus::PendingApproval
        } else {
            CommandStatus::Queued
        }
    };

    let command_id = Uuid::new_v4();
    let profile = &matched.capability_profile;
    let execution_policy_snapshot =
        hecate_protocol::task::TaskExecutionPolicy::from(profile.clone());
    let snapshot_json = serde_json::to_value(&execution_policy_snapshot)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let timeout_secs = if body.command_name == "system.reboot" {
        SYSTEM_REBOOT_TIMEOUT_SECS
    } else if helper_install::is_package_update_command(&body.command_name) {
        AGENT_UPDATE_TIMEOUT_SECS
    } else {
        let policy_timeout = profile.timeout_secs.max(1);
        let requested = body
            .params
            .get("timeout_secs")
            .and_then(|value| value.as_u64())
            .map(|value| value as u32)
            .unwrap_or(policy_timeout);
        requested.min(policy_timeout).max(1) as i32
    };
    sqlx::query(
        "INSERT INTO command_queue (
            id, machine_id, ai_identity_id, command_name, params, status, timeout_secs,
            matched_grant_assignment_id, execution_policy_snapshot
         )
         VALUES ($1, $2, $3, $4, $5, $6::command_status, $7, $8, $9)",
    )
    .bind(command_id)
    .bind(body.machine_id)
    .bind(identity_id)
    .bind(&body.command_name)
    .bind(&params)
    .bind(match status {
        CommandStatus::PendingApproval => "pending_approval",
        CommandStatus::Queued => "queued",
        _ => "queued",
    })
    .bind(timeout_secs)
    .bind(matched.assignment_id)
    .bind(snapshot_json)
    .execute(&state.pool)
    .await?;

    if body.command_name == "file.push"
        || (body.command_name == "desktop.clipboard.set"
            && params.get("artifact_id").and_then(|v| v.as_str()).is_some())
    {
        let artifact_id = params
            .get("artifact_id")
            .and_then(|value| value.as_str())
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| ApiError::BadRequest("artifact_id required".into()))?;
        let sha256 = params
            .get("sha256")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        command_artifacts::link_input_artifact_to_command(
            &state.pool,
            identity_id,
            command_id,
            artifact_id,
            sha256,
        )
        .await?;
    }

    append_audit(
        &state.pool,
        &identity_id.to_string(),
        "command.enqueue",
        &command_id.to_string(),
        "",
        &serde_json::json!({
            "command_name": body.command_name,
            "elevated": params.get("elevated").and_then(|v| v.as_bool()).unwrap_or(false),
        }),
    )
    .await?;

    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(CommandEnqueueResponse {
            command_id,
            status,
        }),
    ))
}

async fn upload_command_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    let sha256 = headers
        .get("x-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let filename = headers
        .get("x-filename")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("upload.bin");

    let stored = command_artifacts::store_input_artifact(
        &state.pool,
        &state.config,
        identity_id,
        filename,
        &body,
        if sha256.is_empty() { None } else { Some(sha256) },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "artifact_id": stored.artifact_id,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "original_name": stored.original_name,
        })),
    ))
}

async fn download_command_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, [(axum::http::HeaderName, String); 2], Vec<u8>)> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    let (artifact, bytes) =
        command_artifacts::load_internal_output_artifact(&state.pool, identity_id, id).await?;

    Ok((
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (
                axum::http::HeaderName::from_static("x-sha256"),
                artifact.sha256,
            ),
        ],
        bytes,
    ))
}

async fn get_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<GetCommandQuery>,
) -> ApiResult<Json<CommandDetail>> {
    let identity_id = verify_internal_token(&state, &headers).await?;

    if !wait_requested(&query) {
        return Ok(Json(load_command_detail(&state, identity_id, id).await?));
    }

    let timeout_secs = query
        .wait_timeout_secs
        .unwrap_or(DEFAULT_WAIT_TIMEOUT_SECS)
        .clamp(1, MAX_WAIT_TIMEOUT_SECS);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        let detail = load_command_detail(&state, identity_id, id).await?;
        if command_status_is_terminal(detail.status) {
            return Ok(Json(detail));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(Json(detail));
        }
        tokio::time::sleep(WAIT_POLL_INTERVAL).await;
    }
}

async fn list_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<ListCommandsResponse>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    let offset = q.offset.unwrap_or(0).max(0);

    let rows: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
        "SELECT id, machine_id, command_name, status::text FROM command_queue
         WHERE ai_identity_id = $1
           AND ($2::uuid IS NULL OR machine_id = $2)
           AND ($3::text IS NULL OR status::text = $3)
         ORDER BY created_at DESC
         LIMIT $4 OFFSET $5",
    )
    .bind(identity_id)
    .bind(q.machine_id)
    .bind(q.status.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    let commands = rows
        .into_iter()
        .map(|(command_id, machine_id, command_name, status_str)| CommandDetail {
            command_id,
            machine_id,
            command_name,
            status: parse_command_status(&status_str),
            result: None,
        })
        .collect();

    Ok(Json(ListCommandsResponse { commands }))
}

async fn cancel_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    let updated = sqlx::query(
        "UPDATE command_queue SET status = 'cancelled', cancel_requested_at = now()
         WHERE id = $1 AND ai_identity_id = $2 AND status IN ('queued')",
    )
    .bind(id)
    .bind(identity_id)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::Conflict("cannot cancel".into()));
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn ai_context(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AiContextResponse>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    let identity: (Uuid, String, bool) = sqlx::query_as(
        "SELECT id, name, active FROM ai_identities
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(identity_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    if !identity.2 {
        return Err(ApiError::Forbidden);
    }

    let effective = crate::authz::compute_effective_rights(&state.pool, identity_id).await?;
    let assignments =
        crate::authz::store::load_enabled_assignment_details(&state.pool, identity_id).await?;
    let mut elevation_enabled = false;
    let mut elevation_bins = Vec::new();
    let mut max_timeout = 0u32;
    let mut max_output = 0u32;
    let mut max_file = 0u32;
    for (_, detail) in &assignments {
        let profile = &detail.capability_profile;
        if profile.elevation_policy.enabled {
            elevation_enabled = true;
            for bin in &profile.elevation_policy.allowed_binaries {
                if !elevation_bins.contains(bin) {
                    elevation_bins.push(bin.clone());
                }
            }
        }
        max_timeout = max_timeout.max(profile.timeout_secs);
        max_output = max_output.max(profile.max_output_bytes);
        max_file = max_file.max(profile.max_file_bytes);
    }
    let capabilities = AiContextCapabilities {
        elevation_enabled,
        elevation_allowed_binaries: elevation_bins,
        shell_run_max_timeout_secs: max_timeout.max(1),
        max_output_bytes: max_output.max(hecate_protocol::permissions::DEFAULT_MAX_OUTPUT_BYTES),
        max_file_bytes: max_file.max(hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES),
    };

    Ok(Json(AiContextResponse {
        identity: hecate_protocol::permissions::AiIdentitySummary {
            id: identity.0,
            name: identity.1,
            active: identity.2,
        },
        grant_assignments: effective.assignments,
        effective_summary: effective.summary,
        capabilities,
        admin_capabilities: AiContextAdminCapabilities {
            allowed_admin_commands: effective.allowed_admin_commands,
        },
    }))
}

async fn authz_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AuthzCatalogResponse>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    Ok(Json(
        crate::authz::build_self_service_catalog(&state.pool, identity_id).await?,
    ))
}

async fn effective_rights(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<EffectiveRightsReport>> {
    let identity_id = verify_internal_token(&state, &headers).await?;
    Ok(Json(
        crate::authz::compute_effective_rights(&state.pool, identity_id).await?,
    ))
}
