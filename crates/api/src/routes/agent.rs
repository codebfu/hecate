//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hecate_protocol::agent::{
    AgentState, AgentStatusResponse, EnrollRequest, EnrollResponse, HeartbeatRequest,
    RotateCredentialRequest, RotateCredentialResponse, UpdateOfferRequest, UpdateOfferResponse,
};
use hecate_protocol::command::CommandResultPayload;
use hecate_protocol::task::PullResponse;
use uuid::Uuid;

use crate::agent_auth;
use crate::audit::append_audit;
use crate::command_artifacts::{self, command_artifact_api_path};
use crate::command_dispatch::{
    build_pull_response_with_keys, build_update_offer_response, desktop_release_artifact_api_path,
    load_dispatched_commands, load_task_signing_privkey, proxmox_release_artifact_api_path,
    release_artifact_api_path,
};
use crate::error::{ApiError, ApiResult};
use crate::key_rotation;
use crate::state::AppState;
use crate::task_crypto::generate_task_signing_keypair;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/agent/enroll", post(enroll))
        .route("/api/v1/agent/status", get(agent_status))
        .route("/api/v1/agent/pull", get(pull))
        .route("/api/v1/agent/credentials/rotate", post(rotate_credentials))
        .route("/api/v1/agent/update-offer", post(get_update_offer))
        .route(
            "/api/v1/agent/releases/{version}/artifact/{component}",
            get(download_component_release_artifact),
        )
        .route(
            "/api/v1/agent/releases/{version}/artifact",
            get(download_release_artifact),
        )
        .route(
            "/api/v1/agent/releases/{version}/desktop-artifact",
            get(download_desktop_release_artifact),
        )
        .route(
            "/api/v1/agent/releases/{version}/proxmox-artifact",
            get(download_proxmox_release_artifact),
        )
        .route(
            "/api/v1/agent/commands/{command_id}/artifact",
            get(download_command_artifact).put(upload_command_artifact),
        )
        .route("/api/v1/agent/results", post(submit_results))
        .route("/api/v1/agent/heartbeat", post(heartbeat))
}

async fn enroll(
    State(state): State<AppState>,
    Json(body): Json<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    crate::enrollment::validate_agent_enroll_body(&body)?;

    let token_hmac = crate::crypto::hmac_sha256_hex(&state.config.api_key_pepper, &body.enrollment_token);
    let mut tx = state.pool.begin().await?;

    let claimed: Option<(Uuid, Vec<String>, Option<Uuid>)> = sqlx::query_as(
        "UPDATE enrollment_tokens
         SET used_at = now()
         WHERE token_hmac = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING id, bound_tags, bound_machine_id",
    )
    .bind(&token_hmac)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((_token_id, bound_tags, bound_machine_id)) = claimed else {
        return Err(ApiError::Unauthorized);
    };

    let release_key =
        crate::server_settings::resolve_release_signing_public_key_b64(&state.pool, &state.config)
            .await?;
    let release_public_key_b64 =
        crate::server_settings::optional_release_public_key(&release_key);

    if let Some(machine_id) = bound_machine_id {
        crate::enrollment::ensure_bound_id_matches(machine_id, body.agent_id, "agent_id")?;
        let response = reenroll_agent(
            &mut tx,
            machine_id,
            &body,
            &bound_tags,
            release_public_key_b64.clone(),
        )
        .await?;
        tx.commit().await?;
        let machine_tags = hecate_protocol::machine_tags::resolve_enrollment_tags(
            &body.tags,
            &body.os,
            &body.arch,
        )
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let fingerprint = crate::enrollment::public_key_fingerprint(&body.public_key);
        append_audit(
            &state.pool,
            "agent",
            "agent.reenroll",
            &machine_id.to_string(),
            "",
            &serde_json::json!({
                "hostname": body.hostname,
                "agent_state": match response.state {
                    AgentState::Active => "active",
                    AgentState::PendingApproval => "pending_approval",
                    AgentState::Revoked => "revoked",
                },
                "tags": machine_tags,
                "operator_tags": bound_tags,
                "credential_pubkey_fingerprint": fingerprint,
            }),
        )
        .await?;
        return Ok(Json(response));
    }

    crate::enrollment::reject_client_id_for_fresh_enroll(body.agent_id, "agent_id")?;

    let machine_tags = hecate_protocol::machine_tags::resolve_enrollment_tags(
        &body.tags,
        &body.os,
        &body.arch,
    )
    .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let auto_approve = crate::server_settings::enrollment_auto_approve(&state.pool).await?;
    let (agent_state, machine_status, response_state) = if auto_approve {
        (
            "active",
            "offline",
            hecate_protocol::agent::AgentState::Active,
        )
    } else {
        (
            "pending_approval",
            "pending",
            hecate_protocol::agent::AgentState::PendingApproval,
        )
    };

    let machine_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO machines (id, hostname, os, arch, tags, operator_tags, attestation_json, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(machine_id)
    .bind(body.hostname.trim())
    .bind(body.os.trim())
    .bind(body.arch.trim())
    .bind(&machine_tags)
    .bind(&bound_tags)
    .bind(&body.attestation)
    .bind(machine_status)
    .execute(&mut *tx)
    .await?;

    let (task_signing_privkey, task_signing_pubkey_b64) = generate_task_signing_keypair();
    let wrapped = crate::crypto::wrap_task_signing_privkey(&task_signing_privkey)
        .map_err(|error| ApiError::Internal(error))?;

    sqlx::query(
        "INSERT INTO agents (machine_id, credential_pubkey, task_signing_privkey, state) VALUES ($1, $2, $3, $4::agent_state)",
    )
    .bind(machine_id)
    .bind(body.public_key.trim())
    .bind(&wrapped)
    .bind(agent_state)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    append_audit(
        &state.pool,
        "agent",
        "agent.enroll",
        &machine_id.to_string(),
        "",
        &serde_json::json!({
            "hostname": body.hostname,
            "auto_approved": auto_approve,
            "agent_state": agent_state,
            "tags": machine_tags,
            "operator_tags": bound_tags,
        }),
    )
    .await?;

    Ok(Json(EnrollResponse {
        agent_id: machine_id,
        machine_id,
        state: response_state,
        task_signing_pubkey_b64,
        release_public_key_b64,
    }))
}

async fn reenroll_agent(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: Uuid,
    body: &EnrollRequest,
    bound_tags: &[String],
    release_public_key_b64: Option<String>,
) -> ApiResult<EnrollResponse> {
    let machine_tags = hecate_protocol::machine_tags::resolve_enrollment_tags(
        &body.tags,
        &body.os,
        &body.arch,
    )
    .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let agent_row: Option<(String,)> = sqlx::query_as(
        "SELECT a.state::text
         FROM agents a
         INNER JOIN machines m ON m.id = a.machine_id
         WHERE a.machine_id = $1 AND m.deleted_at IS NULL",
    )
    .bind(machine_id)
    .fetch_optional(&mut **tx)
    .await?;

    let Some((agent_state,)) = agent_row else {
        return Err(ApiError::NotFound);
    };

    if agent_state == "revoked" {
        return Err(ApiError::Forbidden);
    }

    let response_state = match agent_state.as_str() {
        "active" => AgentState::Active,
        "pending_approval" => AgentState::PendingApproval,
        _ => AgentState::PendingApproval,
    };

    let (task_signing_privkey, task_signing_pubkey_b64) = generate_task_signing_keypair();
    let wrapped = crate::crypto::wrap_task_signing_privkey(&task_signing_privkey)
        .map_err(|error| ApiError::Internal(error))?;

    sqlx::query(
        "UPDATE agents SET
            credential_pubkey = $2,
            credential_pubkey_previous = NULL,
            credential_pubkey_previous_expires_at = NULL,
            credential_rotation_requested_at = NULL,
            task_signing_privkey = $3,
            task_signing_privkey_previous = NULL,
            task_signing_pubkey_previous_b64 = NULL,
            task_signing_previous_expires_at = NULL,
            task_signing_continuity_sig_b64 = NULL,
            task_signing_continuity_chain = '[]'::jsonb
         WHERE machine_id = $1",
    )
    .bind(machine_id)
    .bind(body.public_key.trim())
    .bind(&wrapped)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "UPDATE machines SET
            hostname = $2,
            os = $3,
            arch = $4,
            tags = $5,
            operator_tags = $6,
            attestation_json = $7
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(machine_id)
    .bind(body.hostname.trim())
    .bind(body.os.trim())
    .bind(body.arch.trim())
    .bind(&machine_tags)
    .bind(bound_tags)
    .bind(&body.attestation)
    .execute(&mut **tx)
    .await?;

    Ok(EnrollResponse {
        agent_id: machine_id,
        machine_id,
        state: response_state,
        task_signing_pubkey_b64,
        release_public_key_b64,
    })
}

async fn agent_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AgentStatusResponse>> {
    const PATH: &str = "/api/v1/agent/status";
    let auth = agent_auth::verify_agent_request(
        &state.pool,
        "GET",
        PATH,
        b"",
        &headers,
    )
    .await?;

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT a.state::text, m.hostname
         FROM agents a
         JOIN machines m ON m.id = a.machine_id
         WHERE a.machine_id = $1",
    )
    .bind(auth.agent_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some((state_text, hostname)) = row else {
        return Err(ApiError::NotFound);
    };

    Ok(Json(AgentStatusResponse {
        agent_id: auth.agent_id,
        state: parse_agent_state(&state_text)?,
        hostname,
    }))
}

fn parse_agent_state(value: &str) -> ApiResult<AgentState> {
    match value {
        "pending_approval" => Ok(AgentState::PendingApproval),
        "active" => Ok(AgentState::Active),
        "revoked" => Ok(AgentState::Revoked),
        other => Err(ApiError::Internal(anyhow::anyhow!(
            "unknown agent state: {other}"
        ))),
    }
}

async fn pull(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<PullResponse>> {
    const PATH: &str = "/api/v1/agent/pull";
    let auth = agent_auth::verify_agent_request(
        &state.pool,
        "GET",
        PATH,
        b"",
        &headers,
    )
    .await?;

    let agent_state: Option<String> = sqlx::query_scalar(
        "SELECT state::text FROM agents WHERE machine_id = $1",
    )
    .bind(auth.agent_id)
    .fetch_optional(&state.pool)
    .await?;

    if agent_state.as_deref() != Some("active") {
        return Ok(Json(PullResponse {
            tasks: vec![],
            key_material: None,
        }));
    }

    let key_material =
        key_rotation::build_key_material_payload(&state.pool, &state.config, auth.agent_id).await?;
    let commands = load_dispatched_commands(&state.pool, auth.agent_id).await?;
    let privkey = load_task_signing_privkey(&state.pool, auth.agent_id).await?;
    if !commands.is_empty() && privkey.trim().is_empty() {
        return Err(ApiError::Conflict(
            "agent task signing key is not configured; create a machine-bound re-enrollment token in Machines → agent detail, then run hecate-lampad enroll".into(),
        ));
    }
    Ok(Json(build_pull_response_with_keys(
        &privkey,
        auth.agent_id,
        &commands,
        Some(key_material),
    )?))
}

async fn rotate_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<RotateCredentialResponse>> {
    const PATH: &str = "/api/v1/agent/credentials/rotate";
    let (auth, body): (_, RotateCredentialRequest) =
        agent_auth::verify_and_parse_json(&state.pool, "POST", PATH, &body, &headers).await?;

    let expires_at =
        key_rotation::apply_credential_rotation(&state.pool, auth.agent_id, &body.new_public_key)
            .await?;

    append_audit(
        &state.pool,
        "agent",
        "agent.credential_rotated",
        &auth.agent_id.to_string(),
        "",
        &serde_json::json!({
            "previous_expires_at": expires_at.to_rfc3339(),
        }),
    )
    .await?;

    Ok(Json(RotateCredentialResponse {
        ok: true,
        previous_expires_at: Some(expires_at.to_rfc3339()),
    }))
}

async fn get_update_offer(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<UpdateOfferResponse>> {
    const PATH: &str = "/api/v1/agent/update-offer";
    let (auth, body): (_, UpdateOfferRequest) =
        agent_auth::verify_and_parse_json(&state.pool, "POST", PATH, &body, &headers).await?;

    let agent_state: Option<String> = sqlx::query_scalar(
        "SELECT state::text FROM agents WHERE machine_id = $1",
    )
    .bind(auth.agent_id)
    .fetch_optional(&state.pool)
    .await?;

    if agent_state.as_deref() != Some("active") {
        return Ok(Json(UpdateOfferResponse {
            available: false,
            current_version: body.agent_version,
            target_version: None,
            artifact_path: None,
            sha256: None,
            signature: None,
            release_public_key_b64: None,
            reason: Some("agent is not active".into()),
            desktop: None,
            proxmox: None,
            key_material: None,
            server_task_sig: None,
        }));
    }

    Ok(Json(
        build_update_offer_response(
            &state.pool,
            &state.config,
            auth.agent_id,
            &body.agent_version,
            body.desktop_version.as_deref(),
            body.proxmox_version.as_deref(),
        )
        .await?,
    ))
}

async fn download_release_artifact(
    State(state): State<AppState>,
    Path(version): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    download_feature_artifact(&state, &version, "agent", &headers).await
}

async fn download_desktop_release_artifact(
    State(state): State<AppState>,
    Path(version): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    download_feature_artifact(&state, &version, "desktop", &headers).await
}

async fn download_proxmox_release_artifact(
    State(state): State<AppState>,
    Path(version): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    download_feature_artifact(&state, &version, "proxmox", &headers).await
}

async fn download_component_release_artifact(
    State(state): State<AppState>,
    Path((version, component)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    download_feature_artifact(&state, &version, &component, &headers).await
}

async fn download_feature_artifact(
    state: &AppState,
    version: &str,
    component: &str,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let parsed_component = hecate_protocol::release_artifacts::ReleaseComponent::parse(component)
        .ok_or(ApiError::NotFound)?;
    let path = hecate_protocol::release_artifacts::release_artifact_api_path(version, parsed_component);
    // Agents may still sign legacy aliases; accept either canonical or legacy path.
    let auth = match agent_auth::verify_agent_request(&state.pool, "GET", &path, b"", headers).await {
        Ok(auth) => auth,
        Err(_) => {
            let legacy = match parsed_component {
                hecate_protocol::release_artifacts::ReleaseComponent::Agent => {
                    format!("/api/v1/agent/releases/{version}/artifact")
                }
                hecate_protocol::release_artifacts::ReleaseComponent::Desktop => {
                    format!("/api/v1/agent/releases/{version}/desktop-artifact")
                }
                hecate_protocol::release_artifacts::ReleaseComponent::Proxmox => {
                    format!("/api/v1/agent/releases/{version}/proxmox-artifact")
                }
            };
            agent_auth::verify_agent_request(&state.pool, "GET", &legacy, b"", headers).await?
        }
    };

    let agent_state: Option<String> =
        sqlx::query_scalar("SELECT state::text FROM agents WHERE machine_id = $1")
            .bind(auth.agent_id)
            .fetch_optional(&state.pool)
            .await?;
    if agent_state.as_deref() != Some("active") {
        return Err(ApiError::Forbidden);
    }

    let machine: Option<(String, String)> =
        sqlx::query_as("SELECT os, arch FROM machines WHERE id = $1")
            .bind(auth.agent_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((os, arch)) = machine else {
        return Err(ApiError::NotFound);
    };

    let Some(release) = crate::feature_repo::releases::get_pinned_release_for_download(
        &state.pool,
        parsed_component.as_str(),
        &os,
        &arch,
        version,
    )
    .await?
    else {
        return Err(ApiError::NotFound);
    };

    let etag = format!("\"{}\"", release.sha256);
    if headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|tag| tag.trim_matches('"') == release.sha256)
        })
    {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [
                ("etag", etag.as_str()),
                ("content-type", "application/octet-stream"),
            ],
            Vec::new(),
        )
            .into_response());
    }

    let bytes = crate::feature_repo::releases::read_cached_artifact_bytes(
        &state.config.release_artifacts_dir,
        &release.local_path,
    )
    .await?;

    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/octet-stream"),
            ("etag", etag.as_str()),
        ],
        bytes,
    )
        .into_response())
}

async fn download_command_artifact(
    State(state): State<AppState>,
    Path(command_id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let path = command_artifact_api_path(command_id);
    let auth = agent_auth::verify_agent_request(
        &state.pool,
        "GET",
        &path,
        b"",
        &headers,
    )
    .await?;

    let (_artifact, bytes) =
        command_artifacts::load_agent_input_artifact(&state.pool, command_id, auth.agent_id)
            .await?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        bytes,
    )
        .into_response())
}

async fn upload_command_artifact(
    State(state): State<AppState>,
    Path(command_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let path = command_artifact_api_path(command_id);
    let auth = agent_auth::verify_agent_request(
        &state.pool,
        "PUT",
        &path,
        &body,
        &headers,
    )
    .await?;

    let (ai_identity_id, command_name) =
        command_artifacts::verify_command_allows_output_upload(
            &state.pool,
            command_id,
            auth.agent_id,
        )
        .await?;

    let expected_sha256 = headers
        .get("x-sha256")
        .and_then(|value| value.to_str().ok());
    let original_name = headers
        .get("x-filename")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("artifact.bin");

    let stored = command_artifacts::store_output_artifact(
        &state.pool,
        &state.config,
        command_id,
        ai_identity_id,
        original_name,
        &body,
        expected_sha256,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "artifact_id": stored.artifact_id,
        "sha256": stored.sha256,
        "size_bytes": stored.size_bytes,
        "command_name": command_name,
    })))
}

async fn submit_results(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    const PATH: &str = "/api/v1/agent/results";
    let (auth, body): (_, CommandResultPayload) =
        agent_auth::verify_and_parse_json(&state.pool, "POST", PATH, &body, &headers).await?;

    let command_status: Option<String> = sqlx::query_scalar(
        "SELECT status::text FROM command_queue
         WHERE id = $1 AND machine_id = $2 AND status IN ('dispatched', 'running')",
    )
    .bind(body.command_id)
    .bind(auth.agent_id)
    .fetch_optional(&state.pool)
    .await?;

    if command_status.is_none() {
        return Err(ApiError::Conflict("command not awaiting results".into()));
    }

    let inserted = sqlx::query(
        "INSERT INTO command_results (command_id, stdout, stderr, exit_code, truncated, byte_count)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (command_id) DO NOTHING",
    )
    .bind(body.command_id)
    .bind(&body.stdout)
    .bind(&body.stderr)
    .bind(body.exit_code)
    .bind(body.truncated)
    .bind((body.stdout.len() + body.stderr.len()) as i32)
    .execute(&state.pool)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::Conflict("command result already recorded".into()));
    }

    let status = if body.exit_code.unwrap_or(1) == 0 {
        "completed"
    } else {
        "failed"
    };
    let updated = sqlx::query(
        "UPDATE command_queue
         SET status = $1::command_status, finished_at = now(), reboot_phase = NULL
         WHERE id = $2 AND status IN ('dispatched', 'running')",
    )
    .bind(status)
    .bind(body.command_id)
    .execute(&state.pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::Conflict("command not awaiting results".into()));
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    const PATH: &str = "/api/v1/agent/heartbeat";
    let (auth, body): (_, HeartbeatRequest) =
        agent_auth::verify_and_parse_json(&state.pool, "POST", PATH, &body, &headers).await?;

    let incoming_tags = hecate_protocol::machine_tags::resolve_heartbeat_tags(&body.tags)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let merged_agent_tags = if let Some(incoming) = incoming_tags {
        let existing: Vec<String> = sqlx::query_scalar("SELECT tags FROM machines WHERE id = $1")
            .bind(auth.agent_id)
            .fetch_one(&state.pool)
            .await?;
        Some(
            hecate_protocol::machine_tags::merge_agent_heartbeat_tags(&existing, &incoming)
                .map_err(|error| ApiError::BadRequest(error.to_string()))?,
        )
    } else {
        None
    };

    // Detect agent process restart before overwriting the previous uptime sample.
    let uptime_secs = body.uptime_secs as i64;
    if let Err(error) = crate::reboot_watch::complete_reboot_on_agent_restart(
        &state.pool,
        auth.agent_id,
        uptime_secs,
    )
    .await
    {
        tracing::warn!(
            machine_id = %auth.agent_id,
            error = %error,
            "failed to complete system.reboot on agent restart"
        );
    }

    sqlx::query(
        "UPDATE machines
         SET status = CASE
               WHEN (SELECT state FROM agents WHERE machine_id = $3) = 'active' THEN 'online'
               ELSE status
             END,
             last_seen_at = now(),
             agent_version = $1,
             desktop_version = $5,
             proxmox_version = $11,
             hostname = CASE WHEN $2 <> '' THEN $2 ELSE hostname END,
             tags = CASE WHEN $4::text[] IS NOT NULL THEN $4 ELSE tags END,
             agent_uptime_secs = $6,
             agent_healthy = CASE WHEN $7::boolean IS NULL THEN agent_healthy ELSE $7 END,
             agent_secs_since_last_pull = CASE
               WHEN $7::boolean IS NULL THEN agent_secs_since_last_pull
               ELSE $8
             END,
             agent_current_command_id = CASE
               WHEN $7::boolean IS NULL THEN agent_current_command_id
               WHEN $9::boolean THEN $10
               ELSE NULL
             END
         WHERE id = $3",
    )
    .bind(&body.agent_version)
    .bind(&body.hostname)
    .bind(auth.agent_id)
    .bind(merged_agent_tags)
    .bind(body.desktop_version.as_deref())
    .bind(uptime_secs)
    .bind(body.healthy)
    .bind(body.secs_since_last_pull.map(|v| v as i64))
    .bind(body.busy)
    .bind(body.current_command_id)
    .bind(body.proxmox_version.as_deref())
    .execute(&state.pool)
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Validate an artifact_path for backup restore (must stay under jail, no traversal).
pub fn jail_release_artifact_path(
    release_artifacts_dir: &std::path::Path,
    artifact_path: &str,
) -> ApiResult<String> {
    hecate_protocol::policy::reject_path_traversal(artifact_path)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let jail = std::fs::canonicalize(release_artifacts_dir).unwrap_or_else(|_| {
        release_artifacts_dir.to_path_buf()
    });
    let candidate = std::path::Path::new(artifact_path);
    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        jail.join(candidate)
    };
    let jail_cmp = jail.to_string_lossy().replace('\\', "/");
    let abs_cmp = absolute.to_string_lossy().replace('\\', "/");
    if abs_cmp != jail_cmp && !abs_cmp.starts_with(&format!("{jail_cmp}/")) {
        return Err(ApiError::BadRequest(
            "artifact_path must be under release_artifacts_dir".into(),
        ));
    }
    Ok(absolute.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::machine_tags::{resolve_enrollment_tags, resolve_heartbeat_tags};

    #[test]
    fn parse_agent_state_maps_db_values() {
        assert_eq!(
            parse_agent_state("pending_approval").unwrap(),
            AgentState::PendingApproval
        );
        assert_eq!(parse_agent_state("active").unwrap(), AgentState::Active);
        assert_eq!(parse_agent_state("revoked").unwrap(), AgentState::Revoked);
        assert!(parse_agent_state("unknown").is_err());
    }

    #[test]
    fn enrollment_tag_resolution_accepts_agent_tags() {
        let tags = vec!["os:linux".into(), "arch:x86_64".into(), "virt:vm".into()];
        let resolved = resolve_enrollment_tags(&tags, "linux", "x86_64").expect("valid tags");
        assert_eq!(resolved, vec!["arch:x86_64", "os:linux", "virt:vm"]);
    }

    #[test]
    fn enrollment_tag_resolution_falls_back_to_os_arch() {
        let resolved = resolve_enrollment_tags(&[], "linux", "aarch64").expect("fallback");
        assert_eq!(resolved, vec!["arch:aarch64", "os:linux"]);
    }

    #[test]
    fn heartbeat_tag_resolution_skips_update_when_empty() {
        assert_eq!(resolve_heartbeat_tags(&[]).expect("empty"), None);
    }

    #[test]
    fn heartbeat_tag_resolution_accepts_refreshed_tags() {
        let tags = vec!["virt:container".into(), "os:linux".into()];
        assert_eq!(
            resolve_heartbeat_tags(&tags).expect("valid"),
            Some(vec!["os:linux".into(), "virt:container".into()])
        );
    }

    #[test]
    fn legacy_heartbeat_json_parses_without_health_fields() {
        let legacy = br#"{"agent_version":"1.0.0","uptime_secs":12,"hostname":"cortex","tags":[]}"#;
        let parsed: HeartbeatRequest =
            serde_json::from_slice(legacy).expect("legacy heartbeat must deserialize");
        assert_eq!(parsed.healthy, None);
        assert!(!parsed.busy);
        // Re-serializing must not invent bytes the agent never signed. `busy: false` is omitted.
        let re = serde_json::to_vec(&parsed).expect("serialize");
        assert_eq!(re, legacy, "re-serialize must stay signature-compatible with legacy bodies");
    }
}
