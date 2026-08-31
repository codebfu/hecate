//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Propylaea proxy enrollment, sync, and heartbeat endpoints.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use hecate_protocol::agent::AgentState;
use hecate_protocol::proxy::{
    paths, ProxyEnrollRequest, ProxyEnrollResponse, ProxyHeartbeatRequest, ProxyState,
    ProxySyncAgent, ProxySyncEnrollmentToken, ProxySyncResponse,
};
use uuid::Uuid;

use crate::audit::append_audit;
use crate::enrollment;
use crate::error::{ApiError, ApiResult};
use crate::proxy_auth;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(paths::ENROLL, post(enroll))
        .route(paths::SYNC, get(sync))
        .route(paths::HEARTBEAT, post(heartbeat))
}

async fn enroll(
    State(state): State<AppState>,
    Json(body): Json<ProxyEnrollRequest>,
) -> ApiResult<Json<ProxyEnrollResponse>> {
    enrollment::validate_proxy_enroll_body(&body)?;

    let token_hmac =
        crate::crypto::hmac_sha256_hex(&state.config.api_key_pepper, &body.enrollment_token);
    let mut tx = state.pool.begin().await?;

    let claimed: Option<(Uuid, Vec<String>, Option<Uuid>)> = sqlx::query_as(
        "UPDATE proxy_enrollment_tokens
         SET used_at = now()
         WHERE token_hmac = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING id, bound_tags, bound_proxy_id",
    )
    .bind(&token_hmac)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((_token_id, bound_tags, bound_proxy_id)) = claimed else {
        return Err(ApiError::Unauthorized);
    };

    if let Some(proxy_id) = bound_proxy_id {
        enrollment::ensure_bound_id_matches(proxy_id, body.proxy_id, "proxy_id")?;
        let response = reenroll_proxy(&mut tx, &state, proxy_id, &body, &bound_tags).await?;
        tx.commit().await?;
        let fingerprint = enrollment::public_key_fingerprint(&body.public_key);
        append_audit(
            &state.pool,
            "proxy",
            "proxy.reenroll",
            &proxy_id.to_string(),
            "",
            &serde_json::json!({
                "hostname": body.hostname,
                "proxy_state": match response.state {
                    ProxyState::Active => "active",
                    ProxyState::PendingApproval => "pending_approval",
                    ProxyState::Revoked => "revoked",
                },
                "version": body.version,
                "bound_tags": bound_tags,
                "credential_pubkey_fingerprint": fingerprint,
            }),
        )
        .await?;
        return Ok(Json(response));
    }

    enrollment::reject_client_id_for_fresh_enroll(body.proxy_id, "proxy_id")?;

    let auto_approve =
        crate::server_settings::proxy_enrollment_auto_approve(&state.pool).await?;
    let (db_state, response_state) = if auto_approve {
        ("active", ProxyState::Active)
    } else {
        ("pending_approval", ProxyState::PendingApproval)
    };

    let proxy_id = Uuid::new_v4();
    let mut attestation = if body.attestation.is_null() {
        serde_json::json!({})
    } else {
        body.attestation.clone()
    };
    if let Some(obj) = attestation.as_object_mut() {
        obj.insert(
            "bound_tags".to_string(),
            serde_json::Value::Array(
                bound_tags
                    .iter()
                    .map(|tag| serde_json::Value::String(tag.clone()))
                    .collect(),
            ),
        );
    }

    sqlx::query(
        "INSERT INTO proxies (id, hostname, credential_pubkey, state, version, attestation_json)
         VALUES ($1, $2, $3, $4::proxy_state, $5, $6)",
    )
    .bind(proxy_id)
    .bind(body.hostname.trim())
    .bind(body.public_key.trim())
    .bind(db_state)
    .bind(body.version.trim())
    .bind(&attestation)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    append_audit(
        &state.pool,
        "proxy",
        "proxy.enroll",
        &proxy_id.to_string(),
        "",
        &serde_json::json!({
            "hostname": body.hostname,
            "auto_approved": auto_approve,
            "proxy_state": db_state,
            "version": body.version,
            "bound_tags": bound_tags,
        }),
    )
    .await?;

    Ok(Json(ProxyEnrollResponse {
        proxy_id,
        state: response_state,
    }))
}

async fn reenroll_proxy(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &AppState,
    proxy_id: Uuid,
    body: &ProxyEnrollRequest,
    bound_tags: &[String],
) -> ApiResult<ProxyEnrollResponse> {
    let proxy_row: Option<(String,)> =
        sqlx::query_as("SELECT state::text FROM proxies WHERE id = $1")
            .bind(proxy_id)
            .fetch_optional(&mut **tx)
            .await?;

    let Some((proxy_state,)) = proxy_row else {
        return Err(ApiError::NotFound);
    };

    if proxy_state == "revoked" {
        return Err(ApiError::Forbidden);
    }

    let response_state = match proxy_state.as_str() {
        "active" => ProxyState::Active,
        "pending_approval" => ProxyState::PendingApproval,
        _ => ProxyState::PendingApproval,
    };

    let mut attestation = if body.attestation.is_null() {
        serde_json::json!({})
    } else {
        body.attestation.clone()
    };
    if let Some(obj) = attestation.as_object_mut() {
        obj.insert(
            "bound_tags".to_string(),
            serde_json::Value::Array(
                bound_tags
                    .iter()
                    .map(|tag| serde_json::Value::String(tag.clone()))
                    .collect(),
            ),
        );
    }

    sqlx::query(
        "UPDATE proxies SET
            hostname = $2,
            credential_pubkey = $3,
            credential_pubkey_previous = NULL,
            credential_pubkey_previous_expires_at = NULL,
            version = $4,
            attestation_json = $5
         WHERE id = $1",
    )
    .bind(proxy_id)
    .bind(body.hostname.trim())
    .bind(body.public_key.trim())
    .bind(body.version.trim())
    .bind(&attestation)
    .execute(&mut **tx)
    .await?;

    Ok(ProxyEnrollResponse {
        proxy_id,
        state: response_state,
    })
}

async fn sync(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ProxySyncResponse>> {
    let auth = proxy_auth::verify_proxy_request(
        &state.pool,
        "GET",
        paths::SYNC,
        b"",
        &headers,
    )
    .await?;

    ensure_proxy_active(&state, auth.proxy_id).await?;

    let agent_rows: Vec<(
        Uuid,
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
        String,
    )> = sqlx::query_as(
        "SELECT a.machine_id, a.credential_pubkey, a.credential_pubkey_previous,
                a.credential_pubkey_previous_expires_at, a.state::text
         FROM agents a
         INNER JOIN machines m ON m.id = a.machine_id
         WHERE m.deleted_at IS NULL",
    )
    .fetch_all(&state.pool)
    .await?;

    let agents = agent_rows
        .into_iter()
        .filter_map(
            |(agent_id, pubkey, prev, prev_exp, state_text)| {
                let state = match state_text.as_str() {
                    "pending_approval" => AgentState::PendingApproval,
                    "active" => AgentState::Active,
                    "revoked" => AgentState::Revoked,
                    _ => return None,
                };
                Some(ProxySyncAgent {
                    agent_id,
                    credential_pubkey: pubkey,
                    credential_pubkey_previous: prev.filter(|s| !s.trim().is_empty()),
                    credential_pubkey_previous_expires_at: prev_exp.map(|ts| ts.to_rfc3339()),
                    state,
                })
            },
        )
        .collect();

    let enrollment_tokens = load_agent_enrollment_tokens(&state.pool).await?;
    let proxy_enrollment_tokens = load_proxy_enrollment_tokens(&state.pool).await?;

    sqlx::query("UPDATE proxies SET last_seen_at = now() WHERE id = $1")
        .bind(auth.proxy_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(ProxySyncResponse {
        agents,
        enrollment_tokens,
        proxy_enrollment_tokens,
    }))
}

async fn load_agent_enrollment_tokens(pool: &sqlx::PgPool) -> ApiResult<Vec<ProxySyncEnrollmentToken>> {
    let token_rows: Vec<(
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<Uuid>,
    )> = sqlx::query_as(
        "SELECT token_hmac, expires_at, used_at, bound_machine_id
         FROM enrollment_tokens
         WHERE expires_at > now() - interval '1 day'",
    )
    .fetch_all(pool)
    .await?;

    Ok(token_rows
        .into_iter()
        .map(|(token_hmac, expires_at, used_at, bound_machine_id)| ProxySyncEnrollmentToken {
            token_hmac,
            expires_at: expires_at.to_rfc3339(),
            used_at: used_at.map(|ts| ts.to_rfc3339()),
            bound_machine_id,
            bound_proxy_id: None,
        })
        .collect())
}

async fn load_proxy_enrollment_tokens(pool: &sqlx::PgPool) -> ApiResult<Vec<ProxySyncEnrollmentToken>> {
    let token_rows: Vec<(
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<Uuid>,
    )> = sqlx::query_as(
        "SELECT token_hmac, expires_at, used_at, bound_proxy_id
         FROM proxy_enrollment_tokens
         WHERE expires_at > now() - interval '1 day'",
    )
    .fetch_all(pool)
    .await?;

    Ok(token_rows
        .into_iter()
        .map(|(token_hmac, expires_at, used_at, bound_proxy_id)| ProxySyncEnrollmentToken {
            token_hmac,
            expires_at: expires_at.to_rfc3339(),
            used_at: used_at.map(|ts| ts.to_rfc3339()),
            bound_machine_id: None,
            bound_proxy_id,
        })
        .collect())
}

async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = proxy_auth::verify_proxy_request(
        &state.pool,
        "POST",
        paths::HEARTBEAT,
        &body,
        &headers,
    )
    .await?;

    ensure_proxy_active(&state, auth.proxy_id).await?;

    let payload: ProxyHeartbeatRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("invalid json".into()))?;

    sqlx::query(
        "UPDATE proxies
         SET last_seen_at = now(),
             version = $2,
             hostname = CASE WHEN $3 = '' THEN hostname ELSE $3 END
         WHERE id = $1",
    )
    .bind(auth.proxy_id)
    .bind(payload.version.trim())
    .bind(payload.hostname.trim())
    .execute(&state.pool)
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn ensure_proxy_active(state: &AppState, proxy_id: Uuid) -> ApiResult<()> {
    let state_text: Option<String> =
        sqlx::query_scalar("SELECT state::text FROM proxies WHERE id = $1")
            .bind(proxy_id)
            .fetch_optional(&state.pool)
            .await?;
    match state_text.as_deref() {
        Some("active") => Ok(()),
        Some("pending_approval") => Err(ApiError::Forbidden),
        Some("revoked") => Err(ApiError::Forbidden),
        _ => Err(ApiError::Unauthorized),
    }
}
