//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Proxmox console session tracking for approve-once and TTL.

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

pub fn is_session_followup(command_name: &str) -> bool {
    matches!(
        command_name,
        "proxmox.console.frame" | "proxmox.console.input" | "proxmox.console.close"
    )
}

pub async fn create_session(
    pool: &PgPool,
    machine_id: Uuid,
    ai_identity_id: Uuid,
    params: &serde_json::Value,
) -> ApiResult<Uuid> {
    let session_id = Uuid::new_v4();
    let vmid = params
        .get("vmid")
        .and_then(|value| value.as_u64())
        .and_then(|value| i32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| ApiError::BadRequest("vmid must be a positive integer".into()))?;
    let fps = params
        .get("fps")
        .and_then(|value| value.as_u64())
        .unwrap_or(2)
        .clamp(1, 10) as i32;
    let max_duration_secs = params
        .get("max_duration_secs")
        .and_then(|value| value.as_u64())
        .unwrap_or(600)
        .clamp(30, 3600) as i32;
    let format = params
        .get("format")
        .and_then(|value| value.as_str())
        .unwrap_or("png");
    let format = if format == "jpeg" { "jpeg" } else { "png" };
    let expires_at = Utc::now() + ChronoDuration::seconds(max_duration_secs as i64);

    sqlx::query(
        "INSERT INTO proxmox_console_sessions
         (id, machine_id, ai_identity_id, status, vmid, fps, format, max_duration_secs, expires_at)
         VALUES ($1, $2, $3, 'open', $4, $5, $6, $7, $8)",
    )
    .bind(session_id)
    .bind(machine_id)
    .bind(ai_identity_id)
    .bind(vmid)
    .bind(fps)
    .bind(format)
    .bind(max_duration_secs)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(session_id)
}

pub async fn ensure_open_session(
    pool: &PgPool,
    session_id: Uuid,
    machine_id: Uuid,
    ai_identity_id: Uuid,
) -> ApiResult<()> {
    let _ = sqlx::query(
        "UPDATE proxmox_console_sessions
         SET status = 'expired', closed_at = now()
         WHERE id = $1 AND status = 'open' AND expires_at <= now()",
    )
    .bind(session_id)
    .execute(pool)
    .await;

    let found: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id
         FROM proxmox_console_sessions
         WHERE id = $1
           AND machine_id = $2
           AND ai_identity_id = $3
           AND status = 'open'
           AND expires_at > now()",
    )
    .bind(session_id)
    .bind(machine_id)
    .bind(ai_identity_id)
    .fetch_optional(pool)
    .await?;

    if found.is_none() {
        return Err(ApiError::BadRequest(
            "Proxmox console session not found or not open".into(),
        ));
    }
    Ok(())
}

pub async fn close_session(
    pool: &PgPool,
    session_id: Uuid,
    machine_id: Uuid,
    ai_identity_id: Uuid,
) -> ApiResult<()> {
    let updated = sqlx::query(
        "UPDATE proxmox_console_sessions
         SET status = 'closed', closed_at = now()
         WHERE id = $1
           AND machine_id = $2
           AND ai_identity_id = $3
           AND status = 'open'",
    )
    .bind(session_id)
    .bind(machine_id)
    .bind(ai_identity_id)
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::BadRequest(
            "Proxmox console session not found or already closed".into(),
        ));
    }
    Ok(())
}

pub fn required_session_id(params: &serde_json::Value) -> ApiResult<Uuid> {
    params
        .get("session_id")
        .and_then(|value| value.as_str())
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| ApiError::BadRequest("session_id required".into()))
}
