//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use rand::RngCore;
use time::Duration as CookieDuration;
use uuid::Uuid;

use crate::crypto::hmac_sha256_hex;
use crate::error::{ApiError, ApiResult};
use crate::state::{AppConfig, AppState};

pub const SESSION_COOKIE: &str = "hecate_session";

const SESSION_TTL_DAYS: i64 = 7;

#[derive(Clone, Debug)]
pub struct OperatorSession {
    pub session_id: Uuid,
    pub operator_id: Uuid,
    pub login: String,
    pub role: String,
    pub onboarding_complete: bool,
    pub must_change_password: bool,
    pub auth_stage: String,
}

pub fn cookie_secure(config: &AppConfig) -> bool {
    config.rp_origin.starts_with("https://")
}

pub fn parse_session_cookie(jar: &CookieJar) -> Option<Uuid> {
    jar.get(SESSION_COOKIE)
        .and_then(|cookie| Uuid::parse_str(cookie.value()).ok())
}

pub fn attach_session_cookie(jar: CookieJar, session_id: Uuid, secure: bool) -> CookieJar {
    let mut builder = Cookie::build((SESSION_COOKIE, session_id.to_string()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::days(SESSION_TTL_DAYS));

    if secure {
        builder = builder.secure(true);
    }

    jar.add(builder.build())
}

pub fn clear_session_cookie(jar: CookieJar) -> CookieJar {
    jar.remove(
        Cookie::build((SESSION_COOKIE, ""))
            .path("/")
            .max_age(CookieDuration::seconds(0))
            .build(),
    )
}

fn new_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub async fn create_session(
    pool: &sqlx::PgPool,
    config: &AppConfig,
    operator_id: Uuid,
    auth_stage: &str,
) -> ApiResult<(Uuid, String)> {
    let session_id = Uuid::new_v4();
    let csrf_token = new_csrf_token();
    let csrf_hash = hmac_sha256_hex(&config.session_secret, &csrf_token);
    let expires_at = Utc::now() + Duration::days(SESSION_TTL_DAYS);

    sqlx::query(
        "INSERT INTO operator_sessions (session_id, operator_id, expires_at, csrf_token_hash, auth_stage)
         VALUES ($1, $2, $3, $4, $5::auth_stage)",
    )
    .bind(session_id)
    .bind(operator_id)
    .bind(expires_at)
    .bind(csrf_hash)
    .bind(auth_stage)
    .execute(pool)
    .await?;

    Ok((session_id, csrf_token))
}

pub async fn load_session(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> ApiResult<Option<OperatorSession>> {
    let row: Option<(Uuid, Uuid, String, String, bool, bool, String)> = sqlx::query_as(
        "SELECT s.session_id, o.id, o.login, o.role::text, o.onboarding_complete, o.must_change_password,
                s.auth_stage::text
         FROM operator_sessions s
         JOIN operators o ON o.id = s.operator_id
         WHERE s.session_id = $1 AND s.expires_at > now() AND o.disabled_at IS NULL",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(
        |(session_id, operator_id, login, role, onboarding_complete, must_change_password, auth_stage)| {
            OperatorSession {
                session_id,
                operator_id,
                login,
                role,
                onboarding_complete,
                must_change_password,
                auth_stage,
            }
        },
    ))
}

pub async fn optional_session(state: &AppState, jar: &CookieJar) -> ApiResult<Option<OperatorSession>> {
    let Some(session_id) = parse_session_cookie(jar) else {
        return Ok(None);
    };
    load_session(&state.pool, session_id).await
}

pub async fn require_session(state: &AppState, jar: &CookieJar) -> ApiResult<OperatorSession> {
    optional_session(state, jar)
        .await?
        .ok_or(ApiError::Unauthorized)
}

pub async fn delete_session(pool: &sqlx::PgPool, session_id: Uuid) -> ApiResult<()> {
    sqlx::query("DELETE FROM operator_sessions WHERE session_id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn verify_csrf(
    config: &AppConfig,
    pool: &sqlx::PgPool,
    session_id: Uuid,
    token: &str,
) -> ApiResult<()> {
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT csrf_token_hash FROM operator_sessions WHERE session_id = $1 AND expires_at > now()",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;
    let stored = stored.ok_or(ApiError::Unauthorized)?;
    let expected = hmac_sha256_hex(&config.session_secret, token);
    if !crate::crypto::constant_time_eq_hex(&stored, &expected) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub async fn upgrade_auth_stage(pool: &sqlx::PgPool, session_id: Uuid) -> ApiResult<()> {
    let updated = sqlx::query(
        "UPDATE operator_sessions SET auth_stage = 'full'::auth_stage
         WHERE session_id = $1 AND expires_at > now()",
    )
    .bind(session_id)
    .execute(pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

pub async fn rotate_csrf_token(
    pool: &sqlx::PgPool,
    config: &AppConfig,
    session_id: Uuid,
) -> ApiResult<String> {
    let csrf_token = new_csrf_token();
    let csrf_hash = hmac_sha256_hex(&config.session_secret, &csrf_token);
    let updated = sqlx::query(
        "UPDATE operator_sessions SET csrf_token_hash = $1 WHERE session_id = $2 AND expires_at > now()",
    )
    .bind(&csrf_hash)
    .bind(session_id)
    .execute(pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::Unauthorized);
    }
    Ok(csrf_token)
}
