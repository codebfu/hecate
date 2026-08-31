//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::HeaderMap;
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::session::{self, OperatorSession};
use crate::state::AppState;

pub struct OperatorCtx {
    pub session: OperatorSession,
}

pub struct AdminCtx {
    pub session: OperatorSession,
}

pub async fn require_operator(state: &AppState, jar: &CookieJar) -> ApiResult<OperatorCtx> {
    let session = session::require_session(state, jar).await?;
    ensure_onboarded(&session)?;
    Ok(OperatorCtx { session })
}

pub async fn require_admin_read(state: &AppState, jar: &CookieJar) -> ApiResult<AdminCtx> {
    let session = session::require_session(state, jar).await?;
    ensure_onboarded(&session)?;
    if session.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    Ok(AdminCtx { session })
}

pub async fn require_admin(state: &AppState, jar: &CookieJar, headers: &HeaderMap) -> ApiResult<AdminCtx> {
    let admin = require_admin_read(state, jar).await?;
    verify_csrf_header(state, admin.session.session_id, headers).await?;
    Ok(admin)
}

pub async fn require_operator_write(
    state: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
) -> ApiResult<OperatorCtx> {
    let ctx = require_operator(state, jar).await?;
    verify_csrf_header(state, ctx.session.session_id, headers).await?;
    Ok(ctx)
}

async fn verify_csrf_header(
    state: &AppState,
    session_id: Uuid,
    headers: &HeaderMap,
) -> ApiResult<()> {
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Forbidden)?;
    session::verify_csrf(&state.config, &state.pool, session_id, csrf).await
}

fn ensure_onboarded(session: &OperatorSession) -> ApiResult<()> {
    if !session.onboarding_complete {
        return Err(ApiError::Forbidden);
    }
    if session.auth_stage != "full" {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}
