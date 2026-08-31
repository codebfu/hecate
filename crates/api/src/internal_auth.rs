//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::HeaderMap;
use uuid::Uuid;

use crate::crypto::{constant_time_eq_str, hmac_sha256_hex};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub async fn verify_internal_token(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<Uuid> {
    let token = headers
        .get("x-internal-token")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    if !constant_time_eq_str(token, &state.config.internal_token) {
        return Err(ApiError::Unauthorized);
    }
    let api_key = headers
        .get("x-ai-api-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    let key_hmac = hmac_sha256_hex(&state.config.api_key_pepper, api_key);
    let identity_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT k.ai_identity_id
         FROM ai_api_keys k
         JOIN ai_identities i ON i.id = k.ai_identity_id
         WHERE k.key_hmac = $1
           AND k.revoked_at IS NULL
           AND i.deleted_at IS NULL
           AND i.active = true",
    )
    .bind(&key_hmac)
    .fetch_optional(&state.pool)
    .await?;
    identity_id.ok_or(ApiError::Unauthorized)
}
