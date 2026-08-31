//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Signed Propylaea proxy request authentication.

use axum::http::HeaderMap;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hecate_protocol::agent_signing::{
    build_canonical_string, HEADER_AGENT_ID, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedProxy {
    pub proxy_id: Uuid,
}

pub async fn verify_proxy_request(
    pool: &PgPool,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &HeaderMap,
) -> ApiResult<AuthenticatedProxy> {
    let proxy_id = parse_proxy_id_header(headers)?;
    let timestamp_ms = parse_timestamp_header(headers)?;
    let nonce = required_header(headers, HEADER_NONCE)?;
    let signature = required_header(headers, HEADER_SIGNATURE)?;

    validate_timestamp(timestamp_ms)?;

    let row: Option<(String, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT credential_pubkey, state::text,
                    credential_pubkey_previous,
                    credential_pubkey_previous_expires_at
             FROM proxies WHERE id = $1",
        )
        .bind(proxy_id)
        .fetch_optional(pool)
        .await?;

    let Some((public_key, state, previous_key, previous_expires)) = row else {
        return Err(ApiError::Unauthorized);
    };

    if state == "revoked" {
        return Err(ApiError::Forbidden);
    }

    let canonical = build_canonical_string(method, path, body, timestamp_ms, &nonce);
    let verified = verify_signature(&public_key, &canonical, &signature).is_ok()
        || previous_key.as_ref().is_some_and(|prev| {
            previous_expires.is_some_and(|expires| expires > chrono::Utc::now())
                && !prev.trim().is_empty()
                && verify_signature(prev, &canonical, &signature).is_ok()
        });

    if !verified {
        return Err(ApiError::Unauthorized);
    }

    record_nonce(pool, proxy_id, &nonce).await?;

    Ok(AuthenticatedProxy { proxy_id })
}

async fn record_nonce(pool: &PgPool, proxy_id: Uuid, nonce: &str) -> ApiResult<()> {
    if nonce.is_empty() || nonce.len() > 128 {
        return Err(ApiError::Unauthorized);
    }

    let expires_at = chrono::Utc::now() + chrono::Duration::milliseconds(MAX_CLOCK_SKEW_MS);

    let _ = sqlx::query("DELETE FROM proxy_nonce_cache WHERE expires_at <= now()")
        .execute(pool)
        .await;

    let inserted = sqlx::query(
        "INSERT INTO proxy_nonce_cache (proxy_id, nonce, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (proxy_id, nonce) DO NOTHING",
    )
    .bind(proxy_id)
    .bind(nonce)
    .bind(expires_at)
    .execute(pool)
    .await?;

    if inserted.rows_affected() == 0 {
        return Err(ApiError::Unauthorized);
    }

    Ok(())
}

fn parse_proxy_id_header(headers: &HeaderMap) -> ApiResult<Uuid> {
    let value = required_header(headers, HEADER_AGENT_ID)?;
    value
        .parse::<Uuid>()
        .map_err(|_| ApiError::Unauthorized)
}

fn parse_timestamp_header(headers: &HeaderMap) -> ApiResult<i64> {
    let value = required_header(headers, HEADER_TIMESTAMP)?;
    value
        .parse::<i64>()
        .map_err(|_| ApiError::Unauthorized)
}

fn required_header(headers: &HeaderMap, name: &str) -> ApiResult<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or(ApiError::Unauthorized)
}

fn validate_timestamp(timestamp_ms: i64) -> ApiResult<()> {
    let now = chrono::Utc::now().timestamp_millis();
    if (now - timestamp_ms).abs() > MAX_CLOCK_SKEW_MS {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

fn verify_signature(public_key_b64: &str, canonical: &str, signature_b64: &str) -> ApiResult<()> {
    let pk_bytes = BASE64
        .decode(public_key_b64)
        .map_err(|_| ApiError::Unauthorized)?;
    let pk_array: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Unauthorized)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).map_err(|_| ApiError::Unauthorized)?;

    let sig_bytes = BASE64
        .decode(signature_b64)
        .map_err(|_| ApiError::Unauthorized)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Unauthorized)?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| ApiError::Unauthorized)?;

    Ok(())
}
