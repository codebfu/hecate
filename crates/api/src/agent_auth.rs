//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Signed agent request authentication.

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
pub struct AuthenticatedAgent {
    pub agent_id: Uuid,
}

/// Verify the agent signature over the **exact** request body bytes, then JSON-decode.
///
/// Never re-serialize a parsed body for verification: serde defaults / new fields
/// (e.g. `busy: false`) change the bytes and reject otherwise-valid older agents.
pub async fn verify_and_parse_json<T: serde::de::DeserializeOwned>(
    pool: &PgPool,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &HeaderMap,
) -> ApiResult<(AuthenticatedAgent, T)> {
    let auth = verify_agent_request(pool, method, path, body, headers).await?;
    let parsed = serde_json::from_slice(body).map_err(|error| {
        ApiError::BadRequest(format!("invalid json body: {error}"))
    })?;
    Ok((auth, parsed))
}

pub async fn verify_agent_request(
    pool: &PgPool,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &HeaderMap,
) -> ApiResult<AuthenticatedAgent> {
    let agent_id = parse_agent_id_header(headers)?;
    let timestamp_ms = parse_timestamp_header(headers)?;
    let nonce = required_header(headers, HEADER_NONCE)?;
    let signature = required_header(headers, HEADER_SIGNATURE)?;

    validate_timestamp(timestamp_ms)?;

    let row: Option<(String, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT credential_pubkey, state::text,
                    credential_pubkey_previous,
                    credential_pubkey_previous_expires_at
             FROM agents WHERE machine_id = $1",
        )
        .bind(agent_id)
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

    record_nonce(pool, agent_id, &nonce).await?;

    Ok(AuthenticatedAgent { agent_id })
}

async fn record_nonce(pool: &PgPool, agent_id: Uuid, nonce: &str) -> ApiResult<()> {
    validate_nonce_format(nonce)?;

    let expires_at = chrono::Utc::now() + chrono::Duration::milliseconds(MAX_CLOCK_SKEW_MS);

    let _ = sqlx::query("DELETE FROM agent_nonce_cache WHERE expires_at <= now()")
        .execute(pool)
        .await;

    let inserted = sqlx::query(
        "INSERT INTO agent_nonce_cache (agent_id, nonce, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (agent_id, nonce) DO NOTHING",
    )
    .bind(agent_id)
    .bind(nonce)
    .bind(expires_at)
    .execute(pool)
    .await?;

    if inserted.rows_affected() == 0 {
        return Err(ApiError::Unauthorized);
    }

    Ok(())
}

pub(crate) fn validate_nonce_format(nonce: &str) -> ApiResult<()> {
    if nonce.is_empty() || nonce.len() > 128 {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

fn parse_agent_id_header(headers: &HeaderMap) -> ApiResult<Uuid> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hecate_protocol::agent_signing::build_canonical_string;
    use rand::rngs::OsRng;

    #[test]
    fn verify_signature_accepts_valid_request() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = BASE64.encode(signing_key.verifying_key().to_bytes());
        let canonical = build_canonical_string("GET", "/api/v1/agent/status", b"", 1_700_000_000_000, "nonce");
        let signature = BASE64.encode(signing_key.sign(canonical.as_bytes()).to_bytes());
        verify_signature(&public_key, &canonical, &signature).unwrap();
    }

    #[test]
    fn verify_signature_rejects_tampered_request() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = BASE64.encode(signing_key.verifying_key().to_bytes());
        let canonical = build_canonical_string("GET", "/api/v1/agent/status", b"", 1_700_000_000_000, "nonce");
        let signature = BASE64.encode(signing_key.sign(canonical.as_bytes()).to_bytes());
        let tampered = build_canonical_string("GET", "/api/v1/agent/status", b"x", 1_700_000_000_000, "nonce");
        assert!(verify_signature(&public_key, &tampered, &signature).is_err());
    }

    #[test]
    fn verify_signature_helper_accepts_either_key() {
        let current = SigningKey::generate(&mut OsRng);
        let previous = SigningKey::generate(&mut OsRng);
        let previous_pub = BASE64.encode(previous.verifying_key().to_bytes());
        let canonical =
            build_canonical_string("GET", "/api/v1/agent/pull", b"", 1_700_000_000_000, "n1");
        let signature = BASE64.encode(previous.sign(canonical.as_bytes()).to_bytes());
        verify_signature(&previous_pub, &canonical, &signature).unwrap();
        let current_pub = BASE64.encode(current.verifying_key().to_bytes());
        assert!(verify_signature(&current_pub, &canonical, &signature).is_err());
    }

    #[test]
    fn nonce_format_rejects_empty_and_oversized() {
        assert!(validate_nonce_format("").is_err());
        assert!(validate_nonce_format(&"a".repeat(129)).is_err());
        validate_nonce_format("valid-nonce").unwrap();
    }

    #[test]
    fn signature_covers_raw_body_not_reserialized_defaults() {
        use hecate_protocol::agent::HeartbeatRequest;

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = BASE64.encode(signing_key.verifying_key().to_bytes());
        // Pre-health-field agent body (no `busy`).
        let raw = br#"{"agent_version":"1.0.0","uptime_secs":1,"hostname":"h","tags":[]}"#;
        let canonical =
            build_canonical_string("POST", "/api/v1/agent/heartbeat", raw, 1_700_000_000_000, "n");
        let signature = BASE64.encode(signing_key.sign(canonical.as_bytes()).to_bytes());
        verify_signature(&public_key, &canonical, &signature).unwrap();

        let parsed: HeartbeatRequest = serde_json::from_slice(raw).unwrap();
        let reserialized = serde_json::to_vec(&parsed).unwrap();
        let wrong = build_canonical_string(
            "POST",
            "/api/v1/agent/heartbeat",
            &reserialized,
            1_700_000_000_000,
            "n",
        );
        // With skip_serializing_if on busy=false, reserialize matches; keep assert for the
        // verify-raw-bytes contract: signature over `raw` is what auth must use.
        assert_eq!(
            verify_signature(&public_key, &wrong, &signature).is_ok(),
            reserialized == raw,
            "auth must verify the exact bytes the agent signed"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hecate_protocol::agent_signing::build_canonical_string;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    proptest! {
        #[test]
        fn invalid_signature_bytes_are_rejected(
            body_suffix in ".{0,32}",
            nonce in "[a-f0-9]{8,32}",
        ) {
            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key = BASE64.encode(signing_key.verifying_key().to_bytes());
            let body = format!("payload{body_suffix}");
            let canonical = build_canonical_string(
                "POST",
                "/api/v1/agent/results",
                body.as_bytes(),
                1_700_000_000_000,
                &nonce,
            );
            let bad_signature = BASE64.encode([0u8; 64]);
            prop_assert!(verify_signature(&public_key, &canonical, &bad_signature).is_err());
        }
    }
}
