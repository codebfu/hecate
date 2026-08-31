//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shared enrollment / re-enroll request validation.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hecate_protocol::agent::EnrollRequest;
use hecate_protocol::proxy::ProxyEnrollRequest;
use uuid::Uuid;

use crate::crypto::sha256_hex;
use crate::error::{ApiError, ApiResult};

pub const AGENT_TOKEN_PREFIX: &str = "enr_";
pub const PROXY_TOKEN_PREFIX: &str = "penr_";

pub fn validate_agent_enrollment_token(token: &str) -> ApiResult<()> {
    validate_token_format(token, AGENT_TOKEN_PREFIX)
}

pub fn validate_proxy_enrollment_token(token: &str) -> ApiResult<()> {
    validate_token_format(token, PROXY_TOKEN_PREFIX)
}

fn validate_token_format(token: &str, prefix: &str) -> ApiResult<()> {
    if !token.starts_with(prefix) {
        return Err(ApiError::Unauthorized);
    }
    let hex_part = &token[prefix.len()..];
    if hex_part.len() != 48 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

pub fn validate_ed25519_public_key_b64(public_key: &str) -> ApiResult<()> {
    let trimmed = public_key.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("public_key is required".into()));
    }
    let pk_bytes = BASE64
        .decode(trimmed)
        .map_err(|_| ApiError::BadRequest("public_key must be valid base64".into()))?;
    if pk_bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "public_key must be a 32-byte Ed25519 key".into(),
        ));
    }
    Ok(())
}

pub fn validate_agent_enroll_body(body: &EnrollRequest) -> ApiResult<()> {
    validate_agent_enrollment_token(&body.enrollment_token)?;
    validate_ed25519_public_key_b64(&body.public_key)?;
    if body.hostname.trim().is_empty() {
        return Err(ApiError::BadRequest("hostname is required".into()));
    }
    if body.os.trim().is_empty() {
        return Err(ApiError::BadRequest("os is required".into()));
    }
    if body.arch.trim().is_empty() {
        return Err(ApiError::BadRequest("arch is required".into()));
    }
    Ok(())
}

pub fn validate_proxy_enroll_body(body: &ProxyEnrollRequest) -> ApiResult<()> {
    validate_proxy_enrollment_token(&body.enrollment_token)?;
    validate_ed25519_public_key_b64(&body.public_key)?;
    if body.hostname.trim().is_empty() {
        return Err(ApiError::BadRequest("hostname is required".into()));
    }
    if body.version.trim().is_empty() {
        return Err(ApiError::BadRequest("version is required".into()));
    }
    Ok(())
}

/// When a token is bound to an entity, an optional client id must match exactly.
pub fn ensure_bound_id_matches(
    bound_id: Uuid,
    client_id: Option<Uuid>,
    field: &str,
) -> ApiResult<()> {
    if let Some(client_id) = client_id {
        if client_id != bound_id {
            return Err(ApiError::BadRequest(format!(
                "{field} does not match the bound enrollment token"
            )));
        }
    }
    Ok(())
}

/// Fresh enroll tokens must not carry a target entity id.
pub fn reject_client_id_for_fresh_enroll(client_id: Option<Uuid>, field: &str) -> ApiResult<()> {
    if client_id.is_some() {
        return Err(ApiError::BadRequest(format!(
            "{field} must not be set for a generic enrollment token"
        )));
    }
    Ok(())
}

pub fn public_key_fingerprint(public_key_b64: &str) -> String {
    sha256_hex(public_key_b64.trim().as_bytes())[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_token_format() {
        let ok = format!("enr_{}", "a".repeat(48));
        assert!(validate_agent_enrollment_token(&ok).is_ok());
        assert!(validate_agent_enrollment_token("bad_token").is_err());
    }

    #[test]
    fn bound_id_mismatch_rejected() {
        let bound = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert!(ensure_bound_id_matches(bound, Some(other), "agent_id").is_err());
        assert!(ensure_bound_id_matches(bound, Some(bound), "agent_id").is_ok());
        assert!(ensure_bound_id_matches(bound, None, "agent_id").is_ok());
    }

    #[test]
    fn fresh_enroll_rejects_client_id() {
        assert!(reject_client_id_for_fresh_enroll(Some(Uuid::new_v4()), "agent_id").is_err());
        assert!(reject_client_id_for_fresh_enroll(None, "agent_id").is_ok());
    }
}
