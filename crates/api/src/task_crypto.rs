//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Ed25519 task signing helpers for server → agent integrity.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey, Signature, Verifier, VerifyingKey};
use hecate_protocol::task::TaskExecutionPolicy;
use hecate_protocol::task_signing::build_task_canonical_string;
use serde_json::Value;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

pub fn sign_task(
    task_signing_privkey_b64: &str,
    command_id: Uuid,
    command_name: &str,
    params: &Value,
    execution_policy: &TaskExecutionPolicy,
) -> ApiResult<String> {
    let signing_key = load_signing_key(task_signing_privkey_b64)?;
    let params_json = serde_json::to_string(params).unwrap_or_else(|_| "{}".into());
    let policy_json = serde_json::to_string(execution_policy).unwrap_or_else(|_| "{}".into());
    let canonical = build_task_canonical_string(
        &command_id.to_string(),
        command_name,
        &params_json,
        &policy_json,
    );
    let signature = signing_key.sign(canonical.as_bytes());
    Ok(BASE64.encode(signature.to_bytes()))
}

pub fn verify_task_signature(
    task_signing_pubkey_b64: &str,
    server_task_sig_b64: &str,
    command_id: Uuid,
    command_name: &str,
    params: &Value,
    execution_policy: &TaskExecutionPolicy,
) -> Result<(), String> {
    let verifying_key = load_verifying_key(task_signing_pubkey_b64)
        .map_err(|error| error.to_string())?;
    let params_json = serde_json::to_string(params).unwrap_or_else(|_| "{}".into());
    let policy_json = serde_json::to_string(execution_policy).unwrap_or_else(|_| "{}".into());
    let canonical = build_task_canonical_string(
        &command_id.to_string(),
        command_name,
        &params_json,
        &policy_json,
    );
    let sig_bytes = BASE64
        .decode(server_task_sig_b64)
        .map_err(|_| "invalid task signature encoding".to_string())?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid task signature length".to_string())?;
    let signature = Signature::from_bytes(&sig_array);
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| "invalid server task signature".to_string())
}

pub fn generate_task_signing_keypair() -> (String, String) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let privkey = BASE64.encode(signing_key.to_bytes());
    let pubkey = BASE64.encode(signing_key.verifying_key().to_bytes());
    (privkey, pubkey)
}

/// Derive the Ed25519 public key (base64) from a task-signing private seed (base64).
pub fn task_signing_pubkey_from_privkey(privkey_b64: &str) -> ApiResult<String> {
    let signing_key = load_signing_key(privkey_b64)?;
    Ok(BASE64.encode(signing_key.verifying_key().to_bytes()))
}

pub fn sign_raw(privkey_b64: &str, message: &[u8]) -> ApiResult<String> {
    let signing_key = load_signing_key(privkey_b64)?;
    Ok(BASE64.encode(signing_key.sign(message).to_bytes()))
}

pub fn sign_continuity(previous_privkey_b64: &str, previous_pubkey_b64: &str, successor_pubkey_b64: &str) -> ApiResult<String> {
    let message = hecate_protocol::task::continuity_message(previous_pubkey_b64, successor_pubkey_b64);
    sign_raw(previous_privkey_b64, message.as_bytes())
}

/// Verify a continuity attestation signed by `previous_pubkey_b64` over the successor.
pub fn verify_continuity_pubkey(
    previous_pubkey_b64: &str,
    successor_pubkey_b64: &str,
    signature_b64: &str,
) -> ApiResult<()> {
    let verifying_key = load_verifying_key(previous_pubkey_b64)?;
    let sig_bytes = BASE64
        .decode(signature_b64.trim())
        .map_err(|_| ApiError::BadRequest("invalid release continuity signature encoding".into()))?;
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        ApiError::BadRequest("invalid release continuity signature length".into())
    })?;
    let signature = Signature::from_bytes(&sig_array);
    let message =
        hecate_protocol::task::continuity_message(previous_pubkey_b64, successor_pubkey_b64);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| {
            ApiError::BadRequest(
                "release_key_continuity_sig_b64 does not verify under the previous release public key"
                    .into(),
            )
        })
}

fn load_signing_key(privkey_b64: &str) -> ApiResult<SigningKey> {
    if privkey_b64.trim().is_empty() {
        return Err(ApiError::Conflict(
            "agent task signing key is not configured; create a machine-bound re-enrollment token in Machines → agent detail, then run hecate-lampad enroll".into(),
        ));
    }
    let bytes = BASE64
        .decode(privkey_b64)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid task signing private key")))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid task signing private key length")))?;
    Ok(SigningKey::from_bytes(&array))
}

fn load_verifying_key(pubkey_b64: &str) -> ApiResult<VerifyingKey> {
    let bytes = BASE64
        .decode(pubkey_b64)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid task signing public key")))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid task signing public key length")))?;
    VerifyingKey::from_bytes(&array)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid task signing public key")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::permissions::ShellPolicy;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (privkey, pubkey) = generate_task_signing_keypair();
        let command_id = Uuid::from_u128(1);
        let params = serde_json::json!({ "argv": ["/usr/bin/uptime"] });
        let policy = TaskExecutionPolicy {
            allowed_commands: vec!["shell.run".into()],
            shell_policy: ShellPolicy::default(),
            elevation_policy: hecate_protocol::permissions::ElevationPolicy::default(),
            max_output_bytes: 65_536,
            max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
        };
        let sig = sign_task(&privkey, command_id, "shell.run", &params, &policy).unwrap();
        verify_task_signature(&pubkey, &sig, command_id, "shell.run", &params, &policy).unwrap();
    }

    #[test]
    fn pubkey_derives_from_privkey() {
        let (privkey, pubkey) = generate_task_signing_keypair();
        assert_eq!(task_signing_pubkey_from_privkey(&privkey).unwrap(), pubkey);
    }
}
