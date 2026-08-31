//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Password-based backup encryption (AES-256-GCM + Argon2id).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hecate_protocol::backup::{
    BackupKdfParams, BackupManifest, EncryptedBackupEnvelope, BACKUP_ENCRYPTED_FORMAT,
    BACKUP_ENCRYPTED_VERSION,
};
use rand::RngCore;

use crate::error::{ApiError, ApiResult};

const MIN_PASSWORD_LEN: usize = 12;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
const MAX_KDF_M_COST: u32 = 1_048_576; // 1 GiB
const MAX_KDF_T_COST: u32 = 16;
const MAX_KDF_P_COST: u32 = 8;

pub fn validate_backup_password(password: &str) -> ApiResult<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(ApiError::BadRequest(format!(
            "backup password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

pub fn encrypt_backup(manifest: &BackupManifest, password: &str) -> ApiResult<EncryptedBackupEnvelope> {
    validate_backup_password(password)?;

    let plaintext = serde_json::to_vec(manifest)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("serialize manifest: {error}")))?;

    let kdf_params = BackupKdfParams::default();
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(password, &salt, &kdf_params)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("cipher init: {error}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("encrypt backup: {error}")))?;

    Ok(EncryptedBackupEnvelope {
        format: BACKUP_ENCRYPTED_FORMAT.to_string(),
        version: BACKUP_ENCRYPTED_VERSION,
        kdf: "argon2id".into(),
        kdf_params,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
    })
}

pub fn decrypt_backup(envelope: &EncryptedBackupEnvelope, password: &str) -> ApiResult<BackupManifest> {
    if envelope.format != BACKUP_ENCRYPTED_FORMAT {
        return Err(ApiError::BadRequest(
            "invalid backup format: expected encrypted hecate-backup".into(),
        ));
    }
    if envelope.version != BACKUP_ENCRYPTED_VERSION {
        return Err(ApiError::BadRequest(format!(
            "unsupported encrypted backup version: {}",
            envelope.version
        )));
    }
    if envelope.kdf != "argon2id" {
        return Err(ApiError::BadRequest("unsupported backup kdf".into()));
    }

    let salt = BASE64
        .decode(&envelope.salt)
        .map_err(|_| ApiError::BadRequest("invalid backup salt".into()))?;
    let nonce_bytes = BASE64
        .decode(&envelope.nonce)
        .map_err(|_| ApiError::BadRequest("invalid backup nonce".into()))?;
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| ApiError::BadRequest("invalid backup ciphertext".into()))?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(ApiError::BadRequest("invalid backup nonce length".into()));
    }

    let key = derive_key(password, &salt, &envelope.kdf_params)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("cipher init: {error}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| ApiError::BadRequest("backup decryption failed: wrong password or corrupted file".into()))?;

    let manifest: BackupManifest = serde_json::from_slice(&plaintext)
        .map_err(|error| ApiError::BadRequest(format!("invalid backup manifest: {error}")))?;
    if manifest.format != hecate_protocol::backup::BACKUP_FORMAT {
        return Err(ApiError::BadRequest("invalid backup manifest format".into()));
    }
    Ok(manifest)
}

pub fn parse_encrypted_envelope(bytes: &[u8]) -> ApiResult<EncryptedBackupEnvelope> {
    let envelope: EncryptedBackupEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| ApiError::BadRequest(format!("invalid encrypted backup: {error}")))?;
    Ok(envelope)
}

fn derive_key(password: &str, salt: &[u8], params: &BackupKdfParams) -> ApiResult<[u8; KEY_LEN]> {
    if params.m_cost == 0
        || params.t_cost == 0
        || params.p_cost == 0
        || params.m_cost > MAX_KDF_M_COST
        || params.t_cost > MAX_KDF_T_COST
        || params.p_cost > MAX_KDF_P_COST
    {
        return Err(ApiError::BadRequest(
            "backup kdf_params out of allowed range".into(),
        ));
    }
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("argon2 params: {error}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("argon2 derive: {error}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut sections = HashMap::new();
        sections.insert(
            "ai_identities".into(),
            hecate_protocol::backup::BackupSectionData {
                section_format_version: 1,
                data: serde_json::json!([]),
            },
        );
        let manifest = BackupManifest::new(1, sections);
        let envelope = encrypt_backup(&manifest, "secure-password-12").unwrap();
        let restored = decrypt_backup(&envelope, "secure-password-12").unwrap();
        assert_eq!(restored.format, manifest.format);
        assert_eq!(restored.sections.len(), 1);
    }

    #[test]
    fn wrong_password_rejected() {
        let manifest = BackupManifest::new(1, HashMap::new());
        let envelope = encrypt_backup(&manifest, "secure-password-12").unwrap();
        assert!(decrypt_backup(&envelope, "wrong-password-1").is_err());
    }
}
