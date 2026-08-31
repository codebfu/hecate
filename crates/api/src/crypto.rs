//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use rand::RngCore;

type HmacSha256 = Hmac<Sha256>;

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn hmac_sha256_hex(key: &str, data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("hmac key");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::Argon2;
    let salt = SaltString::generate(&mut rand::thread_rng());
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))?
        .to_string())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;
    PasswordHash::new(hash)
        .ok()
        .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    constant_time_eq_str(a, b)
}

pub fn audit_entry_hash(prev: &str, actor: &str, action: &str, target: &str, payload_hash: &str, ts: &str) -> String {
    let body = format!("{prev}|{actor}|{action}|{target}|{payload_hash}|{ts}");
    sha256_hex(body.as_bytes())
}

const ENVELOPE_PREFIX: &str = "enc:v1:";
const DEFAULT_KEY_ID: &str = "k1";

/// Envelope-encrypt a task-signing private key. Format: `enc:v1:<key_id>:<nonce_b64>:<ct_b64>`.
pub fn wrap_task_signing_privkey(plaintext_b64: &str) -> anyhow::Result<String> {
    if plaintext_b64.starts_with(ENVELOPE_PREFIX) {
        return Ok(plaintext_b64.to_string());
    }
    let (key_id, key) = load_master_key()?;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("task signing master key: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("wrap task signing key: {e}"))?;
    Ok(format!(
        "{ENVELOPE_PREFIX}{key_id}:{}:{}",
        BASE64.encode(nonce_bytes),
        BASE64.encode(ct)
    ))
}

/// Decrypt an envelope-encrypted task-signing private key.
pub fn unwrap_task_signing_privkey(stored: &str) -> anyhow::Result<String> {
    let Some(rest) = stored.strip_prefix(ENVELOPE_PREFIX) else {
        anyhow::bail!("task signing private key must be envelope-encrypted (enc:v1:)");
    };
    let mut parts = rest.splitn(3, ':');
    let key_id = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("malformed wrapped task signing key"))?;
    let nonce_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("malformed wrapped task signing key"))?;
    let ct_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("malformed wrapped task signing key"))?;
    let (loaded_id, key) = load_master_key()?;
    if loaded_id != key_id {
        anyhow::bail!("task signing master key id mismatch (have {loaded_id}, need {key_id})");
    }
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let nonce = BASE64
        .decode(nonce_b64)
        .map_err(|_| anyhow::anyhow!("invalid wrapped key nonce"))?;
    let ct = BASE64
        .decode(ct_b64)
        .map_err(|_| anyhow::anyhow!("invalid wrapped key ciphertext"))?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("task signing master key: {e}"))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| anyhow::anyhow!("unwrap task signing key failed"))?;
    String::from_utf8(pt).map_err(|_| anyhow::anyhow!("unwrapped key is not utf8"))
}

fn load_master_key() -> anyhow::Result<(String, [u8; 32])> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let raw = std::env::var("HECATE_TASK_SIGNING_MASTER_KEY").map_err(|_| {
        anyhow::anyhow!("HECATE_TASK_SIGNING_MASTER_KEY is required to protect task signing keys")
    })?;
    let raw = raw.trim();
    let (key_id, material) = raw
        .split_once(':')
        .map(|(id, rest)| (id.to_string(), rest))
        .unwrap_or_else(|| (DEFAULT_KEY_ID.to_string(), raw));
    let bytes = if let Ok(hex_bytes) = hex::decode(material) {
        hex_bytes
    } else {
        BASE64
            .decode(material)
            .map_err(|_| anyhow::anyhow!("HECATE_TASK_SIGNING_MASTER_KEY must be 32-byte hex or base64"))?
    };
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("HECATE_TASK_SIGNING_MASTER_KEY must be 32 bytes"))?;
    Ok((key_id, array))
}

#[cfg(test)]
mod tests {
    #[test]
    fn wrap_roundtrip_with_master_key() {
        unsafe {
            std::env::set_var(
                "HECATE_TASK_SIGNING_MASTER_KEY",
                format!("k1:{}", "00".repeat(32)),
            );
        }
        let wrapped = super::wrap_task_signing_privkey("dGVzdA==").unwrap();
        assert!(wrapped.starts_with("enc:v1:k1:"));
        assert_eq!(
            super::unwrap_task_signing_privkey(&wrapped).unwrap(),
            "dGVzdA=="
        );
        assert!(super::unwrap_task_signing_privkey("legacy-plaintext").is_err());
    }
}
