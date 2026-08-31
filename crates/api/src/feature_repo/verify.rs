//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{ApiError, ApiResult};

use super::types::Release;

pub fn verify_file_signature(
    public_key_b64: &str,
    file_bytes: &[u8],
    signature_bytes: &[u8],
) -> ApiResult<()> {
    let key_bytes = BASE64
        .decode(public_key_b64.trim())
        .map_err(|_| ApiError::BadRequest("repository public key is not valid base64".into()))?;
    let key = VerifyingKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::BadRequest("repository public key must be 32 bytes".into()))?,
    )
    .map_err(|_| ApiError::BadRequest("repository public key is invalid".into()))?;
    let signature = Signature::from_bytes(
        signature_bytes
            .try_into()
            .map_err(|_| ApiError::BadRequest("repository signature must be 64 bytes".into()))?,
    );
    key.verify(file_bytes, &signature)
        .map_err(|_| ApiError::BadRequest("repository signature verification failed".into()))
}

pub fn verify_release_file(release: &Release, path: &str, file_bytes: &[u8]) -> ApiResult<()> {
    let entry = release
        .checksum(path)
        .ok_or_else(|| ApiError::BadRequest(format!("{path} is not listed in Release")))?;
    if entry.size != file_bytes.len() as u64 {
        return Err(ApiError::BadRequest(format!(
            "{path} size does not match Release"
        )));
    }
    let actual = hex_sha256(file_bytes);
    if actual != entry.sha256 {
        return Err(ApiError::BadRequest(format!(
            "{path} SHA256 does not match Release"
        )));
    }
    Ok(())
}

pub fn verify_sha256(expected: &str, bytes: &[u8]) -> ApiResult<()> {
    if hex_sha256(bytes) != expected.trim().to_ascii_lowercase() {
        return Err(ApiError::BadRequest("artifact SHA256 mismatch".into()));
    }
    Ok(())
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn verifies_raw_ed25519_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let bytes = b"signed repository bytes";
        let signature = signing_key.sign(bytes);
        let public_key = BASE64.encode(signing_key.verifying_key().to_bytes());
        verify_file_signature(&public_key, bytes, &signature.to_bytes()).expect("valid signature");
        assert!(verify_file_signature(&public_key, b"changed", &signature.to_bytes()).is_err());
    }
}
