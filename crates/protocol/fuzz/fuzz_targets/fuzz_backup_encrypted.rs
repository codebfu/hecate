//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

#![no_main]

use libfuzzer_sys::fuzz_target;
use hecate_protocol::backup::{EncryptedBackupEnvelope, BACKUP_ENCRYPTED_FORMAT};

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = serde_json::from_slice::<EncryptedBackupEnvelope>(data) {
        if envelope.format == BACKUP_ENCRYPTED_FORMAT {
            let _ = envelope.version;
            let _ = envelope.kdf.as_str();
            let _ = envelope.salt.len();
            let _ = envelope.nonce.len();
            let _ = envelope.ciphertext.len();
        }
    }
});
