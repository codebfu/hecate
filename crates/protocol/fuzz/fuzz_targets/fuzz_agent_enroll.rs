//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

#![no_main]

use libfuzzer_sys::fuzz_target;
use hecate_protocol::agent::EnrollRequest;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<EnrollRequest>(data) {
        let _ = value.enrollment_token.len();
        let _ = value.public_key.len();
        let _ = value.hostname.len();
        let _ = value.os.len();
        let _ = value.arch.len();
        let _ = value.tags.len();
    }
});
