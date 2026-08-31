//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

#![no_main]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use libfuzzer_sys::fuzz_target;
use hecate_protocol::agent_signing::build_canonical_string;

fuzz_target!(|data: &[u8]| {
    let method = if data.first().copied().unwrap_or(0) % 2 == 0 {
        "GET"
    } else {
        "POST"
    };
    let path = if data.len() > 1 {
        std::str::from_utf8(&data[1..]).unwrap_or("/api/v1/agent/pull")
    } else {
        "/api/v1/agent/pull"
    };
    let timestamp = i64::from_le_bytes(data.get(0..8).and_then(|s| s.try_into().ok()).unwrap_or([0; 8]));
    let nonce = BASE64.encode(data);
    let canonical = build_canonical_string(method, path, data, timestamp, &nonce);
    assert!(canonical.starts_with("v1\n"));
    assert!(canonical.contains(path) || path.is_empty());
});
