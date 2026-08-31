//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Canonical request signing format shared by agents and the Hecate API.

use sha2::{Digest, Sha256};

pub const SIGNING_VERSION: &str = "v1";

pub const HEADER_AGENT_ID: &str = "X-Hecate-Agent-Id";
pub const HEADER_TIMESTAMP: &str = "X-Hecate-Timestamp";
pub const HEADER_NONCE: &str = "X-Hecate-Nonce";
pub const HEADER_SIGNATURE: &str = "X-Hecate-Signature";

/// Build the canonical string for agent request signing.
///
/// Format: `v1\n{method}\n{path}\n{sha256(body)}\n{timestamp}\n{nonce}`
pub fn build_canonical_string(
    method: &str,
    path: &str,
    body: &[u8],
    timestamp_ms: i64,
    nonce: &str,
) -> String {
    let body_hash = hex_sha256(body);
    format!(
        "{SIGNING_VERSION}\n{method}\n{path}\n{body_hash}\n{timestamp_ms}\n{nonce}"
    )
}

pub fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_string_format() {
        let body = br#"{"agent_version":"0.1.0"}"#;
        let canonical =
            build_canonical_string("GET", "/api/v1/agent/pull", body, 1_700_000_000_000, "deadbeef");
        let expected_hash = hex_sha256(body);
        assert_eq!(
            canonical,
            format!("v1\nGET\n/api/v1/agent/pull\n{expected_hash}\n1700000000000\ndeadbeef")
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn canonical_string_includes_nonce(
            path in "/[a-z/_]+",
            nonce in "[a-f0-9]{8,32}",
            timestamp in 1_600_000_000_000i64..2_000_000_000_000i64,
        ) {
            let canonical = build_canonical_string("GET", &path, b"body", timestamp, &nonce);
            prop_assert!(canonical.ends_with(&nonce));
            prop_assert!(canonical.starts_with("v1\nGET\n"));
        }
    }
}
