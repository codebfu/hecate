//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Canonical task signing format for server → agent task integrity.

use sha2::{Digest, Sha256};

pub const TASK_SIGNING_VERSION: &str = "canonical_task_v1";

pub fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the canonical string for server task signing.
///
/// Format: `canonical_task_v1\n{command_id}\n{command_name}\n{sha256(params)}\n{sha256(policy)}`
pub fn build_task_canonical_string(
    command_id: &str,
    command_name: &str,
    params_json: &str,
    policy_json: &str,
) -> String {
    let params_hash = hex_sha256(params_json.as_bytes());
    let policy_hash = hex_sha256(policy_json.as_bytes());
    format!(
        "{TASK_SIGNING_VERSION}\n{command_id}\n{command_name}\n{params_hash}\n{policy_hash}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_canonical_is_deterministic() {
        let first = build_task_canonical_string(
            "00000000-0000-0000-0000-000000000001",
            "shell.run",
            r#"{"argv":["/usr/bin/uptime"]}"#,
            r#"{"allowed_commands":["shell.run"]}"#,
        );
        let second = build_task_canonical_string(
            "00000000-0000-0000-0000-000000000001",
            "shell.run",
            r#"{"argv":["/usr/bin/uptime"]}"#,
            r#"{"allowed_commands":["shell.run"]}"#,
        );
        assert_eq!(first, second);
        assert!(first.starts_with("canonical_task_v1\n"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn task_canonical_is_stable(
            command_id in "[0-9a-f-]{36}",
            command_name in "[a-z._-]+",
            params in r#"\{.*\}"#,
            policy in r#"\{.*\}"#,
        ) {
            let first = build_task_canonical_string(&command_id, &command_name, &params, &policy);
            let second = build_task_canonical_string(&command_id, &command_name, &params, &policy);
            prop_assert!(first.starts_with("canonical_task_v1\n"));
            prop_assert_eq!(first, second);
        }
    }
}
