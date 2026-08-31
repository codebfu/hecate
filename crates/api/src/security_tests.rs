//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Security negative tests (v1 suite).

#[cfg(test)]
mod negative {
    use hecate_protocol::backup::BackupManifest;
    use hecate_protocol::permissions::CapabilityProfileRules;
    use hecate_protocol::policy;
    use hecate_protocol::task::TaskExecutionPolicy;
    use uuid::Uuid;

    use crate::backup_crypto::{decrypt_backup, encrypt_backup};
    use crate::command_dispatch::sign_task_for_command;
    use crate::crypto::{constant_time_eq_hex, constant_time_eq_str};
    use crate::task_crypto::{generate_task_signing_keypair, verify_task_signature};

    #[test]
    fn shell_run_rejects_shell_path() {
        let allowed = vec!["/usr/bin/uptime".into()];
        let argv = vec!["/bin/sh".into(), "-c".into(), "id".into()];
        assert!(policy::check_shell_policy(&argv, &allowed).is_err());
    }

    #[test]
    fn shell_run_rejects_metacharacters() {
        assert!(policy::validate_argv(&["echo".into(), "a;b".into()]).is_err());
    }

    #[test]
    fn deny_all_shell_policy() {
        let rules = CapabilityProfileRules {
            allowed_commands: vec!["shell.run".into()],
            allowed_admin_commands: vec![],
            shell_policy: Default::default(),
            elevation_policy: Default::default(),
            max_output_bytes: hecate_protocol::permissions::DEFAULT_MAX_OUTPUT_BYTES,
            max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
            timeout_secs: hecate_protocol::permissions::DEFAULT_TIMEOUT_SECS,
            max_concurrent: hecate_protocol::permissions::DEFAULT_MAX_CONCURRENT,
        };
        let params = serde_json::json!({ "argv": ["/usr/bin/uptime"] });
        assert!(crate::permissions::validate_shell_params(&params, &rules).is_err());
    }

    #[test]
    fn backup_rejects_invalid_format() {
        let err = crate::backup::parse_manifest(b"{}").unwrap_err();
        assert!(matches!(err, crate::error::ApiError::BadRequest(_)));
    }

    #[test]
    fn backup_upgrade_chain() {
        let mut manifest = BackupManifest::new(1, Default::default());
        manifest.backup_format_version = 0;
        let upgraded = crate::backup::upgrade_backup(manifest).unwrap();
        assert_eq!(
            upgraded.backup_format_version,
            hecate_protocol::backup::BACKUP_FORMAT_VERSION_CURRENT
        );
    }

    #[test]
    fn encrypted_backup_roundtrip_is_portable() {
        let manifest = BackupManifest::new(1, Default::default());
        let envelope = encrypt_backup(&manifest, "secure-password-12").unwrap();
        let restored = decrypt_backup(&envelope, "secure-password-12").unwrap();
        assert_eq!(restored.format, manifest.format);
    }

    #[test]
    fn encrypted_backup_rejects_wrong_password() {
        let manifest = BackupManifest::new(1, Default::default());
        let envelope = encrypt_backup(&manifest, "secure-password-12").unwrap();
        assert!(decrypt_backup(&envelope, "wrong-password-1").is_err());
    }

    #[test]
    fn task_signature_rejects_tampered_task() {
        let (privkey, pubkey) = generate_task_signing_keypair();
        let command_id = Uuid::from_u128(99);
        let params = serde_json::json!({ "argv": ["/usr/bin/uptime"] });
        let policy = TaskExecutionPolicy::default();
        let sig = sign_task_for_command(
            &privkey,
            command_id,
            Uuid::nil(),
            "shell.run",
            &params,
            &policy,
        )
        .unwrap();
        assert!(
            verify_task_signature(
                &pubkey,
                &sig,
                command_id,
                "shell.run",
                &serde_json::json!({ "argv": ["/bin/echo"] }),
                &policy,
            )
            .is_err()
        );
    }

    #[test]
    fn constant_time_helpers_available() {
        assert!(constant_time_eq_str("abc", "abc"));
        assert!(!constant_time_eq_str("abc", "abd"));
        assert!(constant_time_eq_hex("deadbeef", "deadbeef"));
        assert!(!constant_time_eq_hex("deadbeef", "deadbeee"));
    }

    #[test]
    fn encrypted_backup_rejects_tampered_ciphertext() {
        let manifest = BackupManifest::new(1, Default::default());
        let mut envelope = encrypt_backup(&manifest, "secure-password-12").unwrap();
        envelope.ciphertext = "AAAA".into();
        assert!(decrypt_backup(&envelope, "secure-password-12").is_err());
    }

    #[test]
    fn login_lockout_threshold_is_five_attempts() {
        use crate::routes::auth::should_lock_account_after_failure;
        for failed in 0..4 {
            assert!(!should_lock_account_after_failure(failed));
        }
        assert!(should_lock_account_after_failure(4));
    }

    #[test]
    fn nonce_replay_guard_rejects_invalid_nonce_lengths() {
        use crate::agent_auth::validate_nonce_format;
        assert!(validate_nonce_format("").is_err());
        assert!(validate_nonce_format(&"x".repeat(200)).is_err());
    }
}
