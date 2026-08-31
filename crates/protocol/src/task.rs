//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::permissions::{ElevationPolicy, ShellPolicy, DEFAULT_MAX_OUTPUT_BYTES};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskExecutionPolicy {
    pub allowed_commands: Vec<String>,
    pub shell_policy: ShellPolicy,
    pub elevation_policy: ElevationPolicy,
    pub max_output_bytes: u32,
    pub max_file_bytes: u32,
}

impl Default for TaskExecutionPolicy {
    fn default() -> Self {
        Self {
            allowed_commands: vec!["system.info".into()],
            shell_policy: ShellPolicy::default(),
            elevation_policy: ElevationPolicy::default(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_file_bytes: crate::permissions::DEFAULT_MAX_FILE_BYTES,
        }
    }
}

use crate::authz::CapabilityProfile;

impl From<CapabilityProfile> for TaskExecutionPolicy {
    fn from(profile: CapabilityProfile) -> Self {
        Self {
            allowed_commands: profile.allowed_commands,
            shell_policy: profile.shell_policy,
            elevation_policy: profile.elevation_policy,
            max_output_bytes: profile.max_output_bytes,
            max_file_bytes: profile.max_file_bytes,
        }
    }
}

impl From<&CapabilityProfile> for TaskExecutionPolicy {
    fn from(profile: &CapabilityProfile) -> Self {
        profile.clone().into()
    }
}

impl From<crate::permissions::AiPermissionRules> for TaskExecutionPolicy {
    fn from(rules: crate::permissions::AiPermissionRules) -> Self {
        Self {
            allowed_commands: rules.allowed_commands,
            shell_policy: rules.shell_policy,
            elevation_policy: rules.elevation_policy,
            max_output_bytes: rules.max_output_bytes,
            max_file_bytes: rules.max_file_bytes,
        }
    }
}

impl From<&crate::permissions::AiPermissionRules> for TaskExecutionPolicy {
    fn from(rules: &crate::permissions::AiPermissionRules) -> Self {
        rules.clone().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentTask {
    ExecuteCommand {
        command_id: Uuid,
        command_name: String,
        params: serde_json::Value,
        timeout_secs: u32,
        execution_policy: TaskExecutionPolicy,
        server_task_sig: String,
    },
    SelfUpdate {
        target_version: String,
        artifact_path: String,
        sha256: String,
        signature: String,
        /// Ed25519 public key for release signature verification (server-provided).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        release_public_key_b64: Option<String>,
        server_task_sig: String,
    },
        NoOp,
}

pub fn self_update_sign_params(
    kind: &str,
    artifact_path: &str,
    sha256: &str,
    target_version: &str,
) -> serde_json::Value {
    serde_json::json!({
        "artifact_path": artifact_path,
        "kind": kind,
        "sha256": sha256,
        "target_version": target_version,
    })
}

/// Dual-key material advertised on every pull (and update-offer) during rotation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct KeyMaterialPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_signing_pubkey_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_signing_pubkey_previous_b64: Option<String>,
    /// RFC3339 timestamp; omit when no previous task-signing key is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_signing_overlap_until: Option<String>,
    /// Ed25519 signature by the previous (current-on-agent) key over the successor pubkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_signing_continuity_sig_b64: Option<String>,
    /// Extra continuity proofs (oldest first) so an agent that missed rotations can catch up.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub task_signing_continuity_chain: Vec<KeyContinuityAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_public_key_previous_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_key_overlap_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_key_continuity_sig_b64: Option<String>,
    /// When true, the agent must mint a new identity keypair and call credentials/rotate.
    #[serde(default)]
    pub rotate_credential: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct KeyContinuityAttestation {
    pub previous_pubkey_b64: String,
    pub successor_pubkey_b64: String,
    pub signature_b64: String,
}

/// Canonical message signed by K_n to attest K_{n+1}.
pub fn continuity_message(previous_pubkey_b64: &str, successor_pubkey_b64: &str) -> String {
    format!("continuity_v1\n{previous_pubkey_b64}\n{successor_pubkey_b64}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PullResponse {
    pub tasks: Vec<AgentTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_material: Option<KeyMaterialPayload>,
}
