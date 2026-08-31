//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    PendingApproval,
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrollRequest {
    pub enrollment_token: String,
    /// When set, must match a machine-bound enrollment token (re-enroll).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Uuid>,
    pub public_key: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub attestation: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrollResponse {
    pub agent_id: Uuid,
    pub machine_id: Uuid,
    pub state: AgentState,
    pub task_signing_pubkey_b64: String,
    /// Ed25519 public key (base64) for verifying signed release artifacts.
    /// Absent when the server has not configured a release signing key yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_public_key_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentStatusResponse {
    pub agent_id: Uuid,
    pub state: AgentState,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatRequest {
    pub agent_version: String,
    pub uptime_secs: u64,
    /// Current machine hostname; may differ from enrollment if the OS hostname changed.
    pub hostname: String,
    /// Auto-detected machine tags; sent once on the first heartbeat after service start.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Local desktop helper version when installed; omit/null when not present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_version: Option<String>,
    /// Local Proxmox console helper version when installed; omit/null when not present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_version: Option<String>,
    /// Global agent health: pull loop can drain the queue, or a command is in flight.
    /// Absent on older agents (server treats as unknown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthy: Option<bool>,
    /// True while the agent is executing a command (pull may be paused by design).
    /// Omitted when false so older agents that never sent this field stay signature-compatible
    /// if a consumer re-serializes the parsed struct (API verifies raw bytes instead).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub busy: bool,
    /// Seconds since the last successful pull. None before the first pull.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secs_since_last_pull: Option<u64>,
    /// Command currently being executed, when `busy` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_command_id: Option<Uuid>,
}

/// Available self-update offer for an enrolled agent (CLI `update` command).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateOfferResponse {
    pub available: bool,
    pub current_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_public_key_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional desktop helper update offered alongside (or instead of) the agent binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<DesktopUpdateOffer>,
    /// Optional Proxmox console helper update offered alongside other components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<ProxmoxUpdateOffer>,
    /// Dual-key material for release / task signing during rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_material: Option<crate::task::KeyMaterialPayload>,
    /// Task-signing signature over the agent artifact path/hash (H1c).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_task_sig: Option<String>,
}

/// Agent requests identity key rotation (signed with the current identity key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotateCredentialRequest {
    pub new_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotateCredentialResponse {
    pub ok: bool,
    /// RFC3339 expiry for the previous credential pubkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_expires_at: Option<String>,
}

/// Desktop helper component of an update offer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DesktopUpdateOffer {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_task_sig: Option<String>,
}

/// Proxmox console helper component of an update offer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxmoxUpdateOffer {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_task_sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateOfferRequest {
    pub agent_version: String,
    /// Local desktop helper version when installed; omit when not present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_version: Option<String>,
    /// Local Proxmox console helper version when installed; omit when not present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineSummary {
    pub id: Uuid,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    /// Effective tags (agent + operator).
    pub tags: Vec<String>,
    #[serde(default)]
    pub agent_tags: Vec<String>,
    #[serde(default)]
    pub operator_tags: Vec<String>,
    pub status: String,
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox_version: Option<String>,
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_response_includes_optional_release_public_key() {
        let id = Uuid::nil();
        let with_key = EnrollResponse {
            agent_id: id,
            machine_id: id,
            state: AgentState::Active,
            task_signing_pubkey_b64: "task-key".into(),
            release_public_key_b64: Some("release-key".into()),
        };
        let json = serde_json::to_value(&with_key).unwrap();
        assert_eq!(json["release_public_key_b64"], "release-key");
        assert_eq!(json["task_signing_pubkey_b64"], "task-key");

        let without_key = EnrollResponse {
            release_public_key_b64: None,
            ..with_key.clone()
        };
        let json = serde_json::to_value(&without_key).unwrap();
        assert!(json.get("release_public_key_b64").is_none());

        let legacy = serde_json::json!({
            "agent_id": id,
            "machine_id": id,
            "state": "active",
            "task_signing_pubkey_b64": "task-key",
        });
        let parsed: EnrollResponse = serde_json::from_value(legacy).unwrap();
        assert!(parsed.release_public_key_b64.is_none());
    }

    #[test]
    fn enroll_request_agent_id_is_optional_in_json() {
        let without = serde_json::json!({
            "enrollment_token": format!("enr_{}", "a".repeat(48)),
            "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "hostname": "host",
            "os": "linux",
            "arch": "x86_64",
            "tags": [],
            "attestation": {},
        });
        let parsed: EnrollRequest = serde_json::from_value(without).unwrap();
        assert!(parsed.agent_id.is_none());

        let id = Uuid::new_v4();
        let with_id = serde_json::json!({
            "enrollment_token": format!("enr_{}", "b".repeat(48)),
            "agent_id": id,
            "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "hostname": "host",
            "os": "linux",
            "arch": "x86_64",
            "tags": [],
            "attestation": {},
        });
        let parsed: EnrollRequest = serde_json::from_value(with_id).unwrap();
        assert_eq!(parsed.agent_id, Some(id));
        let json = serde_json::to_value(&EnrollRequest {
            agent_id: None,
            ..parsed
        })
        .unwrap();
        assert!(json.get("agent_id").is_none());
    }

    #[test]
    fn key_material_payload_defaults_for_legacy_pull() {
        use crate::task::{KeyMaterialPayload, PullResponse};

        let legacy = serde_json::json!({ "tasks": [] });
        let parsed: PullResponse = serde_json::from_value(legacy).unwrap();
        assert!(parsed.key_material.is_none());

        let with_keys = PullResponse {
            tasks: vec![],
            key_material: Some(KeyMaterialPayload {
                task_signing_pubkey_b64: Some("abc".into()),
                rotate_credential: true,
                ..Default::default()
            }),
        };
        let json = serde_json::to_value(&with_keys).unwrap();
        assert_eq!(json["key_material"]["rotate_credential"], true);
        assert_eq!(json["key_material"]["task_signing_pubkey_b64"], "abc");
    }
}
