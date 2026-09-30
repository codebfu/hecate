//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Types for Propylaea proxy enrollment and sync with Hecate.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent::AgentState;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    PendingApproval,
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyEnrollRequest {
    pub enrollment_token: String,
    /// When set, must match a proxy-bound enrollment token (re-enroll).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<Uuid>,
    pub public_key: String,
    pub hostname: String,
    pub version: String,
    #[serde(default)]
    pub attestation: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyEnrollResponse {
    pub proxy_id: Uuid,
    pub state: ProxyState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProxyRateLimitClass {
    Enroll,
    Allowed,
    Unrecognized,
}

impl ProxyRateLimitClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Allowed => "allowed",
            Self::Unrecognized => "unrecognized",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "enroll" => Some(Self::Enroll),
            "allowed" => Some(Self::Allowed),
            "unrecognized" => Some(Self::Unrecognized),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyRateLimitEntry {
    pub ip: String,
    pub class: ProxyRateLimitClass,
    pub count: u32,
    pub limit: u32,
    /// RFC3339 timestamp when the current window started.
    pub window_started_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyRateLimitUnban {
    pub ip: String,
    pub class: ProxyRateLimitClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyHeartbeatRequest {
    pub version: String,
    pub uptime_secs: u64,
    pub hostname: String,
    /// Currently limited client IPs (count > limit), reported by Propylaea.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<ProxyRateLimitEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxySyncAgent {
    pub agent_id: Uuid,
    pub credential_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_pubkey_previous: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_pubkey_previous_expires_at: Option<String>,
    pub state: AgentState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxySyncEnrollmentToken {
    pub token_hmac: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_machine_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_proxy_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxySyncResponse {
    pub agents: Vec<ProxySyncAgent>,
    pub enrollment_tokens: Vec<ProxySyncEnrollmentToken>,
    #[serde(default)]
    pub proxy_enrollment_tokens: Vec<ProxySyncEnrollmentToken>,
    /// Pending operator unbans for this proxy (delivered once via sync).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limit_unbans: Vec<ProxyRateLimitUnban>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxySummary {
    pub id: Uuid,
    pub hostname: String,
    pub state: ProxyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub enrolled_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

/// HTTP path constants for proxy↔Hecate communication.
pub mod paths {
    pub const ENROLL: &str = "/api/v1/proxy/enroll";
    pub const SYNC: &str = "/api/v1/proxy/sync";
    pub const HEARTBEAT: &str = "/api/v1/proxy/heartbeat";
}
