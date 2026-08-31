//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::authz::{
    PermissionRequestChanges, PermissionRequestClass, PermissionRequestPreview,
    ResolvedGrantAssignment,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionRequestStatus {
    Pending,
    Approved,
    Rejected,
}

impl PermissionRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermissionRequestSummary {
    pub id: Uuid,
    pub ai_identity_id: Uuid,
    pub ai_identity_name: String,
    pub status: PermissionRequestStatus,
    pub reason: String,
    pub request_class: PermissionRequestClass,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermissionRequestDetail {
    #[serde(flatten)]
    pub summary: PermissionRequestSummary,
    pub current_assignments: Vec<ResolvedGrantAssignment>,
    pub requested_changes: PermissionRequestChanges,
    pub request_preview: PermissionRequestPreview,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_reason: Option<String>,
}
