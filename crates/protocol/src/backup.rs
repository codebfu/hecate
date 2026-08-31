//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};

pub const BACKUP_FORMAT: &str = "hecate-backup";
pub const BACKUP_ENCRYPTED_FORMAT: &str = "hecate-backup-encrypted";
pub const BACKUP_ENCRYPTED_VERSION: u32 = 1;
pub const BACKUP_FORMAT_VERSION_CURRENT: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupKdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for BackupKdfParams {
    fn default() -> Self {
        Self {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedBackupEnvelope {
    pub format: String,
    pub version: u32,
    pub kdf: String,
    pub kdf_params: BackupKdfParams,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackupSectionId {
    AiIdentities,
    AiPermissions,
    Operators,
    OperatorWebauthn,
    Fleet,
    CommandDefinitions,
    AgentReleases,
    AgentReleaseArtifacts,
    ServerSettings,
}

impl BackupSectionId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AiIdentities => "ai_identities",
            Self::AiPermissions => "ai_permissions",
            Self::Operators => "operators",
            Self::OperatorWebauthn => "operator_webauthn",
            Self::Fleet => "fleet",
            Self::CommandDefinitions => "command_definitions",
            Self::AgentReleases => "agent_releases",
            Self::AgentReleaseArtifacts => "agent_release_artifacts",
            Self::ServerSettings => "server_settings",
        }
    }

    pub fn all_exportable() -> &'static [BackupSectionId] {
        &[
            Self::AiIdentities,
            Self::AiPermissions,
            Self::Operators,
            Self::OperatorWebauthn,
            Self::Fleet,
            Self::CommandDefinitions,
            Self::AgentReleases,
            Self::AgentReleaseArtifacts,
            Self::ServerSettings,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupSectionMeta {
    pub id: String,
    pub label: String,
    pub default_selected: bool,
    pub exportable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupSectionData {
    pub section_format_version: u32,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupManifest {
    pub format: String,
    pub backup_format_version: u32,
    pub exported_at: chrono::DateTime<chrono::Utc>,
    pub hecate_version: String,
    pub schema_version_at_export: i64,
    pub sections_included: Vec<String>,
    pub sections: std::collections::HashMap<String, BackupSectionData>,
}

impl BackupManifest {
    pub fn new(schema_version: i64, sections: std::collections::HashMap<String, BackupSectionData>) -> Self {
        let sections_included: Vec<_> = sections.keys().cloned().collect();
        Self {
            format: BACKUP_FORMAT.to_string(),
            backup_format_version: BACKUP_FORMAT_VERSION_CURRENT,
            exported_at: chrono::Utc::now(),
            hecate_version: crate::HECATE_VERSION.to_string(),
            schema_version_at_export: schema_version,
            sections_included,
            sections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn manifest_roundtrip() {
        let mut sections = HashMap::new();
        sections.insert(
            "ai_identities".into(),
            BackupSectionData {
                section_format_version: 1,
                data: serde_json::json!([]),
            },
        );
        let manifest = BackupManifest::new(1, sections);
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: BackupManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.format, BACKUP_FORMAT);
        assert_eq!(parsed.backup_format_version, 1);
    }
}
