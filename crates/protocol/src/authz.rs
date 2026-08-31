//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Granular authorization model: Fleet Scope, Capability Profile, Access Grant, Grant Assignment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::permissions::{
    validate_path_command_cwd_requirement, CapabilityProfileRules, ShellPolicy, ElevationPolicy,
    DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT_SECS,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TagMatchMode {
    #[default]
    Any,
    All,
}

impl TagMatchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::All => "all",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "any" => Some(Self::Any),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

/// Built-in fleet scope that dynamically includes every machine in the fleet.
pub const SYSTEM_FLEET_SCOPE_ALL_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0004);

pub fn is_system_fleet_scope(id: Uuid) -> bool {
    id == SYSTEM_FLEET_SCOPE_ALL_ID
}

/// Built-in capability profile that allows every agent/platform command.
pub const SYSTEM_CAPABILITY_PROFILE_ALL_USER_COMMANDS_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0005);

/// Built-in capability profile that allows every admin command.
pub const SYSTEM_CAPABILITY_PROFILE_ALL_ADMIN_COMMANDS_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0006);

pub fn is_system_capability_profile(id: Uuid) -> bool {
    id == SYSTEM_CAPABILITY_PROFILE_ALL_USER_COMMANDS_ID
        || id == SYSTEM_CAPABILITY_PROFILE_ALL_ADMIN_COMMANDS_ID
}

/// Post-migration seed entities: minimal hidden grant auto-assigned to every AI identity.
pub const BOOTSTRAP_FLEET_SCOPE_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0001);

pub const BOOTSTRAP_CAPABILITY_PROFILE_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0002);

pub const BOOTSTRAP_ACCESS_GRANT_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0003);

pub fn is_bootstrap_fleet_scope(id: Uuid) -> bool {
    id == BOOTSTRAP_FLEET_SCOPE_ID
}

pub fn is_bootstrap_capability_profile(id: Uuid) -> bool {
    id == BOOTSTRAP_CAPABILITY_PROFILE_ID
}

pub fn is_bootstrap_access_grant(id: Uuid) -> bool {
    id == BOOTSTRAP_ACCESS_GRANT_ID
}

pub fn is_internal_catalog_fleet_scope(id: Uuid) -> bool {
    is_bootstrap_fleet_scope(id)
}

pub fn is_internal_catalog_capability_profile(id: Uuid) -> bool {
    is_bootstrap_capability_profile(id)
}

pub fn is_internal_catalog_access_grant(id: Uuid) -> bool {
    is_bootstrap_access_grant(id)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthzProvenance {
    #[default]
    Operator,
    PermissionRequest,
    Import,
    Seed,
    System,
}

impl AuthzProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::PermissionRequest => "permission_request",
            Self::Import => "import",
            Self::Seed => "seed",
            Self::System => "system",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "operator" => Some(Self::Operator),
            "permission_request" => Some(Self::PermissionRequest),
            "import" => Some(Self::Import),
            "seed" => Some(Self::Seed),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FleetScope {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tag_match_mode: TagMatchMode,
    #[serde(default)]
    pub provenance: AuthzProvenance,
    #[serde(default)]
    pub request_scoped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_ai_identity_id: Option<Uuid>,
    pub machine_ids: Vec<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityProfile {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub provenance: AuthzProvenance,
    #[serde(default)]
    pub request_scoped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_ai_identity_id: Option<Uuid>,
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    #[serde(default)]
    pub allowed_admin_commands: Vec<String>,
    #[serde(default)]
    pub shell_policy: ShellPolicy,
    #[serde(default)]
    pub elevation_policy: ElevationPolicy,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: u32,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u32,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u32,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_max_output_bytes() -> u32 {
    DEFAULT_MAX_OUTPUT_BYTES
}

fn default_max_file_bytes() -> u32 {
    DEFAULT_MAX_FILE_BYTES
}

fn default_timeout_secs() -> u32 {
    DEFAULT_TIMEOUT_SECS
}

fn default_max_concurrent() -> u32 {
    DEFAULT_MAX_CONCURRENT
}

impl CapabilityProfile {
    pub fn as_rules(&self) -> CapabilityProfileRules {
        CapabilityProfileRules {
            allowed_commands: self.allowed_commands.clone(),
            allowed_admin_commands: self.allowed_admin_commands.clone(),
            shell_policy: self.shell_policy.clone(),
            elevation_policy: self.elevation_policy.clone(),
            max_output_bytes: self.max_output_bytes,
            max_file_bytes: self.max_file_bytes,
            timeout_secs: self.timeout_secs,
            max_concurrent: self.max_concurrent,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_path_command_cwd_requirement(&self.as_rules())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessGrant {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub provenance: AuthzProvenance,
    #[serde(default)]
    pub request_scoped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_ai_identity_id: Option<Uuid>,
    pub fleet_scope_id: Uuid,
    pub capability_profile_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrantAssignment {
    pub id: Uuid,
    pub ai_identity_id: Uuid,
    pub access_grant_id: Uuid,
    #[serde(default = "default_true")]
    pub requires_approval_for_shell: bool,
    #[serde(default = "default_true")]
    pub requires_approval_for_elevated: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FleetScopeSummary {
    pub id: Uuid,
    pub name: String,
    pub tag_match_mode: TagMatchMode,
    pub machine_count: usize,
    pub tag_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityProfileSummary {
    pub id: Uuid,
    pub name: String,
    pub command_count: usize,
    pub admin_command_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessGrantSummary {
    pub id: Uuid,
    pub name: String,
    pub fleet_scope: FleetScopeSummary,
    pub capability_profile: CapabilityProfileSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolvedGrantAssignment {
    pub id: Uuid,
    pub access_grant: AccessGrantSummary,
    pub requires_approval_for_shell: bool,
    pub requires_approval_for_elevated: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EffectiveRightsSummary {
    pub assignment_count: usize,
    pub machine_scope_count: usize,
    pub allowed_command_count: usize,
    pub allowed_admin_command_count: usize,
    pub max_concurrent_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectiveRightsReport {
    pub summary: EffectiveRightsSummary,
    pub assignments: Vec<ResolvedGrantAssignment>,
    pub allowed_commands: Vec<String>,
    pub allowed_admin_commands: Vec<String>,
    pub machine_ids: Vec<String>,
    pub machine_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FleetScopePreview {
    pub fleet_scope_id: Uuid,
    pub machines: Vec<FleetScopePreviewMachine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FleetScopePreviewMachine {
    pub id: Uuid,
    pub hostname: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzCatalogResponse {
    pub fleet_scopes: Vec<FleetScope>,
    pub capability_profiles: Vec<CapabilityProfile>,
    pub access_grants: Vec<AccessGrantDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessGrantDetail {
    #[serde(flatten)]
    pub grant: AccessGrant,
    pub fleet_scope: FleetScope,
    pub capability_profile: CapabilityProfile,
}

/// Runtime match result used at enqueue and dispatch.
#[derive(Debug, Clone)]
pub struct MatchedGrant {
    pub assignment_id: Uuid,
    pub access_grant_id: Uuid,
    pub capability_profile: CapabilityProfile,
    pub requires_approval_for_shell: bool,
    pub requires_approval_for_elevated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntityRef {
    Id { id: Uuid },
    Proposed { key: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PermissionRequestChanges {
    #[serde(default)]
    pub propose_fleet_scopes: Vec<ProposedFleetScope>,
    #[serde(default)]
    pub propose_capability_profiles: Vec<ProposedCapabilityProfile>,
    #[serde(default)]
    pub propose_access_grants: Vec<ProposedAccessGrant>,
    #[serde(default)]
    pub add_assignments: Vec<RequestedAssignment>,
    #[serde(default)]
    pub remove_assignment_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposedFleetScope {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tag_match_mode: TagMatchMode,
    #[serde(default)]
    pub machine_ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposedCapabilityProfile {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    #[serde(default)]
    pub allowed_admin_commands: Vec<String>,
    #[serde(default)]
    pub shell_policy: ShellPolicy,
    #[serde(default)]
    pub elevation_policy: ElevationPolicy,
    #[serde(default)]
    pub max_output_bytes: Option<u32>,
    #[serde(default)]
    pub max_file_bytes: Option<u32>,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
    #[serde(default)]
    pub max_concurrent: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposedAccessGrant {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub fleet_scope: EntityRef,
    pub capability_profile: EntityRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestedAssignment {
    pub access_grant: EntityRef,
    #[serde(default = "default_true")]
    pub requires_approval_for_shell: bool,
    #[serde(default = "default_true")]
    pub requires_approval_for_elevated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionRequestClass {
    Standard,
    Admin,
}

impl PermissionRequestClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Admin => "admin",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "standard" => Some(Self::Standard),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AutoApproveWarning {
    pub kind: String,
    pub message: String,
    pub assignment_labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PermissionRequestPreview {
    pub entities_to_create: PermissionRequestEntitiesToCreate,
    pub assignments_to_add: Vec<RequestedAssignment>,
    pub assignments_to_remove: Vec<Uuid>,
    pub effective_rights_before: EffectiveRightsSummary,
    pub effective_rights_after: EffectiveRightsSummary,
    #[serde(default)]
    pub auto_approve_warnings: Vec<AutoApproveWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PermissionRequestEntitiesToCreate {
    pub fleet_scopes: Vec<ProposedFleetScope>,
    pub capability_profiles: Vec<ProposedCapabilityProfile>,
    pub access_grants: Vec<ProposedAccessGrant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_capability_profile_ids_are_stable() {
        assert!(is_system_capability_profile(
            SYSTEM_CAPABILITY_PROFILE_ALL_USER_COMMANDS_ID
        ));
        assert!(is_system_capability_profile(
            SYSTEM_CAPABILITY_PROFILE_ALL_ADMIN_COMMANDS_ID
        ));
        assert!(!is_system_capability_profile(Uuid::new_v4()));
    }

    #[test]
    fn bootstrap_catalog_ids_are_stable() {
        assert!(is_bootstrap_access_grant(BOOTSTRAP_ACCESS_GRANT_ID));
        assert!(is_internal_catalog_capability_profile(BOOTSTRAP_CAPABILITY_PROFILE_ID));
        assert!(!is_bootstrap_access_grant(Uuid::new_v4()));
    }

    #[test]
    fn system_fleet_scope_all_id_is_stable() {
        assert!(is_system_fleet_scope(SYSTEM_FLEET_SCOPE_ALL_ID));
        assert!(!is_system_fleet_scope(Uuid::new_v4()));
    }

    #[test]
    fn capability_profile_validates_path_commands() {
        let mut profile = CapabilityProfile {
            id: Uuid::new_v4(),
            name: "test".into(),
            description: String::new(),
            provenance: AuthzProvenance::Operator,
            request_scoped: false,
            owner_ai_identity_id: None,
            allowed_commands: vec!["shell.run".into()],
            allowed_admin_commands: vec![],
            shell_policy: ShellPolicy::default(),
            elevation_policy: ElevationPolicy::default(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(profile.validate().is_err());
        profile.shell_policy.allowed_cwd = vec!["/tmp".into()];
        assert!(profile.validate().is_ok());
    }
}
