//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const MACHINE_IDS_WILDCARD: &str = "*";
pub use crate::policy::ALLOWLIST_WILDCARD;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MachineIdError {
    #[error("invalid machine id: {0}")]
    Invalid(String),
}

/// Validates machine id permission entries (`*` or a UUID string).
pub fn validate_machine_ids(ids: &[String]) -> Result<(), MachineIdError> {
    for id in ids {
        if id == MACHINE_IDS_WILDCARD {
            continue;
        }
        Uuid::parse_str(id).map_err(|_| MachineIdError::Invalid(id.clone()))?;
    }
    Ok(())
}

pub fn machine_ids_allow_all(ids: &[String]) -> bool {
    ids.iter().any(|id| id == MACHINE_IDS_WILDCARD)
}

pub fn allowed_commands_allow_all(commands: &[String]) -> bool {
    commands.iter().any(|command| command == ALLOWLIST_WILDCARD)
}

pub fn command_allowed(commands: &[String], name: &str) -> bool {
    allowed_commands_allow_all(commands) || commands.iter().any(|command| command == name)
}

pub fn platform_command_allowed(commands: &[String], name: &str) -> bool {
    command_allowed(commands, name)
}

pub fn allowed_admin_commands_allow_all(commands: &[String]) -> bool {
    allowed_commands_allow_all(commands)
}

pub fn admin_command_allowed(commands: &[String], name: &str) -> bool {
    allowed_admin_commands_allow_all(commands) || commands.iter().any(|command| command == name)
}

/// Commands whose execution resolves a filesystem path or working directory against
/// `ShellPolicy::allowed_cwd`. Granting these without a scoped `allowed_cwd` is a
/// deny-all misconfiguration in practice (every path check fails closed).
pub const PATH_SENSITIVE_COMMANDS: &[&str] = &[
    "shell.run",
    "desktop.shell.run",
    "file.pull",
    "file.push",
    "file.copy",
    "file.move",
    "file.rename",
    "file.delete",
    "folder.mkdir",
    "folder.rmdir",
    "folder.rename",
    "folder.move",
    "folder.copy",
    "remote.download",
];

pub fn requires_allowed_cwd(commands: &[String]) -> bool {
    if allowed_commands_allow_all(commands) {
        return true;
    }
    commands
        .iter()
        .any(|command| PATH_SENSITIVE_COMMANDS.contains(&command.as_str()))
}

/// Validate that saved rules granting path-sensitive commands also configure a
/// non-empty `allowed_cwd` (or the `*` wildcard). Catches a common admin mistake
/// where a path command is enabled but every execution is silently deny-by-default.
pub fn validate_path_command_cwd_requirement_legacy(rules: &AiPermissionRules) -> Result<(), String> {
    validate_path_command_cwd_requirement(&CapabilityProfileRules {
        allowed_commands: rules.allowed_commands.clone(),
        allowed_admin_commands: rules.allowed_admin_commands.clone(),
        shell_policy: rules.shell_policy.clone(),
        elevation_policy: rules.elevation_policy.clone(),
        max_output_bytes: rules.max_output_bytes,
        max_file_bytes: rules.max_file_bytes,
        timeout_secs: rules.timeout_secs,
        max_concurrent: rules.max_concurrent,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ShellPolicy {
    pub allowed_binaries: Vec<String>,
    pub allowed_cwd: Vec<String>,
    pub allowed_env: Vec<String>,
}

/// Opt-in policy for privileged (root/admin) execution via the `elevated` shell.run flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ElevationPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_binaries: Vec<String>,
}

pub const DEFAULT_MAX_OUTPUT_BYTES: u32 = 1_048_576;
pub const DEFAULT_MAX_FILE_BYTES: u32 = 52_428_800;
pub const DEFAULT_TIMEOUT_SECS: u32 = 30;
pub const DEFAULT_MAX_CONCURRENT: u32 = 4;

fn default_allowed_commands() -> Vec<String> {
    vec!["system.info".into(), "permissions.request".into()]
}

/// Deny-by-default machine scope with read-only `system.info` and conservative execution limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiPermissionRules {
    #[serde(default)]
    pub machine_ids: Vec<String>,
    #[serde(default)]
    pub machine_tags: Vec<String>,
    #[serde(default = "default_allowed_commands")]
    pub allowed_commands: Vec<String>,
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
    #[serde(default)]
    pub allowed_admin_commands: Vec<String>,
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

impl Default for AiPermissionRules {
    fn default() -> Self {
        Self {
            machine_ids: Vec::new(),
            machine_tags: Vec::new(),
            allowed_commands: default_allowed_commands(),
            shell_policy: ShellPolicy::default(),
            elevation_policy: ElevationPolicy::default(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            allowed_admin_commands: Vec::new(),
        }
    }
}

/// Capability rules shared by profiles and legacy permission validation helpers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityProfileRules {
    pub allowed_commands: Vec<String>,
    pub allowed_admin_commands: Vec<String>,
    pub shell_policy: ShellPolicy,
    pub elevation_policy: ElevationPolicy,
    pub max_output_bytes: u32,
    pub max_file_bytes: u32,
    pub timeout_secs: u32,
    pub max_concurrent: u32,
}

pub fn validate_path_command_cwd_requirement(rules: &CapabilityProfileRules) -> Result<(), String> {
    if !requires_allowed_cwd(&rules.allowed_commands) {
        return Ok(());
    }
    if rules.shell_policy.allowed_cwd.is_empty() {
        return Err(
            "allowed_commands grants a path-sensitive command (shell.run, file.*, folder.*, or remote.download); shell_policy.allowed_cwd must list at least one directory or \"*\"".into(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiIdentitySummary {
    pub id: Uuid,
    pub name: String,
    pub active: bool,
}

/// Runtime capabilities exposed to AI clients (MCP `hecate://context/permissions`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiContextCapabilities {
    pub elevation_enabled: bool,
    pub elevation_allowed_binaries: Vec<String>,
    pub shell_run_max_timeout_secs: u32,
    pub max_output_bytes: u32,
    pub max_file_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiContextAdminCapabilities {
    pub allowed_admin_commands: Vec<String>,
}

impl From<&AiPermissionRules> for AiContextCapabilities {
    fn from(rules: &AiPermissionRules) -> Self {
        Self {
            elevation_enabled: rules.elevation_policy.enabled,
            elevation_allowed_binaries: rules.elevation_policy.allowed_binaries.clone(),
            shell_run_max_timeout_secs: rules.timeout_secs,
            max_output_bytes: rules.max_output_bytes,
            max_file_bytes: rules.max_file_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiContextResponse {
    pub identity: AiIdentitySummary,
    pub grant_assignments: Vec<crate::authz::ResolvedGrantAssignment>,
    pub effective_summary: crate::authz::EffectiveRightsSummary,
    pub capabilities: AiContextCapabilities,
    pub admin_capabilities: AiContextAdminCapabilities,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_deny_machines_but_allow_system_info() {
        let rules = AiPermissionRules::default();
        assert!(rules.machine_ids.is_empty());
        assert!(rules.machine_tags.is_empty());
        assert_eq!(
            rules.allowed_commands,
            vec!["system.info", "permissions.request"]
        );
        assert!(rules.allowed_admin_commands.is_empty());
        assert_eq!(rules.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES);
        assert_eq!(rules.max_file_bytes, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(rules.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(rules.max_concurrent, DEFAULT_MAX_CONCURRENT);
    }

    #[test]
    fn shell_policy_deserializes_empty_object() {
        let policy: ShellPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(policy, ShellPolicy::default());
    }

    #[test]
    fn elevation_policy_deserializes_empty_object() {
        let policy: ElevationPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(policy, ElevationPolicy::default());
    }

    #[test]
    fn empty_json_deserializes_to_default_rules() {
        let rules: AiPermissionRules = serde_json::from_str("{}").unwrap();
        assert_eq!(rules, AiPermissionRules::default());
    }

    #[test]
    fn command_wildcard_allows_any_command() {
        assert!(command_allowed(&["*".into()], "system.info"));
        assert!(command_allowed(&["*".into()], "custom.command"));
        assert!(!command_allowed(&["system.info".into()], "shell.run"));
    }

    #[test]
    fn admin_command_allowed_respects_wildcard() {
        assert!(admin_command_allowed(&["*".into()], "admin.audit.list"));
        assert!(!admin_command_allowed(&[], "admin.audit.list"));
    }

    #[test]
    fn path_command_cwd_requirement_rejects_empty_allowed_cwd() {
        let mut rules = AiPermissionRules::default();
        rules.allowed_commands = vec!["shell.run".into()];
        assert!(validate_path_command_cwd_requirement_legacy(&rules).is_err());
        rules.shell_policy.allowed_cwd = vec!["/tmp".into()];
        assert!(validate_path_command_cwd_requirement_legacy(&rules).is_ok());
    }

    #[test]
    fn path_command_cwd_requirement_ignores_non_path_commands() {
        let mut rules = AiPermissionRules::default();
        rules.allowed_commands = vec!["system.info".into()];
        assert!(validate_path_command_cwd_requirement_legacy(&rules).is_ok());
    }

    #[test]
    fn path_command_cwd_requirement_wildcard_command_requires_cwd() {
        let mut rules = AiPermissionRules::default();
        rules.allowed_commands = vec!["*".into()];
        assert!(validate_path_command_cwd_requirement_legacy(&rules).is_err());
        rules.shell_policy.allowed_cwd = vec!["*".into()];
        assert!(validate_path_command_cwd_requirement_legacy(&rules).is_ok());
    }
}
