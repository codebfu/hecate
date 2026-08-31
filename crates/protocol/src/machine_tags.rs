//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Validation and fallback helpers for machine tags.

use thiserror::Error;

const MAX_TAGS: usize = 16;
const MAX_TAG_LEN: usize = 64;

/// Namespaces owned by the agent auto-detection pipeline.
pub const RESERVED_AGENT_NAMESPACES: &[&str] = &[
    "os",
    "arch",
    "distro",
    "virt",
    "init",
    "gui",
    "display",
    "proxmox",
    "hypervisor",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MachineTagError {
    #[error("too many tags (max {MAX_TAGS})")]
    TooMany,
    #[error("tag too long (max {MAX_TAG_LEN} chars): {0}")]
    TooLong(String),
    #[error("invalid tag format: {0}")]
    InvalidFormat(String),
}

/// Returns the namespace portion of a tag, if present.
pub fn tag_namespace(tag: &str) -> Option<&str> {
    tag.split_once(':').map(|(namespace, _)| namespace)
}

/// Whether a namespace is reserved for agent auto-detection.
pub fn is_reserved_agent_namespace(namespace: &str) -> bool {
    RESERVED_AGENT_NAMESPACES.contains(&namespace)
}

/// Validates namespaced machine tags and returns a deduplicated sorted copy.
pub fn validate_machine_tags(tags: &[String]) -> Result<Vec<String>, MachineTagError> {
    if tags.len() > MAX_TAGS {
        return Err(MachineTagError::TooMany);
    }

    let mut normalized = Vec::with_capacity(tags.len());
    for tag in tags {
        if tag.len() > MAX_TAG_LEN {
            return Err(MachineTagError::TooLong(tag.clone()));
        }
        if !is_valid_tag(tag) {
            return Err(MachineTagError::InvalidFormat(tag.clone()));
        }
        normalized.push(tag.clone());
    }

    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

/// Validates custom (operator/agent-config) tags; rejects reserved agent namespaces.
pub fn validate_custom_tags(tags: &[String]) -> Result<Vec<String>, MachineTagError> {
    for tag in tags {
        if let Some(namespace) = tag_namespace(tag) {
            if is_reserved_agent_namespace(namespace) {
                return Err(MachineTagError::InvalidFormat(format!(
                    "reserved namespace: {tag}"
                )));
            }
        }
    }
    validate_machine_tags(tags)
}

/// Which tag sources participate in AI machine authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthzTagSources {
    pub auto: bool,
    pub operator: bool,
    pub agent_custom: bool,
}

impl Default for AuthzTagSources {
    fn default() -> Self {
        // Safe defaults: auto + operator on; agent-controlled custom off.
        Self {
            auto: true,
            operator: true,
            agent_custom: false,
        }
    }
}

/// Splits agent-owned tags into reserved (auto) vs custom namespaces.
pub fn split_agent_tags(agent_tags: &[String]) -> (Vec<String>, Vec<String>) {
    let mut auto = Vec::new();
    let mut custom = Vec::new();
    for tag in agent_tags {
        match tag_namespace(tag) {
            Some(namespace) if is_reserved_agent_namespace(namespace) => auto.push(tag.clone()),
            _ => custom.push(tag.clone()),
        }
    }
    (auto, custom)
}

/// Merges agent and operator tags into the effective tag set shown to clients.
pub fn merge_effective_tags(
    agent_tags: &[String],
    operator_tags: &[String],
) -> Result<Vec<String>, MachineTagError> {
    let mut merged = agent_tags.to_vec();
    merged.extend(operator_tags.iter().cloned());
    merged.sort();
    merged.dedup();
    validate_machine_tags(&merged)
}

/// Builds the tag set used for AI `machine_authorized` checks.
pub fn merge_authz_tags(
    agent_tags: &[String],
    operator_tags: &[String],
    sources: AuthzTagSources,
) -> Result<Vec<String>, MachineTagError> {
    let (auto, custom) = split_agent_tags(agent_tags);
    let mut merged = Vec::new();
    if sources.auto {
        merged.extend(auto);
    }
    if sources.agent_custom {
        merged.extend(custom);
    }
    if sources.operator {
        merged.extend(operator_tags.iter().cloned());
    }
    merged.sort();
    merged.dedup();
    if merged.is_empty() {
        return Ok(merged);
    }
    validate_machine_tags(&merged)
}

/// Merges incoming agent heartbeat tags with existing agent-owned tags.
pub fn merge_agent_heartbeat_tags(
    existing_agent: &[String],
    incoming: &[String],
) -> Result<Vec<String>, MachineTagError> {
    let existing_custom: Vec<String> = existing_agent
        .iter()
        .filter(|tag| {
            tag_namespace(tag)
                .map(|namespace| !is_reserved_agent_namespace(namespace))
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    let incoming_reserved: Vec<String> = incoming
        .iter()
        .filter(|tag| {
            tag_namespace(tag)
                .map(is_reserved_agent_namespace)
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    let incoming_custom: Vec<String> = incoming
        .iter()
        .filter(|tag| {
            tag_namespace(tag)
                .map(|namespace| !is_reserved_agent_namespace(namespace))
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    let mut merged = incoming_reserved;
    for tag in existing_custom {
        if !merged.contains(&tag) {
            merged.push(tag);
        }
    }
    for tag in incoming_custom {
        if !merged.contains(&tag) {
            merged.push(tag);
        }
    }
    validate_machine_tags(&merged)
}

/// Builds minimal tags from enrollment OS/arch fields (legacy agent fallback).
pub fn fallback_tags_from_os_arch(os: &str, arch: &str) -> Vec<String> {
    let mut tags = vec![
        format!("os:{}", normalize_component(os)),
        format!("arch:{}", normalize_component(arch)),
    ];
    tags.sort();
    tags.dedup();
    tags
}

/// Uses agent-provided tags when present, otherwise falls back to os/arch tags.
pub fn resolve_enrollment_tags(
    tags: &[String],
    os: &str,
    arch: &str,
) -> Result<Vec<String>, MachineTagError> {
    if tags.is_empty() {
        Ok(fallback_tags_from_os_arch(os, arch))
    } else {
        validate_machine_tags(tags)
    }
}

/// Validates heartbeat tags when provided; returns None to keep existing DB tags.
/// Agents send tags only on the first heartbeat after service start.
pub fn resolve_heartbeat_tags(tags: &[String]) -> Result<Option<Vec<String>>, MachineTagError> {
    if tags.is_empty() {
        Ok(None)
    } else {
        validate_machine_tags(tags).map(Some)
    }
}

fn normalize_component(value: &str) -> String {
    value.to_ascii_lowercase().replace('_', "-")
}

fn is_valid_tag(tag: &str) -> bool {
    let Some((namespace, value)) = tag.split_once(':') else {
        return false;
    };
    is_valid_namespace(namespace) && is_valid_value(value)
}

fn is_valid_namespace(segment: &str) -> bool {
    is_valid_segment(segment, false)
}

fn is_valid_value(segment: &str) -> bool {
    is_valid_segment(segment, true)
}

fn is_valid_segment(segment: &str, allow_dot: bool) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || matches!(c, '_' | '-')
            || (allow_dot && c == '.')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_namespaced_tags() {
        let tags = vec![
            "os:linux".into(),
            "arch:x86_64".into(),
            "distro:ubuntu".into(),
        ];
        assert_eq!(
            validate_machine_tags(&tags).expect("valid"),
            vec!["arch:x86_64", "distro:ubuntu", "os:linux"]
        );
    }

    #[test]
    fn validate_rejects_missing_namespace() {
        let tags = vec!["linux".into()];
        assert_eq!(
            validate_machine_tags(&tags),
            Err(MachineTagError::InvalidFormat("linux".into()))
        );
    }

    #[test]
    fn validate_rejects_uppercase() {
        let tags = vec!["OS:Linux".into()];
        assert_eq!(
            validate_machine_tags(&tags),
            Err(MachineTagError::InvalidFormat("OS:Linux".into()))
        );
    }

    #[test]
    fn validate_rejects_too_many_tags() {
        let tags: Vec<String> = (0..17).map(|i| format!("ns:tag{i}")).collect();
        assert_eq!(validate_machine_tags(&tags), Err(MachineTagError::TooMany));
    }

    #[test]
    fn validate_custom_tags_rejects_reserved_namespace() {
        let tags = vec!["proxmox:console".into()];
        assert!(validate_custom_tags(&tags).is_err());
    }

    #[test]
    fn validate_custom_tags_accepts_custom_namespace() {
        let tags = vec!["env:prod".into(), "role:web".into()];
        assert_eq!(
            validate_custom_tags(&tags).expect("valid"),
            vec!["env:prod", "role:web"]
        );
    }

    #[test]
    fn merge_effective_tags_unions_agent_and_operator() {
        let agent = vec!["os:linux".into(), "arch:x86_64".into()];
        let operator = vec!["env:prod".into()];
        assert_eq!(
            merge_effective_tags(&agent, &operator).expect("valid"),
            vec!["arch:x86_64", "env:prod", "os:linux"]
        );
    }

    #[test]
    fn merge_authz_tags_defaults_exclude_agent_custom() {
        let agent = vec!["os:linux".into(), "env:prod".into()];
        let operator = vec!["role:web".into()];
        assert_eq!(
            merge_authz_tags(&agent, &operator, AuthzTagSources::default()).expect("valid"),
            vec!["os:linux", "role:web"]
        );
    }

    #[test]
    fn merge_authz_tags_can_enable_agent_custom() {
        let agent = vec!["os:linux".into(), "env:prod".into()];
        let sources = AuthzTagSources {
            auto: true,
            operator: false,
            agent_custom: true,
        };
        assert_eq!(
            merge_authz_tags(&agent, &[], sources).expect("valid"),
            vec!["env:prod", "os:linux"]
        );
    }

    #[test]
    fn merge_effective_tags_rejects_over_limit() {
        let agent: Vec<String> = (0..10).map(|i| format!("a:tag{i}")).collect();
        let operator: Vec<String> = (0..10).map(|i| format!("b:tag{i}")).collect();
        assert!(merge_effective_tags(&agent, &operator).is_err());
    }

    #[test]
    fn merge_agent_heartbeat_tags_replaces_reserved_namespaces() {
        let existing = vec![
            "os:linux".into(),
            "arch:x86_64".into(),
            "proxmox:none".into(),
            "env:prod".into(),
        ];
        let incoming = vec![
            "os:linux".into(),
            "arch:aarch64".into(),
            "proxmox:console".into(),
        ];
        assert_eq!(
            merge_agent_heartbeat_tags(&existing, &incoming).expect("valid"),
            vec!["arch:aarch64", "env:prod", "os:linux", "proxmox:console"]
        );
    }

    #[test]
    fn fallback_builds_os_and_arch_tags() {
        assert_eq!(
            fallback_tags_from_os_arch("linux", "x86_64"),
            vec!["arch:x86-64", "os:linux"]
        );
    }

    #[test]
    fn resolve_uses_fallback_when_empty() {
        assert_eq!(
            resolve_enrollment_tags(&[], "linux", "aarch64").expect("fallback"),
            vec!["arch:aarch64", "os:linux"]
        );
    }

    #[test]
    fn resolve_validates_provided_tags() {
        let tags = vec!["os:linux".into(), "virt:vm".into()];
        assert_eq!(
            resolve_enrollment_tags(&tags, "linux", "x86_64").expect("valid"),
            vec!["os:linux", "virt:vm"]
        );
    }

    #[test]
    fn heartbeat_resolve_preserves_existing_when_empty() {
        assert_eq!(resolve_heartbeat_tags(&[]).expect("empty"), None);
    }

    #[test]
    fn heartbeat_resolve_validates_provided_tags() {
        let tags = vec!["virt:container".into(), "os:linux".into()];
        assert_eq!(
            resolve_heartbeat_tags(&tags).expect("valid"),
            Some(vec!["os:linux".into(), "virt:container".into()])
        );
    }
}
