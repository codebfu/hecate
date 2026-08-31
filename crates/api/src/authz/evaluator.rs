//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use hecate_protocol::authz::{
    AccessGrantDetail, CapabilityProfile, FleetScope, FleetScopePreview, FleetScopePreviewMachine,
    GrantAssignment, MatchedGrant, TagMatchMode,
};
use hecate_protocol::permissions::{
    allowed_commands_allow_all, command_allowed, CapabilityProfileRules, ALLOWLIST_WILDCARD,
};
use hecate_protocol::policy::ALLOWLIST_WILDCARD as POLICY_WILDCARD;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::machines::{self, MachineRow};
use crate::permissions;
use crate::server_settings;

use super::store;

#[derive(Debug, Clone)]
pub struct MatchingGrant {
    pub assignment: GrantAssignment,
    pub detail: AccessGrantDetail,
}

pub fn fleet_scope_matches(scope: &FleetScope, machine_id: Uuid, authz_tags: &[String]) -> bool {
    let ids_configured = !scope.machine_ids.is_empty();
    let tags_configured = !scope.tags.is_empty();

    if !ids_configured && !tags_configured {
        return false;
    }

    if ids_configured {
        if hecate_protocol::permissions::machine_ids_allow_all(&scope.machine_ids) {
            return true;
        }
        let id_str = machine_id.to_string();
        if scope.machine_ids.contains(&id_str) {
            return true;
        }
    }

    if tags_configured {
        let tag_match = match scope.tag_match_mode {
            TagMatchMode::Any => scope.tags.iter().any(|tag| authz_tags.contains(tag)),
            TagMatchMode::All => scope.tags.iter().all(|tag| authz_tags.contains(tag)),
        };
        if tag_match {
            return true;
        }
    }

    false
}

pub fn find_matching_grants(
    assignments: &[(GrantAssignment, AccessGrantDetail)],
    machine_id: Uuid,
    authz_tags: &[String],
    command_name: &str,
) -> Vec<MatchingGrant> {
    assignments
        .iter()
        .filter_map(|(assignment, detail)| {
            if !assignment.enabled {
                return None;
            }
            if !fleet_scope_matches(&detail.fleet_scope, machine_id, authz_tags) {
                return None;
            }
            if !command_allowed(&detail.capability_profile.allowed_commands, command_name) {
                return None;
            }
            Some(MatchingGrant {
                assignment: assignment.clone(),
                detail: detail.clone(),
            })
        })
        .collect()
}

fn shell_policy_width(profile: &CapabilityProfile, command_name: &str, params: &Value) -> u64 {
    if !matches!(command_name, "shell.run" | "desktop.shell.run") {
        return 0;
    }
    let rules = profile_to_rules(profile);
    let argv: Vec<String> = params
        .get("argv")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if argv.is_empty() {
        return u64::MAX / 4;
    }
    let binary = &argv[0];
    let elevated = params
        .get("elevated")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let allowed = if elevated {
        &rules.elevation_policy.allowed_binaries
    } else {
        &rules.shell_policy.allowed_binaries
    };
    if allowed.is_empty() {
        return u64::MAX / 4;
    }
    if allowed.iter().any(|entry| entry == POLICY_WILDCARD) {
        return 10_000;
    }
    if allowed.iter().any(|entry| entry == binary) {
        return 100;
    }
    u64::MAX / 4
}

fn profile_to_rules(profile: &CapabilityProfile) -> CapabilityProfileRules {
    profile.as_rules()
}

/// S2 — deterministic most-restrictive grant selection (lower score wins).
pub fn select_most_restrictive_grant(
    matches: &[MatchingGrant],
    command_name: &str,
    params: &Value,
) -> Option<MatchingGrant> {
    matches
        .iter()
        .min_by(|left, right| {
            let left_score = restrictiveness_score(&left.detail.capability_profile, command_name, params);
            let right_score =
                restrictiveness_score(&right.detail.capability_profile, command_name, params);
            left_score
                .cmp(&right_score)
                .then_with(|| left.assignment.id.cmp(&right.assignment.id))
        })
        .cloned()
}

fn restrictiveness_score(profile: &CapabilityProfile, command_name: &str, params: &Value) -> u64 {
    let mut score = 0u64;
    if allowed_commands_allow_all(&profile.allowed_commands) {
        score += 1_000_000;
    } else {
        score += profile.allowed_commands.len() as u64 * 1_000;
    }
    if profile.elevation_policy.enabled {
        score += 100;
    }
    score += shell_policy_width(profile, command_name, params);
    score
}

pub async fn count_active_commands(pool: &PgPool, identity_id: Uuid) -> ApiResult<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM command_queue
         WHERE ai_identity_id = $1
           AND status IN ('queued', 'pending_approval', 'dispatched', 'running')",
    )
    .bind(identity_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn check_max_concurrent(
    pool: &PgPool,
    identity_id: Uuid,
    max_concurrent: u32,
) -> ApiResult<()> {
    let active = count_active_commands(pool, identity_id).await?;
    let limit = i64::from(max_concurrent.max(1));
    if active >= limit {
        return Err(ApiError::TooManyRequests(format!(
            "max_concurrent limit reached ({limit})"
        )));
    }
    Ok(())
}

pub async fn identity_can_access_machine(
    pool: &PgPool,
    identity_id: Uuid,
    machine_id: Uuid,
) -> ApiResult<bool> {
    let assignments = store::load_enabled_assignment_details(pool, identity_id).await?;
    if assignments.is_empty() {
        return Ok(false);
    }
    let authz_tags = machines::load_authz_tags(pool, machine_id).await?;
    Ok(assignments.iter().any(|(_, detail)| {
        fleet_scope_matches(&detail.fleet_scope, machine_id, &authz_tags)
    }))
}

pub async fn authorize_agent_command(
    pool: &PgPool,
    identity_id: Uuid,
    machine_id: Uuid,
    command_name: &str,
    params: &Value,
) -> ApiResult<MatchedGrant> {
    let assignments = store::load_enabled_assignment_details(pool, identity_id).await?;
    if assignments.is_empty() {
        return Err(ApiError::Forbidden);
    }

    let authz_tags = machines::load_authz_tags(pool, machine_id).await?;
    let matches = find_matching_grants(&assignments, machine_id, &authz_tags, command_name);
    let Some(selected) = select_most_restrictive_grant(&matches, command_name, params) else {
        return Err(ApiError::Forbidden);
    };

    let known: Option<(String,)> = sqlx::query_as(
        "SELECT risk_level FROM command_definitions WHERE name = $1",
    )
    .bind(command_name)
    .fetch_optional(pool)
    .await?;
    if known.is_none() {
        return Err(ApiError::BadRequest(format!(
            "unknown command: {command_name}"
        )));
    }

    let rules = profile_to_rules(&selected.detail.capability_profile);
    validate_command_params(command_name, params, &rules).await?;

    crate::content_policy::enforce_content_policy(
        pool,
        identity_id,
        &rules,
        command_name,
        params,
        None,
    )
    .await?;

    Ok(MatchedGrant {
        assignment_id: selected.assignment.id,
        access_grant_id: selected.assignment.access_grant_id,
        capability_profile: selected.detail.capability_profile,
        requires_approval_for_shell: selected.assignment.requires_approval_for_shell,
        requires_approval_for_elevated: selected.assignment.requires_approval_for_elevated,
    })
}

async fn validate_command_params(
    command_name: &str,
    params: &Value,
    rules: &CapabilityProfileRules,
) -> ApiResult<()> {
    if command_name == "shell.run" {
        permissions::validate_shell_params(params, rules)?;
    } else if command_name == "file.pull" {
        permissions::validate_file_pull_params(params, rules)?;
    } else if command_name == "file.push" {
        permissions::validate_file_push_params(params, rules)?;
    } else if command_name == "remote.download" {
        permissions::validate_remote_download_params(params, rules)?;
        permissions::validate_remote_download_resolved_host(params).await?;
    } else if matches!(command_name, "file.copy" | "file.move" | "folder.move" | "folder.copy") {
        permissions::validate_src_dest_params(params, rules)?;
    } else if matches!(command_name, "file.rename" | "folder.rename") {
        permissions::validate_rename_params(params, rules)?;
    } else if matches!(command_name, "file.delete" | "folder.rmdir") {
        permissions::validate_path_params(params, rules)?;
    } else if command_name == "folder.mkdir" {
        permissions::validate_mkdir_params(params, rules)?;
    } else if command_name.starts_with("desktop.") {
        permissions::validate_desktop_params(command_name, params, rules)?;
    } else if command_name.starts_with("proxmox.") {
        permissions::validate_proxmox_params(command_name, params)?;
    } else if command_name == "helper.install" {
        crate::helper_install::parse_helper_component(params)?;
    }
    Ok(())
}

pub async fn preview_fleet_scope(pool: &PgPool, scope_id: Uuid) -> ApiResult<FleetScopePreview> {
    let scope = store::load_fleet_scope(pool, scope_id).await?;
    let sources = server_settings::authz_tag_sources(pool).await?;
    let rows: Vec<MachineRow> = sqlx::query_as(
        "SELECT id, hostname, os, arch, tags, operator_tags, agent_version, desktop_version,
                proxmox_version, last_seen_at, agent_healthy, agent_secs_since_last_pull,
                agent_current_command_id
         FROM machines
         WHERE deleted_at IS NULL
         ORDER BY hostname",
    )
    .fetch_all(pool)
    .await?;

    let mut machines = Vec::new();
    for row in rows {
        let authz_tags = machines::authz_tags(&row.tags, &row.operator_tags, sources)?;
        if fleet_scope_matches(&scope, row.id, &authz_tags) {
            machines.push(FleetScopePreviewMachine {
                id: row.id,
                hostname: row.hostname,
                tags: authz_tags,
            });
        }
    }

    Ok(FleetScopePreview {
        fleet_scope_id: scope_id,
        machines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::authz::{AccessGrant, AuthzProvenance};
    use hecate_protocol::permissions::ShellPolicy;

    fn sample_scope(machine_ids: Vec<&str>, tags: Vec<&str>, mode: TagMatchMode) -> FleetScope {
        FleetScope {
            id: Uuid::new_v4(),
            name: "scope".into(),
            description: String::new(),
            tag_match_mode: mode,
            provenance: AuthzProvenance::Operator,
            request_scoped: false,
            owner_ai_identity_id: None,
            machine_ids: machine_ids.into_iter().map(str::to_string).collect(),
            tags: tags.into_iter().map(str::to_string).collect(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn fleet_scope_matches_all_machines_wildcard() {
        let scope = sample_scope(vec![hecate_protocol::permissions::MACHINE_IDS_WILDCARD], vec![], TagMatchMode::Any);
        assert!(fleet_scope_matches(&scope, Uuid::new_v4(), &[]));
        assert!(fleet_scope_matches(&scope, Uuid::new_v4(), &["env:prod".into()]));
    }

    #[test]
    fn fleet_scope_matches_explicit_machine() {
        let machine_id = Uuid::new_v4();
        let scope = sample_scope(vec![machine_id.to_string().as_str()], vec![], TagMatchMode::Any);
        assert!(fleet_scope_matches(&scope, machine_id, &[]));
        assert!(!fleet_scope_matches(&scope, Uuid::new_v4(), &[]));
    }

    #[test]
    fn fleet_scope_matches_any_tag() {
        let scope = sample_scope(vec![], vec!["env:prod"], TagMatchMode::Any);
        let machine_id = Uuid::new_v4();
        assert!(fleet_scope_matches(
            &scope,
            machine_id,
            &["env:prod".into(), "os:linux".into()]
        ));
        assert!(!fleet_scope_matches(&scope, machine_id, &["env:staging".into()]));
    }

    #[test]
    fn select_most_restrictive_prefers_narrower_profile() {
        let assignment_a = GrantAssignment {
            id: Uuid::new_v4(),
            ai_identity_id: Uuid::new_v4(),
            access_grant_id: Uuid::new_v4(),
            requires_approval_for_shell: true,
            requires_approval_for_elevated: true,
            enabled: true,
            created_at: chrono::Utc::now(),
        };
        let assignment_b = GrantAssignment {
            id: Uuid::new_v4(),
            ..assignment_a.clone()
        };
        let narrow = CapabilityProfile {
            id: Uuid::new_v4(),
            name: "narrow".into(),
            description: String::new(),
            provenance: AuthzProvenance::Operator,
            request_scoped: false,
            owner_ai_identity_id: None,
            allowed_commands: vec!["system.info".into()],
            allowed_admin_commands: vec![],
            shell_policy: ShellPolicy::default(),
            elevation_policy: Default::default(),
            max_output_bytes: 1,
            max_file_bytes: 1,
            timeout_secs: 1,
            max_concurrent: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let wide = CapabilityProfile {
            allowed_commands: vec![ALLOWLIST_WILDCARD.into(), "system.info".into()],
            elevation_policy: hecate_protocol::permissions::ElevationPolicy {
                enabled: true,
                allowed_binaries: vec!["*".into()],
            },
            ..narrow.clone()
        };
        let scope = sample_scope(vec![], vec![], TagMatchMode::Any);
        let grant = AccessGrant {
            id: Uuid::new_v4(),
            name: "grant".into(),
            description: String::new(),
            provenance: AuthzProvenance::Operator,
            request_scoped: false,
            owner_ai_identity_id: None,
            fleet_scope_id: scope.id,
            capability_profile_id: narrow.id,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let matches = vec![
            MatchingGrant {
                assignment: assignment_a,
                detail: AccessGrantDetail {
                    grant: grant.clone(),
                    fleet_scope: scope.clone(),
                    capability_profile: wide,
                },
            },
            MatchingGrant {
                assignment: assignment_b,
                detail: AccessGrantDetail {
                    grant,
                    fleet_scope: scope,
                    capability_profile: narrow,
                },
            },
        ];
        let selected = select_most_restrictive_grant(&matches, "system.info", &serde_json::json!({}))
            .expect("selected");
        assert_eq!(
            selected.detail.capability_profile.allowed_commands,
            vec!["system.info".to_string()]
        );
    }
}
