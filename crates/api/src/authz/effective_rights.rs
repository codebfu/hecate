//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use hecate_protocol::authz::{
    is_internal_catalog_access_grant, AccessGrantSummary, CapabilityProfileSummary,
    EffectiveRightsReport, EffectiveRightsSummary, FleetScopeSummary, ResolvedGrantAssignment,
};
use hecate_protocol::permissions::ALLOWLIST_WILDCARD;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiResult;
use crate::machines;
use crate::server_settings;

use super::evaluator::fleet_scope_matches;
use super::store;

pub async fn compute_effective_rights(
    pool: &PgPool,
    identity_id: Uuid,
) -> ApiResult<EffectiveRightsReport> {
    let assignments = store::load_enabled_assignment_details(pool, identity_id).await?;
    let sources = server_settings::authz_tag_sources(pool).await?;

    let mut allowed_commands = Vec::new();
    let mut allowed_admin_commands = Vec::new();
    let mut machine_ids = std::collections::BTreeSet::new();
    let mut machine_tags = std::collections::BTreeSet::new();
    let mut max_concurrent_limit = u32::MAX;
    let mut resolved = Vec::new();

    for (assignment, detail) in &assignments {
        merge_strings(&mut allowed_commands, &detail.capability_profile.allowed_commands);
        merge_strings(
            &mut allowed_admin_commands,
            &detail.capability_profile.allowed_admin_commands,
        );
        max_concurrent_limit = max_concurrent_limit
            .min(detail.capability_profile.max_concurrent.max(1));

        for machine_id in &detail.fleet_scope.machine_ids {
            machine_ids.insert(machine_id.clone());
        }
        for tag in &detail.fleet_scope.tags {
            machine_tags.insert(tag.clone());
        }

        if is_internal_catalog_access_grant(detail.grant.id) {
            continue;
        }

        resolved.push(ResolvedGrantAssignment {
            id: assignment.id,
            access_grant: AccessGrantSummary {
                id: detail.grant.id,
                name: detail.grant.name.clone(),
                fleet_scope: FleetScopeSummary {
                    id: detail.fleet_scope.id,
                    name: detail.fleet_scope.name.clone(),
                    tag_match_mode: detail.fleet_scope.tag_match_mode,
                    machine_count: detail.fleet_scope.machine_ids.len(),
                    tag_count: detail.fleet_scope.tags.len(),
                },
                capability_profile: CapabilityProfileSummary {
                    id: detail.capability_profile.id,
                    name: detail.capability_profile.name.clone(),
                    command_count: detail.capability_profile.allowed_commands.len(),
                    admin_command_count: detail
                        .capability_profile
                        .allowed_admin_commands
                        .len(),
                },
            },
            requires_approval_for_shell: assignment.requires_approval_for_shell,
            requires_approval_for_elevated: assignment.requires_approval_for_elevated,
            enabled: assignment.enabled,
        });
    }

    let machine_scope_count = if machine_ids.is_empty() && machine_tags.is_empty() {
        0
    } else {
        let rows: Vec<machines::MachineRow> = sqlx::query_as(
            "SELECT id, hostname, os, arch, tags, operator_tags, agent_version,
                    desktop_version, proxmox_version, last_seen_at, agent_healthy,
                    agent_secs_since_last_pull, agent_current_command_id
             FROM machines
             WHERE deleted_at IS NULL",
        )
        .fetch_all(pool)
        .await?;
        rows.into_iter()
            .filter(|row| {
                let authz_tags =
                    machines::authz_tags(&row.tags, &row.operator_tags, sources).unwrap_or_default();
                assignments.iter().any(|(_, detail)| {
                    fleet_scope_matches(&detail.fleet_scope, row.id, &authz_tags)
                })
            })
            .count()
    };

    Ok(EffectiveRightsReport {
        summary: EffectiveRightsSummary {
            assignment_count: resolved.len(),
            machine_scope_count,
            allowed_command_count: allowed_commands.len(),
            allowed_admin_command_count: allowed_admin_commands.len(),
            max_concurrent_limit: if max_concurrent_limit == u32::MAX {
                0
            } else {
                max_concurrent_limit
            },
        },
        assignments: resolved,
        allowed_commands,
        allowed_admin_commands,
        machine_ids: machine_ids.into_iter().collect(),
        machine_tags: machine_tags.into_iter().collect(),
    })
}

fn merge_strings(target: &mut Vec<String>, source: &[String]) {
    if source.iter().any(|entry| entry == ALLOWLIST_WILDCARD) {
        *target = vec![ALLOWLIST_WILDCARD.into()];
        return;
    }
    for item in source {
        if !target.contains(item) {
            target.push(item.clone());
        }
    }
    target.sort();
}
