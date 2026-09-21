//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Validation, preview, and transactional apply for permission requests.

use std::collections::HashMap;

use hecate_protocol::authz::{
    is_internal_catalog_access_grant, AutoApproveWarning, EffectiveRightsSummary, EntityRef,
    PermissionRequestChanges, PermissionRequestClass, PermissionRequestEntitiesToCreate,
    PermissionRequestPreview, ProposedCapabilityProfile, RequestedAssignment,
    BOOTSTRAP_ACCESS_GRANT_ID,
};
use hecate_protocol::permissions::{
    machine_ids_allow_all, validate_machine_ids, ALLOWLIST_WILDCARD, MACHINE_IDS_WILDCARD,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::authz::{self, store};
use crate::error::{ApiError, ApiResult};
use crate::machines;
use crate::server_settings;

const MIN_REASON_LEN: usize = 10;
const MAX_REASON_LEN: usize = 2000;
const AUDIT_LIST_CMD: &str = "admin.audit.list";

pub fn validate_reason(reason: &str) -> ApiResult<()> {
    let trimmed = reason.trim();
    if trimmed.len() < MIN_REASON_LEN {
        return Err(ApiError::BadRequest(format!(
            "reason must be at least {MIN_REASON_LEN} characters"
        )));
    }
    if trimmed.len() > MAX_REASON_LEN {
        return Err(ApiError::BadRequest(format!(
            "reason must be at most {MAX_REASON_LEN} characters"
        )));
    }
    if !trimmed.chars().any(|c| c.is_alphanumeric()) {
        return Err(ApiError::BadRequest(
            "reason must contain at least one letter or digit".into(),
        ));
    }
    Ok(())
}

pub async fn validate_and_classify(
    pool: &PgPool,
    changes: &PermissionRequestChanges,
) -> ApiResult<PermissionRequestClass> {
    if changes.propose_fleet_scopes.is_empty()
        && changes.propose_capability_profiles.is_empty()
        && changes.propose_access_grants.is_empty()
        && changes.add_assignments.is_empty()
        && changes.remove_assignment_ids.is_empty()
    {
        return Err(ApiError::BadRequest("requested_changes is empty".into()));
    }

    let mut has_admin_cmds = false;
    let mut has_standard_cmds = false;
    let mut force_admin = false;

    for scope in &changes.propose_fleet_scopes {
        validate_machine_ids(&scope.machine_ids).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        if machine_ids_allow_all(&scope.machine_ids) {
            force_admin = true;
        }
    }

    for profile in &changes.propose_capability_profiles {
        validate_proposed_profile(profile)?;
        classify_profile_flags(
            profile,
            &mut has_admin_cmds,
            &mut has_standard_cmds,
            &mut force_admin,
        );
    }

    for grant in &changes.propose_access_grants {
        let profile = resolve_profile_for_ref(pool, changes, &grant.capability_profile).await?;
        classify_profile_flags(
            &profile,
            &mut has_admin_cmds,
            &mut has_standard_cmds,
            &mut force_admin,
        );
        if scope_ref_is_fleet_wildcard(pool, changes, &grant.fleet_scope).await? {
            force_admin = true;
        }
    }

    for assignment in &changes.add_assignments {
        let profile = resolve_profile_for_assignment(pool, changes, assignment).await?;
        classify_profile_flags(
            &profile,
            &mut has_admin_cmds,
            &mut has_standard_cmds,
            &mut force_admin,
        );
        if assignment_scope_is_fleet_wildcard(pool, changes, assignment).await? {
            force_admin = true;
        }
    }

    if has_admin_cmds && has_standard_cmds {
        return Err(ApiError::BadRequest(
            "Submit separate permission requests for admin and standard rights".into(),
        ));
    }

    Ok(if has_admin_cmds || force_admin {
        PermissionRequestClass::Admin
    } else {
        PermissionRequestClass::Standard
    })
}

fn classify_profile_flags(
    profile: &ProposedCapabilityProfile,
    has_admin_cmds: &mut bool,
    has_standard_cmds: &mut bool,
    force_admin: &mut bool,
) {
    if !profile.allowed_admin_commands.is_empty() {
        *has_admin_cmds = true;
    }
    if !profile.allowed_commands.is_empty() {
        *has_standard_cmds = true;
    }
    if profile.elevation_policy.enabled {
        *force_admin = true;
    }
}

async fn scope_ref_is_fleet_wildcard(
    pool: &PgPool,
    changes: &PermissionRequestChanges,
    entity_ref: &EntityRef,
) -> ApiResult<bool> {
    match entity_ref {
        EntityRef::Proposed { key } => Ok(changes
            .propose_fleet_scopes
            .iter()
            .find(|s| &s.key == key)
            .map(|s| machine_ids_allow_all(&s.machine_ids))
            .unwrap_or(false)),
        EntityRef::Id { id } => {
            reject_if_request_scoped_scope(pool, *id).await?;
            let scope = store::get_fleet_scope(pool, *id).await?;
            Ok(machine_ids_allow_all(&scope.machine_ids))
        }
    }
}

async fn assignment_scope_is_fleet_wildcard(
    pool: &PgPool,
    changes: &PermissionRequestChanges,
    assignment: &RequestedAssignment,
) -> ApiResult<bool> {
    match &assignment.access_grant {
        EntityRef::Proposed { key } => {
            let grant = changes
                .propose_access_grants
                .iter()
                .find(|g| &g.key == key)
                .ok_or_else(|| ApiError::BadRequest(format!("unknown proposed grant key: {key}")))?;
            scope_ref_is_fleet_wildcard(pool, changes, &grant.fleet_scope).await
        }
        EntityRef::Id { id } => {
            reject_if_request_scoped_grant(pool, *id).await?;
            let detail = store::get_access_grant(pool, *id).await?;
            Ok(machine_ids_allow_all(&detail.fleet_scope.machine_ids))
        }
    }
}

pub async fn build_preview(
    pool: &PgPool,
    identity_id: Uuid,
    changes: &PermissionRequestChanges,
) -> ApiResult<PermissionRequestPreview> {
    let effective_before = authz::compute_effective_rights(pool, identity_id).await?;
    let effective_after = simulate_effective_rights_after(pool, identity_id, changes).await?;
    let mut warnings = Vec::new();
    for assignment in &changes.add_assignments {
        if !assignment.requires_approval_for_shell {
            warnings.push(AutoApproveWarning {
                kind: "shell".into(),
                message: "Disables operator approval for high-risk shell commands".into(),
                assignment_labels: vec!["pending assignment".into()],
            });
        }
        if !assignment.requires_approval_for_elevated {
            warnings.push(AutoApproveWarning {
                kind: "elevated".into(),
                message: "Disables operator approval for elevated commands".into(),
                assignment_labels: vec!["pending assignment".into()],
            });
        }
    }

    Ok(PermissionRequestPreview {
        entities_to_create: PermissionRequestEntitiesToCreate {
            fleet_scopes: changes.propose_fleet_scopes.clone(),
            capability_profiles: changes.propose_capability_profiles.clone(),
            access_grants: changes.propose_access_grants.clone(),
        },
        assignments_to_add: changes.add_assignments.clone(),
        assignments_to_remove: changes.remove_assignment_ids.clone(),
        effective_rights_before: effective_before.summary,
        effective_rights_after: effective_after,
        auto_approve_warnings: warnings,
    })
}

async fn simulate_effective_rights_after(
    pool: &PgPool,
    identity_id: Uuid,
    changes: &PermissionRequestChanges,
) -> ApiResult<EffectiveRightsSummary> {
    let current = store::load_enabled_assignment_details(pool, identity_id).await?;
    let remove: std::collections::HashSet<Uuid> =
        changes.remove_assignment_ids.iter().copied().collect();

    let mut allowed_commands = Vec::new();
    let mut allowed_admin_commands = Vec::new();
    let mut machine_ids = std::collections::BTreeSet::new();
    let mut machine_tags = std::collections::BTreeSet::new();
    let mut max_concurrent_limit = u32::MAX;
    let mut assignment_count = 0usize;
    let mut matching_scopes: Vec<hecate_protocol::authz::FleetScope> = Vec::new();

    let mut kept_grant_ids = std::collections::HashSet::new();

    for (assignment, detail) in &current {
        if remove.contains(&assignment.id) {
            continue;
        }
        kept_grant_ids.insert(detail.grant.id);
        merge_preview_strings(
            &mut allowed_commands,
            &detail.capability_profile.allowed_commands,
        );
        merge_preview_strings(
            &mut allowed_admin_commands,
            &detail.capability_profile.allowed_admin_commands,
        );
        max_concurrent_limit =
            max_concurrent_limit.min(detail.capability_profile.max_concurrent.max(1));
        for machine_id in &detail.fleet_scope.machine_ids {
            machine_ids.insert(machine_id.clone());
        }
        for tag in &detail.fleet_scope.tags {
            machine_tags.insert(tag.clone());
        }
        if !is_internal_catalog_access_grant(detail.grant.id) {
            assignment_count += 1;
            matching_scopes.push(detail.fleet_scope.clone());
        }
    }

    for assignment in &changes.add_assignments {
        let (profile, scope, grant_id) =
            resolve_assignment_preview_parts(pool, changes, assignment).await?;
        let replacing = grant_id.is_some_and(|id| kept_grant_ids.contains(&id));
        if let Some(id) = grant_id {
            kept_grant_ids.insert(id);
        }
        merge_preview_strings(&mut allowed_commands, &profile.allowed_commands);
        merge_preview_strings(&mut allowed_admin_commands, &profile.allowed_admin_commands);
        let max_c = profile.max_concurrent.unwrap_or(4).max(1);
        max_concurrent_limit = max_concurrent_limit.min(max_c);
        for machine_id in &scope.machine_ids {
            machine_ids.insert(machine_id.clone());
        }
        for tag in &scope.tags {
            machine_tags.insert(tag.clone());
        }
        let is_internal = grant_id.is_some_and(is_internal_catalog_access_grant);
        if !is_internal {
            if !replacing {
                assignment_count += 1;
            }
            matching_scopes.push(scope);
        }
    }

    let sources = server_settings::authz_tag_sources(pool).await?;
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
                matching_scopes
                    .iter()
                    .any(|scope| authz::fleet_scope_matches(scope, row.id, &authz_tags))
            })
            .count()
    };

    Ok(EffectiveRightsSummary {
        assignment_count,
        machine_scope_count,
        allowed_command_count: allowed_commands.len(),
        allowed_admin_command_count: allowed_admin_commands.len(),
        max_concurrent_limit: if max_concurrent_limit == u32::MAX {
            0
        } else {
            max_concurrent_limit
        },
    })
}

fn merge_preview_strings(target: &mut Vec<String>, source: &[String]) {
    if source.iter().any(|entry| entry == ALLOWLIST_WILDCARD) {
        *target = vec![ALLOWLIST_WILDCARD.into()];
        return;
    }
    if target.iter().any(|entry| entry == ALLOWLIST_WILDCARD) {
        return;
    }
    for item in source {
        if !target.contains(item) {
            target.push(item.clone());
        }
    }
    target.sort();
}

async fn resolve_assignment_preview_parts(
    pool: &PgPool,
    changes: &PermissionRequestChanges,
    assignment: &RequestedAssignment,
) -> ApiResult<(
    ProposedCapabilityProfile,
    hecate_protocol::authz::FleetScope,
    Option<Uuid>,
)> {
    match &assignment.access_grant {
        EntityRef::Id { id } => {
            reject_if_request_scoped_grant(pool, *id).await?;
            let detail = store::get_access_grant(pool, *id).await?;
            Ok((
                ProposedCapabilityProfile {
                    key: detail.capability_profile.id.to_string(),
                    name: detail.capability_profile.name.clone(),
                    description: detail.capability_profile.description.clone(),
                    allowed_commands: detail.capability_profile.allowed_commands.clone(),
                    allowed_admin_commands: detail.capability_profile.allowed_admin_commands.clone(),
                    shell_policy: detail.capability_profile.shell_policy.clone(),
                    elevation_policy: detail.capability_profile.elevation_policy.clone(),
                    max_output_bytes: Some(detail.capability_profile.max_output_bytes),
                    max_file_bytes: Some(detail.capability_profile.max_file_bytes),
                    timeout_secs: Some(detail.capability_profile.timeout_secs),
                    max_concurrent: Some(detail.capability_profile.max_concurrent),
                },
                detail.fleet_scope,
                Some(*id),
            ))
        }
        EntityRef::Proposed { key } => {
            let grant = changes
                .propose_access_grants
                .iter()
                .find(|g| &g.key == key)
                .ok_or_else(|| ApiError::BadRequest(format!("unknown proposed grant key: {key}")))?;
            let profile = resolve_profile_for_ref(pool, changes, &grant.capability_profile).await?;
            let scope = resolve_scope_for_preview(pool, changes, &grant.fleet_scope).await?;
            Ok((profile, scope, None))
        }
    }
}

async fn resolve_scope_for_preview(
    pool: &PgPool,
    changes: &PermissionRequestChanges,
    entity_ref: &EntityRef,
) -> ApiResult<hecate_protocol::authz::FleetScope> {
    match entity_ref {
        EntityRef::Proposed { key } => {
            let proposed = changes
                .propose_fleet_scopes
                .iter()
                .find(|s| &s.key == key)
                .ok_or_else(|| ApiError::BadRequest(format!("unknown proposed scope key: {key}")))?;
            Ok(hecate_protocol::authz::FleetScope {
                id: Uuid::nil(),
                name: proposed.name.clone(),
                description: proposed.description.clone(),
                tag_match_mode: proposed.tag_match_mode,
                provenance: hecate_protocol::authz::AuthzProvenance::PermissionRequest,
                request_scoped: true,
                owner_ai_identity_id: None,
                machine_ids: proposed.machine_ids.clone(),
                tags: proposed.tags.clone(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
        }
        EntityRef::Id { id } => {
            reject_if_request_scoped_scope(pool, *id).await?;
            store::get_fleet_scope(pool, *id).await
        }
    }
}

pub async fn validate_remove_assignments(
    pool: &PgPool,
    identity_id: Uuid,
    changes: &PermissionRequestChanges,
) -> ApiResult<()> {
    if changes.remove_assignment_ids.is_empty() {
        return Ok(());
    }

    for assignment_id in &changes.remove_assignment_ids {
        let row: Option<(Uuid, Vec<String>)> = sqlx::query_as(
            "SELECT aga.access_grant_id, cp.allowed_admin_commands
             FROM ai_grant_assignments aga
             JOIN access_grants ag ON ag.id = aga.access_grant_id
             JOIN capability_profiles cp ON cp.id = ag.capability_profile_id
             WHERE aga.id = $1 AND aga.ai_identity_id = $2",
        )
        .bind(assignment_id)
        .bind(identity_id)
        .fetch_optional(pool)
        .await?;

        let Some((access_grant_id, admin_cmds)) = row else {
            return Err(ApiError::BadRequest(format!(
                "assignment {assignment_id} not found for identity"
            )));
        };

        if access_grant_id == BOOTSTRAP_ACCESS_GRANT_ID {
            return Err(ApiError::BadRequest(
                "cannot remove bootstrap grant assignment".into(),
            ));
        }

        if admin_cmds.iter().any(|cmd| cmd == AUDIT_LIST_CMD) {
            return Err(ApiError::BadRequest(
                "cannot remove audit grant assignments via permission request".into(),
            ));
        }
    }

    Ok(())
}

pub async fn apply_approved_changes(
    pool: &PgPool,
    identity_id: Uuid,
    changes: &PermissionRequestChanges,
) -> ApiResult<()> {
    let mut tx = pool.begin().await?;

    let mut scope_ids: HashMap<String, Uuid> = HashMap::new();
    for scope in &changes.propose_fleet_scopes {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO fleet_scopes (
                id, name, description, tag_match_mode, provenance, request_scoped, owner_ai_identity_id
             ) VALUES ($1, $2, $3, $4::tag_match_mode, 'permission_request', true, $5)",
        )
        .bind(id)
        .bind(&scope.name)
        .bind(&scope.description)
        .bind(scope.tag_match_mode.as_str())
        .bind(identity_id)
        .execute(&mut *tx)
        .await?;
        for machine_id in &scope.machine_ids {
            if machine_id == MACHINE_IDS_WILDCARD {
                continue;
            }
            let machine_uuid = Uuid::parse_str(machine_id)
                .map_err(|_| ApiError::BadRequest(format!("invalid machine id: {machine_id}")))?;
            sqlx::query(
                "INSERT INTO fleet_scope_machines (fleet_scope_id, machine_id) VALUES ($1, $2)",
            )
            .bind(id)
            .bind(machine_uuid)
            .execute(&mut *tx)
            .await?;
        }
        for tag in &scope.tags {
            sqlx::query(
                "INSERT INTO fleet_scope_tags (fleet_scope_id, tag) VALUES ($1, $2)",
            )
            .bind(id)
            .bind(tag)
            .execute(&mut *tx)
            .await?;
        }
        scope_ids.insert(scope.key.clone(), id);
    }

    let mut profile_ids: HashMap<String, Uuid> = HashMap::new();
    for profile in &changes.propose_capability_profiles {
        validate_proposed_profile(profile)?;
        let id = Uuid::new_v4();
        let shell_policy = serde_json::to_value(&profile.shell_policy)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
        let elevation_policy = serde_json::to_value(&profile.elevation_policy)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
        sqlx::query(
            "INSERT INTO capability_profiles (
                id, name, description, provenance, request_scoped, owner_ai_identity_id,
                allowed_commands, allowed_admin_commands, shell_policy, elevation_policy,
                max_output_bytes, max_file_bytes, timeout_secs, max_concurrent
             ) VALUES (
                $1, $2, $3, 'permission_request', true, $4,
                $5, $6, $7, $8,
                COALESCE($9, 1048576), COALESCE($10, 52428800), COALESCE($11, 30), COALESCE($12, 4)
             )",
        )
        .bind(id)
        .bind(&profile.name)
        .bind(&profile.description)
        .bind(identity_id)
        .bind(&profile.allowed_commands)
        .bind(&profile.allowed_admin_commands)
        .bind(shell_policy)
        .bind(elevation_policy)
        .bind(profile.max_output_bytes.map(|v| v as i32))
        .bind(profile.max_file_bytes.map(|v| v as i32))
        .bind(profile.timeout_secs.map(|v| v as i32))
        .bind(profile.max_concurrent.map(|v| v as i32))
        .execute(&mut *tx)
        .await?;
        profile_ids.insert(profile.key.clone(), id);
    }

    let mut grant_ids: HashMap<String, Uuid> = HashMap::new();
    for grant in &changes.propose_access_grants {
        let fleet_scope_id = resolve_scope_id(pool, changes, &grant.fleet_scope, &scope_ids).await?;
        let capability_profile_id =
            resolve_profile_id(pool, changes, &grant.capability_profile, &profile_ids).await?;
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO access_grants (
                id, name, description, provenance, request_scoped, owner_ai_identity_id,
                fleet_scope_id, capability_profile_id
             ) VALUES ($1, $2, $3, 'permission_request', true, $4, $5, $6)",
        )
        .bind(id)
        .bind(&grant.name)
        .bind(&grant.description)
        .bind(identity_id)
        .bind(fleet_scope_id)
        .bind(capability_profile_id)
        .execute(&mut *tx)
        .await?;
        grant_ids.insert(grant.key.clone(), id);
    }

    for assignment in &changes.add_assignments {
        let access_grant_id =
            resolve_grant_id(pool, changes, &assignment.access_grant, &grant_ids).await?;
        sqlx::query(
            "INSERT INTO ai_grant_assignments (
                ai_identity_id, access_grant_id,
                requires_approval_for_shell, requires_approval_for_elevated, enabled
             ) VALUES ($1, $2, $3, $4, true)
             ON CONFLICT (ai_identity_id, access_grant_id) DO UPDATE SET
                requires_approval_for_shell = EXCLUDED.requires_approval_for_shell,
                requires_approval_for_elevated = EXCLUDED.requires_approval_for_elevated,
                enabled = true",
        )
        .bind(identity_id)
        .bind(access_grant_id)
        .bind(assignment.requires_approval_for_shell)
        .bind(assignment.requires_approval_for_elevated)
        .execute(&mut *tx)
        .await?;
    }

    if !changes.remove_assignment_ids.is_empty() {
        sqlx::query(
            "DELETE FROM ai_grant_assignments
             WHERE ai_identity_id = $1 AND id = ANY($2)",
        )
        .bind(identity_id)
        .bind(&changes.remove_assignment_ids)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

fn validate_proposed_profile(profile: &ProposedCapabilityProfile) -> ApiResult<()> {
    if profile.allowed_commands.iter().any(|c| c == ALLOWLIST_WILDCARD) {
        return Err(ApiError::BadRequest("wildcards not allowed in proposals".into()));
    }
    if profile
        .allowed_admin_commands
        .iter()
        .any(|c| c == ALLOWLIST_WILDCARD)
    {
        return Err(ApiError::BadRequest("wildcards not allowed in proposals".into()));
    }
    let capability = hecate_protocol::authz::CapabilityProfile {
        id: Uuid::nil(),
        name: profile.name.clone(),
        description: profile.description.clone(),
        provenance: hecate_protocol::authz::AuthzProvenance::PermissionRequest,
        request_scoped: true,
        owner_ai_identity_id: None,
        allowed_commands: profile.allowed_commands.clone(),
        allowed_admin_commands: profile.allowed_admin_commands.clone(),
        shell_policy: profile.shell_policy.clone(),
        elevation_policy: profile.elevation_policy.clone(),
        max_output_bytes: profile.max_output_bytes.unwrap_or(1_048_576),
        max_file_bytes: profile.max_file_bytes.unwrap_or(52_428_800),
        timeout_secs: profile.timeout_secs.unwrap_or(30),
        max_concurrent: profile.max_concurrent.unwrap_or(4),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    capability.validate().map_err(ApiError::BadRequest)?;
    Ok(())
}

async fn resolve_profile_for_ref(
    pool: &PgPool,
    changes: &PermissionRequestChanges,
    entity_ref: &EntityRef,
) -> ApiResult<ProposedCapabilityProfile> {
    match entity_ref {
        EntityRef::Proposed { key } => changes
            .propose_capability_profiles
            .iter()
            .find(|p| &p.key == key)
            .cloned()
            .ok_or_else(|| ApiError::BadRequest(format!("unknown proposed profile key: {key}"))),
        EntityRef::Id { id } => {
            reject_if_request_scoped_profile(pool, *id).await?;
            let profile = store::get_capability_profile(pool, *id).await?;
            Ok(ProposedCapabilityProfile {
                key: id.to_string(),
                name: profile.name,
                description: profile.description,
                allowed_commands: profile.allowed_commands,
                allowed_admin_commands: profile.allowed_admin_commands,
                shell_policy: profile.shell_policy,
                elevation_policy: profile.elevation_policy,
                max_output_bytes: Some(profile.max_output_bytes),
                max_file_bytes: Some(profile.max_file_bytes),
                timeout_secs: Some(profile.timeout_secs),
                max_concurrent: Some(profile.max_concurrent),
            })
        }
    }
}

async fn resolve_profile_for_assignment(
    pool: &PgPool,
    changes: &PermissionRequestChanges,
    assignment: &RequestedAssignment,
) -> ApiResult<ProposedCapabilityProfile> {
    let grant_ref = &assignment.access_grant;
    let grant = match grant_ref {
        EntityRef::Proposed { key } => changes
            .propose_access_grants
            .iter()
            .find(|g| &g.key == key)
            .ok_or_else(|| ApiError::BadRequest(format!("unknown proposed grant key: {key}")))?,
        EntityRef::Id { id } => {
            reject_if_request_scoped_grant(pool, *id).await?;
            let detail = store::get_access_grant(pool, *id).await?;
            return Ok(ProposedCapabilityProfile {
                key: detail.capability_profile.id.to_string(),
                name: detail.capability_profile.name,
                description: detail.capability_profile.description,
                allowed_commands: detail.capability_profile.allowed_commands,
                allowed_admin_commands: detail.capability_profile.allowed_admin_commands,
                shell_policy: detail.capability_profile.shell_policy,
                elevation_policy: detail.capability_profile.elevation_policy,
                max_output_bytes: Some(detail.capability_profile.max_output_bytes),
                max_file_bytes: Some(detail.capability_profile.max_file_bytes),
                timeout_secs: Some(detail.capability_profile.timeout_secs),
                max_concurrent: Some(detail.capability_profile.max_concurrent),
            });
        }
    };
    resolve_profile_for_ref(pool, changes, &grant.capability_profile).await
}

async fn reject_if_request_scoped_scope(pool: &PgPool, id: Uuid) -> ApiResult<()> {
    let scope = store::get_fleet_scope(pool, id).await?;
    if scope.request_scoped {
        return Err(ApiError::BadRequest(
            "cannot reference request-scoped fleet scopes; promote to catalog first".into(),
        ));
    }
    Ok(())
}

async fn reject_if_request_scoped_profile(pool: &PgPool, id: Uuid) -> ApiResult<()> {
    let profile = store::get_capability_profile(pool, id).await?;
    if profile.request_scoped {
        return Err(ApiError::BadRequest(
            "cannot reference request-scoped capability profiles; promote to catalog first".into(),
        ));
    }
    Ok(())
}

async fn reject_if_request_scoped_grant(pool: &PgPool, id: Uuid) -> ApiResult<()> {
    let detail = store::get_access_grant(pool, id).await?;
    if detail.grant.request_scoped {
        return Err(ApiError::BadRequest(
            "cannot reference request-scoped access grants; promote to catalog first".into(),
        ));
    }
    Ok(())
}

async fn resolve_scope_id(
    pool: &PgPool,
    _changes: &PermissionRequestChanges,
    entity_ref: &EntityRef,
    proposed: &HashMap<String, Uuid>,
) -> ApiResult<Uuid> {
    match entity_ref {
        EntityRef::Proposed { key } => proposed
            .get(key)
            .copied()
            .ok_or_else(|| ApiError::BadRequest(format!("unknown proposed scope key: {key}"))),
        EntityRef::Id { id } => {
            reject_if_request_scoped_scope(pool, *id).await?;
            Ok(*id)
        }
    }
}

async fn resolve_profile_id(
    pool: &PgPool,
    _changes: &PermissionRequestChanges,
    entity_ref: &EntityRef,
    proposed: &HashMap<String, Uuid>,
) -> ApiResult<Uuid> {
    match entity_ref {
        EntityRef::Proposed { key } => proposed
            .get(key)
            .copied()
            .ok_or_else(|| ApiError::BadRequest(format!("unknown proposed profile key: {key}"))),
        EntityRef::Id { id } => {
            reject_if_request_scoped_profile(pool, *id).await?;
            Ok(*id)
        }
    }
}

async fn resolve_grant_id(
    pool: &PgPool,
    _changes: &PermissionRequestChanges,
    entity_ref: &EntityRef,
    proposed: &HashMap<String, Uuid>,
) -> ApiResult<Uuid> {
    match entity_ref {
        EntityRef::Proposed { key } => proposed
            .get(key)
            .copied()
            .ok_or_else(|| ApiError::BadRequest(format!("unknown proposed grant key: {key}"))),
        EntityRef::Id { id } => {
            reject_if_request_scoped_grant(pool, *id).await?;
            Ok(*id)
        }
    }
}

pub fn ai_may_approve_standard_tier1(changes: &PermissionRequestChanges) -> bool {
    changes.propose_fleet_scopes.is_empty()
        && changes.propose_capability_profiles.is_empty()
        && changes.propose_access_grants.is_empty()
        && changes.remove_assignment_ids.is_empty()
        && changes.add_assignments.iter().all(|a| {
            matches!(a.access_grant, EntityRef::Id { .. })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::permissions::ElevationPolicy;

    #[test]
    fn elevation_forces_admin_classification_flag() {
        let mut has_admin_cmds = false;
        let mut has_standard_cmds = false;
        let mut force_admin = false;
        let profile = ProposedCapabilityProfile {
            key: "cp1".into(),
            name: "wide".into(),
            description: String::new(),
            allowed_commands: vec!["shell.run".into()],
            allowed_admin_commands: vec![],
            shell_policy: Default::default(),
            elevation_policy: ElevationPolicy {
                enabled: true,
                allowed_binaries: vec!["*".into()],
            },
            max_output_bytes: None,
            max_file_bytes: None,
            timeout_secs: None,
            max_concurrent: None,
        };
        classify_profile_flags(
            &profile,
            &mut has_admin_cmds,
            &mut has_standard_cmds,
            &mut force_admin,
        );
        assert!(!has_admin_cmds);
        assert!(has_standard_cmds);
        assert!(force_admin);
    }

    #[test]
    fn fleet_wildcard_detected() {
        assert!(machine_ids_allow_all(&[MACHINE_IDS_WILDCARD.into()]));
        assert!(!machine_ids_allow_all(&["00000000-0000-4000-8000-000000000001".into()]));
    }
}
