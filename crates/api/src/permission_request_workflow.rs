//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Validation, preview, and transactional apply for permission requests.

use std::collections::HashMap;

use hecate_protocol::authz::{
    AutoApproveWarning, EntityRef, PermissionRequestChanges, PermissionRequestClass,
    PermissionRequestEntitiesToCreate, PermissionRequestPreview, ProposedAccessGrant,
    ProposedCapabilityProfile, ProposedFleetScope, RequestedAssignment, TagMatchMode,
    BOOTSTRAP_ACCESS_GRANT_ID,
};
use hecate_protocol::machine_tags;
use hecate_protocol::permissions::{validate_machine_ids, ALLOWLIST_WILDCARD, MACHINE_IDS_WILDCARD};
use sqlx::PgPool;
use uuid::Uuid;

use crate::authz::{self, store};
use crate::error::{ApiError, ApiResult};

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

    let mut has_admin = false;
    let mut has_standard = false;

    for profile in &changes.propose_capability_profiles {
        validate_proposed_profile(profile)?;
        if profile.allowed_admin_commands.is_empty() {
            if !profile.allowed_commands.is_empty() {
                has_standard = true;
            }
        } else {
            has_admin = true;
        }
        if !profile.allowed_commands.is_empty() {
            has_standard = true;
        }
    }

    for grant in &changes.propose_access_grants {
        let profile = resolve_profile_for_ref(pool, changes, &grant.capability_profile).await?;
        if !profile.allowed_admin_commands.is_empty() {
            has_admin = true;
        }
        if !profile.allowed_commands.is_empty() {
            has_standard = true;
        }
    }

    for assignment in &changes.add_assignments {
        let profile = resolve_profile_for_assignment(pool, changes, assignment).await?;
        if !profile.allowed_admin_commands.is_empty() {
            has_admin = true;
        }
        if !profile.allowed_commands.is_empty() {
            has_standard = true;
        }
    }

    if has_admin && has_standard {
        return Err(ApiError::BadRequest(
            "Submit separate permission requests for admin and standard rights".into(),
        ));
    }

    Ok(if has_admin {
        PermissionRequestClass::Admin
    } else {
        PermissionRequestClass::Standard
    })
}

pub async fn build_preview(
    pool: &PgPool,
    identity_id: Uuid,
    changes: &PermissionRequestChanges,
) -> ApiResult<PermissionRequestPreview> {
    let effective_before = authz::compute_effective_rights(pool, identity_id).await?;
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
        effective_rights_before: effective_before.summary.clone(),
        effective_rights_after: effective_before.summary,
        auto_approve_warnings: warnings,
    })
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
            store::get_fleet_scope(pool, *id).await?;
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
            store::get_capability_profile(pool, *id).await?;
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
            store::get_access_grant(pool, *id).await?;
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
