//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use chrono::{DateTime, Utc};
use hecate_protocol::authz::{
    is_bootstrap_capability_profile, is_bootstrap_fleet_scope, is_bootstrap_access_grant,
    is_internal_catalog_access_grant, is_internal_catalog_capability_profile,
    is_internal_catalog_fleet_scope, is_system_capability_profile, is_system_fleet_scope,
    AccessGrant, AccessGrantDetail, BOOTSTRAP_ACCESS_GRANT_ID,
    AccessGrantSummary, AuthzProvenance, CapabilityProfile, CapabilityProfileSummary, FleetScope,
    FleetScopeSummary, GrantAssignment, ResolvedGrantAssignment, TagMatchMode,
};
use hecate_protocol::machine_tags;
use hecate_protocol::permissions::{validate_machine_ids, ShellPolicy, ElevationPolicy};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

const ALL_MACHINES_TAG: &str = "__hecate_all_machines__";

#[derive(Debug, Clone, Deserialize)]
pub struct FleetScopeInput {
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FleetScopePatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub tag_match_mode: Option<TagMatchMode>,
    pub machine_ids: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityProfileInput {
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CapabilityProfilePatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub allowed_commands: Option<Vec<String>>,
    pub allowed_admin_commands: Option<Vec<String>>,
    pub shell_policy: Option<ShellPolicy>,
    pub elevation_policy: Option<ElevationPolicy>,
    pub max_output_bytes: Option<u32>,
    pub max_file_bytes: Option<u32>,
    pub timeout_secs: Option<u32>,
    pub max_concurrent: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessGrantInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub fleet_scope_id: Uuid,
    pub capability_profile_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccessGrantPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub fleet_scope_id: Option<Uuid>,
    pub capability_profile_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GrantAssignmentInput {
    pub access_grant_id: Uuid,
    #[serde(default = "default_true")]
    pub requires_approval_for_shell: bool,
    #[serde(default = "default_true")]
    pub requires_approval_for_elevated: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct SetGrantAssignmentsInput {
    pub assignments: Vec<GrantAssignmentInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoveAssignmentsInput {
    pub assignment_ids: Vec<Uuid>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct FleetScopeRow {
    id: Uuid,
    name: String,
    description: String,
    tag_match_mode: String,
    provenance: String,
    request_scoped: bool,
    owner_ai_identity_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct CapabilityProfileRow {
    id: Uuid,
    name: String,
    description: String,
    provenance: String,
    request_scoped: bool,
    owner_ai_identity_id: Option<Uuid>,
    allowed_commands: Vec<String>,
    allowed_admin_commands: Vec<String>,
    shell_policy: serde_json::Value,
    elevation_policy: serde_json::Value,
    max_output_bytes: i32,
    max_file_bytes: i32,
    timeout_secs: i32,
    max_concurrent: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct AccessGrantRow {
    id: Uuid,
    name: String,
    description: String,
    provenance: String,
    request_scoped: bool,
    owner_ai_identity_id: Option<Uuid>,
    fleet_scope_id: Uuid,
    capability_profile_id: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct GrantAssignmentRow {
    id: Uuid,
    ai_identity_id: Uuid,
    access_grant_id: Uuid,
    requires_approval_for_shell: bool,
    requires_approval_for_elevated: bool,
    enabled: bool,
    created_at: DateTime<Utc>,
}

fn parse_tag_match_mode(raw: &str) -> ApiResult<TagMatchMode> {
    TagMatchMode::parse(raw).ok_or_else(|| ApiError::BadRequest(format!("invalid tag_match_mode: {raw}")))
}

fn parse_provenance(raw: &str) -> ApiResult<AuthzProvenance> {
    AuthzProvenance::parse(raw).ok_or_else(|| ApiError::BadRequest(format!("invalid provenance: {raw}")))
}

fn row_to_fleet_scope(row: FleetScopeRow, machine_ids: Vec<String>, tags: Vec<String>) -> ApiResult<FleetScope> {
    Ok(FleetScope {
        id: row.id,
        name: row.name,
        description: row.description,
        tag_match_mode: parse_tag_match_mode(&row.tag_match_mode)?,
        provenance: parse_provenance(&row.provenance)?,
        request_scoped: row.request_scoped,
        owner_ai_identity_id: row.owner_ai_identity_id,
        machine_ids,
        tags,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn row_to_capability_profile(row: CapabilityProfileRow) -> ApiResult<CapabilityProfile> {
    let shell_policy: ShellPolicy = serde_json::from_value(row.shell_policy)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("invalid shell_policy: {e}")))?;
    let elevation_policy: ElevationPolicy = serde_json::from_value(row.elevation_policy)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("invalid elevation_policy: {e}")))?;
    Ok(CapabilityProfile {
        id: row.id,
        name: row.name,
        description: row.description,
        provenance: parse_provenance(&row.provenance)?,
        request_scoped: row.request_scoped,
        owner_ai_identity_id: row.owner_ai_identity_id,
        allowed_commands: row.allowed_commands,
        allowed_admin_commands: row.allowed_admin_commands,
        shell_policy,
        elevation_policy,
        max_output_bytes: row.max_output_bytes as u32,
        max_file_bytes: row.max_file_bytes as u32,
        timeout_secs: row.timeout_secs as u32,
        max_concurrent: row.max_concurrent as u32,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn row_to_access_grant(row: AccessGrantRow) -> ApiResult<AccessGrant> {
    Ok(AccessGrant {
        id: row.id,
        name: row.name,
        description: row.description,
        provenance: parse_provenance(&row.provenance)?,
        request_scoped: row.request_scoped,
        owner_ai_identity_id: row.owner_ai_identity_id,
        fleet_scope_id: row.fleet_scope_id,
        capability_profile_id: row.capability_profile_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

async fn load_fleet_scope_machines(pool: &PgPool, scope_id: Uuid) -> ApiResult<Vec<String>> {
    let machine_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT machine_id FROM fleet_scope_machines WHERE fleet_scope_id = $1 ORDER BY machine_id",
    )
    .bind(scope_id)
    .fetch_all(pool)
    .await?;
    Ok(machine_ids.into_iter().map(|id| id.to_string()).collect())
}

async fn load_fleet_scope_tags(pool: &PgPool, scope_id: Uuid) -> ApiResult<Vec<String>> {
    let tags: Vec<String> = sqlx::query_scalar(
        "SELECT tag FROM fleet_scope_tags WHERE fleet_scope_id = $1 ORDER BY tag",
    )
    .bind(scope_id)
    .fetch_all(pool)
    .await?;
    Ok(tags
        .into_iter()
        .filter(|tag| tag != ALL_MACHINES_TAG)
        .collect())
}

async fn load_fleet_scope_machine_ids(pool: &PgPool, scope_id: Uuid) -> ApiResult<Vec<String>> {
    let has_all: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM fleet_scope_tags
            WHERE fleet_scope_id = $1 AND tag = $2
         )",
    )
    .bind(scope_id)
    .bind(ALL_MACHINES_TAG)
    .fetch_one(pool)
    .await?;
    let mut machine_ids = load_fleet_scope_machines(pool, scope_id).await?;
    if has_all {
        machine_ids.insert(0, hecate_protocol::permissions::MACHINE_IDS_WILDCARD.into());
    }
    Ok(machine_ids)
}

async fn load_fleet_scope_row(pool: &PgPool, id: Uuid) -> ApiResult<FleetScopeRow> {
    sqlx::query_as(
        "SELECT id, name, description, tag_match_mode::text, provenance::text, request_scoped,
                owner_ai_identity_id, created_at, updated_at
         FROM fleet_scopes WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)
}

pub async fn load_fleet_scope(pool: &PgPool, id: Uuid) -> ApiResult<FleetScope> {
    let row = load_fleet_scope_row(pool, id).await?;
    let machine_ids = load_fleet_scope_machine_ids(pool, id).await?;
    let tags = load_fleet_scope_tags(pool, id).await?;
    row_to_fleet_scope(row, machine_ids, tags)
}

async fn load_capability_profile_row(pool: &PgPool, id: Uuid) -> ApiResult<CapabilityProfileRow> {
    sqlx::query_as(
        "SELECT id, name, description, provenance::text, request_scoped, owner_ai_identity_id,
                allowed_commands, allowed_admin_commands, shell_policy, elevation_policy,
                max_output_bytes, max_file_bytes, timeout_secs, max_concurrent,
                created_at, updated_at
         FROM capability_profiles WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)
}

pub async fn load_capability_profile(pool: &PgPool, id: Uuid) -> ApiResult<CapabilityProfile> {
    row_to_capability_profile(load_capability_profile_row(pool, id).await?)
}

async fn load_access_grant_row(pool: &PgPool, id: Uuid) -> ApiResult<AccessGrantRow> {
    sqlx::query_as(
        "SELECT id, name, description, provenance::text, request_scoped, owner_ai_identity_id,
                fleet_scope_id, capability_profile_id, created_at, updated_at
         FROM access_grants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)
}

pub async fn load_access_grant(pool: &PgPool, id: Uuid) -> ApiResult<AccessGrant> {
    row_to_access_grant(load_access_grant_row(pool, id).await?)
}

async fn load_access_grant_detail(pool: &PgPool, id: Uuid) -> ApiResult<AccessGrantDetail> {
    let grant = load_access_grant(pool, id).await?;
    let fleet_scope = load_fleet_scope(pool, grant.fleet_scope_id).await?;
    let capability_profile = load_capability_profile(pool, grant.capability_profile_id).await?;
    Ok(AccessGrantDetail {
        grant,
        fleet_scope,
        capability_profile,
    })
}

fn ensure_fleet_scope_mutable(id: Uuid) -> ApiResult<()> {
    if is_system_fleet_scope(id) || is_bootstrap_fleet_scope(id) {
        return Err(ApiError::ForbiddenMessage(
            "internal fleet scopes cannot be modified".into(),
        ));
    }
    Ok(())
}

fn ensure_capability_profile_mutable(id: Uuid) -> ApiResult<()> {
    if is_system_capability_profile(id) || is_bootstrap_capability_profile(id) {
        return Err(ApiError::ForbiddenMessage(
            "internal capability profiles cannot be modified".into(),
        ));
    }
    Ok(())
}

fn ensure_access_grant_mutable(id: Uuid) -> ApiResult<()> {
    if is_internal_catalog_access_grant(id) {
        return Err(ApiError::ForbiddenMessage(
            "internal access grants cannot be modified".into(),
        ));
    }
    Ok(())
}

/// Ensures every AI identity has the hidden bootstrap grant (system.info + permissions.request).
pub async fn ensure_bootstrap_assignment(pool: &PgPool, identity_id: Uuid) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO ai_grant_assignments (
            ai_identity_id, access_grant_id,
            requires_approval_for_shell, requires_approval_for_elevated, enabled
         ) VALUES ($1, $2, true, true, true)
         ON CONFLICT (ai_identity_id, access_grant_id) DO NOTHING",
    )
    .bind(identity_id)
    .bind(BOOTSTRAP_ACCESS_GRANT_ID)
    .execute(pool)
    .await?;
    Ok(())
}

fn assignment_targets_bootstrap_grant(access_grant_id: Uuid) -> bool {
    is_bootstrap_access_grant(access_grant_id)
}

fn validate_fleet_scope_input(input: &FleetScopeInput) -> ApiResult<()> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name required".into()));
    }
    validate_machine_ids(&input.machine_ids).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    machine_tags::validate_machine_tags(&input.tags).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(())
}

fn validate_capability_profile_input(input: &CapabilityProfileInput) -> ApiResult<()> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name required".into()));
    }
    let profile = CapabilityProfile {
        id: Uuid::nil(),
        name: name.to_string(),
        description: input.description.clone(),
        provenance: AuthzProvenance::Operator,
        request_scoped: false,
        owner_ai_identity_id: None,
        allowed_commands: input.allowed_commands.clone(),
        allowed_admin_commands: input.allowed_admin_commands.clone(),
        shell_policy: input.shell_policy.clone(),
        elevation_policy: input.elevation_policy.clone(),
        max_output_bytes: input.max_output_bytes.unwrap_or(hecate_protocol::permissions::DEFAULT_MAX_OUTPUT_BYTES),
        max_file_bytes: input.max_file_bytes.unwrap_or(hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES),
        timeout_secs: input.timeout_secs.unwrap_or(hecate_protocol::permissions::DEFAULT_TIMEOUT_SECS),
        max_concurrent: input.max_concurrent.unwrap_or(hecate_protocol::permissions::DEFAULT_MAX_CONCURRENT),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    profile.validate().map_err(ApiError::BadRequest)?;
    Ok(())
}

async fn replace_fleet_scope_machines(
    pool: &PgPool,
    scope_id: Uuid,
    machine_ids: &[String],
) -> ApiResult<()> {
    validate_machine_ids(machine_ids).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    sqlx::query("DELETE FROM fleet_scope_machines WHERE fleet_scope_id = $1")
        .bind(scope_id)
        .execute(pool)
        .await?;
    sqlx::query(
        "DELETE FROM fleet_scope_tags WHERE fleet_scope_id = $1 AND tag = $2",
    )
    .bind(scope_id)
    .bind(ALL_MACHINES_TAG)
    .execute(pool)
    .await?;
    if machine_ids.iter().any(|id| id == hecate_protocol::permissions::MACHINE_IDS_WILDCARD) {
        sqlx::query("INSERT INTO fleet_scope_tags (fleet_scope_id, tag) VALUES ($1, $2)")
            .bind(scope_id)
            .bind(ALL_MACHINES_TAG)
            .execute(pool)
            .await?;
    }
    for machine_id in machine_ids {
        if machine_id == hecate_protocol::permissions::MACHINE_IDS_WILDCARD {
            continue;
        }
        let machine_uuid = Uuid::parse_str(machine_id)
            .map_err(|_| ApiError::BadRequest(format!("invalid machine id: {machine_id}")))?;
        sqlx::query(
            "INSERT INTO fleet_scope_machines (fleet_scope_id, machine_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(scope_id)
        .bind(machine_uuid)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn replace_fleet_scope_tags(pool: &PgPool, scope_id: Uuid, tags: &[String]) -> ApiResult<()> {
    machine_tags::validate_machine_tags(tags).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    sqlx::query("DELETE FROM fleet_scope_tags WHERE fleet_scope_id = $1")
        .bind(scope_id)
        .execute(pool)
        .await?;
    for tag in tags {
        sqlx::query("INSERT INTO fleet_scope_tags (fleet_scope_id, tag) VALUES ($1, $2)")
            .bind(scope_id)
            .bind(tag)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn list_fleet_scopes(pool: &PgPool) -> ApiResult<Vec<FleetScope>> {
    let rows: Vec<FleetScopeRow> = sqlx::query_as(
        "SELECT id, name, description, tag_match_mode::text, provenance::text, request_scoped,
                owner_ai_identity_id, created_at, updated_at
         FROM fleet_scopes
         ORDER BY CASE WHEN provenance = 'system' THEN 0 ELSE 1 END, name",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let machine_ids = load_fleet_scope_machine_ids(pool, row.id).await?;
        let tags = load_fleet_scope_tags(pool, row.id).await?;
        out.push(row_to_fleet_scope(row, machine_ids, tags)?);
    }
    out.retain(|scope| !is_internal_catalog_fleet_scope(scope.id));
    Ok(out)
}

pub async fn get_fleet_scope(pool: &PgPool, id: Uuid) -> ApiResult<FleetScope> {
    load_fleet_scope(pool, id).await
}

pub async fn create_fleet_scope(pool: &PgPool, input: FleetScopeInput) -> ApiResult<FleetScope> {
    validate_fleet_scope_input(&input)?;
    let id = Uuid::new_v4();
    let name = input.name.trim().to_string();
    sqlx::query(
        "INSERT INTO fleet_scopes (id, name, description, tag_match_mode, provenance, request_scoped)
         VALUES ($1, $2, $3, $4::tag_match_mode, 'operator', false)",
    )
    .bind(id)
    .bind(&name)
    .bind(input.description.trim())
    .bind(input.tag_match_mode.as_str())
    .execute(pool)
    .await?;
    replace_fleet_scope_machines(pool, id, &input.machine_ids).await?;
    replace_fleet_scope_tags(pool, id, &input.tags).await?;
    load_fleet_scope(pool, id).await
}

pub async fn update_fleet_scope(
    pool: &PgPool,
    id: Uuid,
    patch: FleetScopePatch,
) -> ApiResult<FleetScope> {
    ensure_fleet_scope_mutable(id)?;
    let _ = load_fleet_scope_row(pool, id).await?;
    if let Some(name) = &patch.name {
        let name = name.trim();
        if name.is_empty() {
            return Err(ApiError::BadRequest("name required".into()));
        }
        sqlx::query(
            "UPDATE fleet_scopes SET name = $1, updated_at = now() WHERE id = $2",
        )
        .bind(name)
        .bind(id)
        .execute(pool)
        .await?;
    }
    if let Some(description) = &patch.description {
        sqlx::query(
            "UPDATE fleet_scopes SET description = $1, updated_at = now() WHERE id = $2",
        )
        .bind(description)
        .bind(id)
        .execute(pool)
        .await?;
    }
    if let Some(mode) = patch.tag_match_mode {
        sqlx::query(
            "UPDATE fleet_scopes SET tag_match_mode = $1::tag_match_mode, updated_at = now() WHERE id = $2",
        )
        .bind(mode.as_str())
        .bind(id)
        .execute(pool)
        .await?;
    }
    if let Some(machine_ids) = &patch.machine_ids {
        replace_fleet_scope_machines(pool, id, machine_ids).await?;
    }
    if let Some(tags) = &patch.tags {
        replace_fleet_scope_tags(pool, id, tags).await?;
    }
    if patch.name.is_some()
        || patch.description.is_some()
        || patch.tag_match_mode.is_some()
        || patch.machine_ids.is_some()
        || patch.tags.is_some()
    {
        sqlx::query("UPDATE fleet_scopes SET updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
    }
    load_fleet_scope(pool, id).await
}

pub async fn delete_fleet_scope(pool: &PgPool, id: Uuid) -> ApiResult<()> {
    ensure_fleet_scope_mutable(id)?;
    let referenced: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM access_grants WHERE fleet_scope_id = $1)",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    if referenced {
        return Err(ApiError::Conflict(
            "fleet scope is referenced by access grants".into(),
        ));
    }
    let deleted = sqlx::query("DELETE FROM fleet_scopes WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

pub async fn list_capability_profiles(pool: &PgPool) -> ApiResult<Vec<CapabilityProfile>> {
    let rows: Vec<CapabilityProfileRow> = sqlx::query_as(
        "SELECT id, name, description, provenance::text, request_scoped, owner_ai_identity_id,
                allowed_commands, allowed_admin_commands, shell_policy, elevation_policy,
                max_output_bytes, max_file_bytes, timeout_secs, max_concurrent,
                created_at, updated_at
         FROM capability_profiles
         ORDER BY CASE WHEN provenance = 'system' THEN 0 ELSE 1 END, name",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(row_to_capability_profile)
        .filter(|profile| profile.as_ref().map(|p| !is_internal_catalog_capability_profile(p.id)).unwrap_or(true))
        .collect()
}

pub async fn get_capability_profile(pool: &PgPool, id: Uuid) -> ApiResult<CapabilityProfile> {
    load_capability_profile(pool, id).await
}

pub async fn create_capability_profile(
    pool: &PgPool,
    input: CapabilityProfileInput,
) -> ApiResult<CapabilityProfile> {
    validate_capability_profile_input(&input)?;
    let id = Uuid::new_v4();
    let name = input.name.trim().to_string();
    let shell_policy = serde_json::to_value(&input.shell_policy)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let elevation_policy = serde_json::to_value(&input.elevation_policy)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    sqlx::query(
        "INSERT INTO capability_profiles (
            id, name, description, provenance, request_scoped,
            allowed_commands, allowed_admin_commands, shell_policy, elevation_policy,
            max_output_bytes, max_file_bytes, timeout_secs, max_concurrent
         ) VALUES (
            $1, $2, $3, 'operator', false,
            $4, $5, $6, $7,
            COALESCE($8, 1048576), COALESCE($9, 52428800), COALESCE($10, 30), COALESCE($11, 4)
         )",
    )
    .bind(id)
    .bind(&name)
    .bind(input.description.trim())
    .bind(&input.allowed_commands)
    .bind(&input.allowed_admin_commands)
    .bind(shell_policy)
    .bind(elevation_policy)
    .bind(input.max_output_bytes.map(|v| v as i32))
    .bind(input.max_file_bytes.map(|v| v as i32))
    .bind(input.timeout_secs.map(|v| v as i32))
    .bind(input.max_concurrent.map(|v| v as i32))
    .execute(pool)
    .await?;
    load_capability_profile(pool, id).await
}

pub async fn update_capability_profile(
    pool: &PgPool,
    id: Uuid,
    patch: CapabilityProfilePatch,
) -> ApiResult<CapabilityProfile> {
    ensure_capability_profile_mutable(id)?;
    let current = load_capability_profile(pool, id).await?;
    let next = CapabilityProfile {
        name: patch.name.as_ref().map(|v| v.trim().to_string()).unwrap_or(current.name),
        description: patch.description.clone().unwrap_or(current.description),
        allowed_commands: patch.allowed_commands.clone().unwrap_or(current.allowed_commands),
        allowed_admin_commands: patch
            .allowed_admin_commands
            .clone()
            .unwrap_or(current.allowed_admin_commands),
        shell_policy: patch.shell_policy.clone().unwrap_or(current.shell_policy),
        elevation_policy: patch.elevation_policy.clone().unwrap_or(current.elevation_policy),
        max_output_bytes: patch.max_output_bytes.unwrap_or(current.max_output_bytes),
        max_file_bytes: patch.max_file_bytes.unwrap_or(current.max_file_bytes),
        timeout_secs: patch.timeout_secs.unwrap_or(current.timeout_secs),
        max_concurrent: patch.max_concurrent.unwrap_or(current.max_concurrent),
        ..current
    };
    if patch.name.as_ref().is_some_and(|name| name.trim().is_empty()) {
        return Err(ApiError::BadRequest("name required".into()));
    }
    next.validate().map_err(ApiError::BadRequest)?;
    let shell_policy = serde_json::to_value(&next.shell_policy)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let elevation_policy = serde_json::to_value(&next.elevation_policy)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    sqlx::query(
        "UPDATE capability_profiles SET
            name = $1, description = $2, allowed_commands = $3, allowed_admin_commands = $4,
            shell_policy = $5, elevation_policy = $6,
            max_output_bytes = $7, max_file_bytes = $8, timeout_secs = $9, max_concurrent = $10,
            updated_at = now()
         WHERE id = $11",
    )
    .bind(&next.name)
    .bind(&next.description)
    .bind(&next.allowed_commands)
    .bind(&next.allowed_admin_commands)
    .bind(shell_policy)
    .bind(elevation_policy)
    .bind(next.max_output_bytes as i32)
    .bind(next.max_file_bytes as i32)
    .bind(next.timeout_secs as i32)
    .bind(next.max_concurrent as i32)
    .bind(id)
    .execute(pool)
    .await?;
    load_capability_profile(pool, id).await
}

pub async fn delete_capability_profile(pool: &PgPool, id: Uuid) -> ApiResult<()> {
    ensure_capability_profile_mutable(id)?;
    let referenced: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM access_grants WHERE capability_profile_id = $1)",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    if referenced {
        return Err(ApiError::Conflict(
            "capability profile is referenced by access grants".into(),
        ));
    }
    let deleted = sqlx::query("DELETE FROM capability_profiles WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

pub async fn list_access_grants(pool: &PgPool) -> ApiResult<Vec<AccessGrantDetail>> {
    let rows: Vec<AccessGrantRow> = sqlx::query_as(
        "SELECT id, name, description, provenance::text, request_scoped, owner_ai_identity_id,
                fleet_scope_id, capability_profile_id, created_at, updated_at
         FROM access_grants ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(load_access_grant_detail(pool, row.id).await?);
    }
    out.retain(|detail| !is_internal_catalog_access_grant(detail.grant.id));
    Ok(out)
}

pub async fn get_access_grant(pool: &PgPool, id: Uuid) -> ApiResult<AccessGrantDetail> {
    load_access_grant_detail(pool, id).await
}

pub async fn create_access_grant(pool: &PgPool, input: AccessGrantInput) -> ApiResult<AccessGrantDetail> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name required".into()));
    }
    let _ = load_fleet_scope_row(pool, input.fleet_scope_id).await?;
    let _ = load_capability_profile_row(pool, input.capability_profile_id).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO access_grants (
            id, name, description, provenance, request_scoped, fleet_scope_id, capability_profile_id
         ) VALUES ($1, $2, $3, 'operator', false, $4, $5)",
    )
    .bind(id)
    .bind(name)
    .bind(input.description.trim())
    .bind(input.fleet_scope_id)
    .bind(input.capability_profile_id)
    .execute(pool)
    .await?;
    load_access_grant_detail(pool, id).await
}

pub async fn update_access_grant(
    pool: &PgPool,
    id: Uuid,
    patch: AccessGrantPatch,
) -> ApiResult<AccessGrantDetail> {
    ensure_access_grant_mutable(id)?;
    let _ = load_access_grant_row(pool, id).await?;
    if let Some(name) = &patch.name {
        let name = name.trim();
        if name.is_empty() {
            return Err(ApiError::BadRequest("name required".into()));
        }
        sqlx::query("UPDATE access_grants SET name = $1, updated_at = now() WHERE id = $2")
            .bind(name)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(description) = &patch.description {
        sqlx::query("UPDATE access_grants SET description = $1, updated_at = now() WHERE id = $2")
            .bind(description)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(fleet_scope_id) = patch.fleet_scope_id {
        let _ = load_fleet_scope_row(pool, fleet_scope_id).await?;
        sqlx::query("UPDATE access_grants SET fleet_scope_id = $1, updated_at = now() WHERE id = $2")
            .bind(fleet_scope_id)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(capability_profile_id) = patch.capability_profile_id {
        let _ = load_capability_profile_row(pool, capability_profile_id).await?;
        sqlx::query(
            "UPDATE access_grants SET capability_profile_id = $1, updated_at = now() WHERE id = $2",
        )
        .bind(capability_profile_id)
        .bind(id)
        .execute(pool)
        .await?;
    }
    load_access_grant_detail(pool, id).await
}

pub async fn delete_access_grant(pool: &PgPool, id: Uuid) -> ApiResult<()> {
    ensure_access_grant_mutable(id)?;
    let referenced: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ai_grant_assignments WHERE access_grant_id = $1)",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    if referenced {
        return Err(ApiError::Conflict(
            "access grant is assigned to AI identities".into(),
        ));
    }
    let deleted = sqlx::query("DELETE FROM access_grants WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

fn to_grant_summary(detail: &AccessGrantDetail) -> AccessGrantSummary {
    AccessGrantSummary {
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
            admin_command_count: detail.capability_profile.allowed_admin_commands.len(),
        },
    }
}

pub async fn load_grant_assignments(
    pool: &PgPool,
    identity_id: Uuid,
) -> ApiResult<Vec<ResolvedGrantAssignment>> {
    ensure_bootstrap_assignment(pool, identity_id).await?;
    let rows: Vec<GrantAssignmentRow> = sqlx::query_as(
        "SELECT id, ai_identity_id, access_grant_id, requires_approval_for_shell,
                requires_approval_for_elevated, enabled, created_at
         FROM ai_grant_assignments
         WHERE ai_identity_id = $1
         ORDER BY created_at",
    )
    .bind(identity_id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if is_internal_catalog_access_grant(row.access_grant_id) {
            continue;
        }
        let detail = load_access_grant_detail(pool, row.access_grant_id).await?;
        out.push(ResolvedGrantAssignment {
            id: row.id,
            access_grant: to_grant_summary(&detail),
            requires_approval_for_shell: row.requires_approval_for_shell,
            requires_approval_for_elevated: row.requires_approval_for_elevated,
            enabled: row.enabled,
        });
    }
    Ok(out)
}

async fn ensure_identity_exists(pool: &PgPool, identity_id: Uuid) -> ApiResult<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ai_identities WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(identity_id)
    .fetch_one(pool)
    .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

pub async fn set_grant_assignments(
    pool: &PgPool,
    identity_id: Uuid,
    input: SetGrantAssignmentsInput,
) -> ApiResult<Vec<ResolvedGrantAssignment>> {
    ensure_identity_exists(pool, identity_id).await?;
    for assignment in &input.assignments {
        if assignment_targets_bootstrap_grant(assignment.access_grant_id) {
            return Err(ApiError::BadRequest(
                "bootstrap access grant is managed automatically for every AI identity".into(),
            ));
        }
        let detail = load_access_grant_detail(pool, assignment.access_grant_id).await?;
        if detail.grant.request_scoped {
            return Err(ApiError::BadRequest(
                "cannot assign request-scoped access grants directly; promote to catalog first".into(),
            ));
        }
    }

    let mut tx = pool.begin().await?;
    sqlx::query(
        "DELETE FROM ai_grant_assignments
         WHERE ai_identity_id = $1 AND access_grant_id != $2",
    )
    .bind(identity_id)
    .bind(BOOTSTRAP_ACCESS_GRANT_ID)
    .execute(&mut *tx)
    .await?;
    for assignment in input.assignments {
        sqlx::query(
            "INSERT INTO ai_grant_assignments (
                ai_identity_id, access_grant_id,
                requires_approval_for_shell, requires_approval_for_elevated, enabled
             ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(identity_id)
        .bind(assignment.access_grant_id)
        .bind(assignment.requires_approval_for_shell)
        .bind(assignment.requires_approval_for_elevated)
        .bind(assignment.enabled)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    ensure_bootstrap_assignment(pool, identity_id).await?;
    load_grant_assignments(pool, identity_id).await
}

pub async fn remove_assignments(
    pool: &PgPool,
    identity_id: Uuid,
    input: RemoveAssignmentsInput,
) -> ApiResult<Vec<ResolvedGrantAssignment>> {
    ensure_identity_exists(pool, identity_id).await?;
    if input.assignment_ids.is_empty() {
        return Err(ApiError::BadRequest("assignment_ids required".into()));
    }
    let bootstrap_blocked: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM ai_grant_assignments
            WHERE ai_identity_id = $1
              AND access_grant_id = $2
              AND id = ANY($3)
         )",
    )
    .bind(identity_id)
    .bind(BOOTSTRAP_ACCESS_GRANT_ID)
    .bind(&input.assignment_ids)
    .fetch_one(pool)
    .await?;
    if bootstrap_blocked {
        return Err(ApiError::BadRequest(
            "bootstrap grant assignment cannot be removed".into(),
        ));
    }
    sqlx::query(
        "DELETE FROM ai_grant_assignments
         WHERE ai_identity_id = $1 AND id = ANY($2)",
    )
    .bind(identity_id)
    .bind(&input.assignment_ids)
    .execute(pool)
    .await?;
    load_grant_assignments(pool, identity_id).await
}

pub async fn promote_to_catalog(pool: &PgPool, entity: &str, id: Uuid) -> ApiResult<()> {
    let updated = match entity {
        "fleet_scope" | "fleet_scopes" => {
            if is_system_fleet_scope(id) || is_bootstrap_fleet_scope(id) {
                return Err(ApiError::ForbiddenMessage(
                    "internal fleet scopes cannot be promoted or modified".into(),
                ));
            }
            sqlx::query(
                "UPDATE fleet_scopes SET request_scoped = false, owner_ai_identity_id = NULL, provenance = 'operator', updated_at = now() WHERE id = $1",
            )
            .bind(id)
            .execute(pool)
            .await?
        }
        "capability_profile" | "capability_profiles" => {
            if is_system_capability_profile(id) || is_bootstrap_capability_profile(id) {
                return Err(ApiError::ForbiddenMessage(
                    "internal capability profiles cannot be promoted or modified".into(),
                ));
            }
            sqlx::query(
                "UPDATE capability_profiles SET request_scoped = false, owner_ai_identity_id = NULL, provenance = 'operator', updated_at = now() WHERE id = $1",
            )
            .bind(id)
            .execute(pool)
            .await?
        }
        "access_grant" | "access_grants" => {
            if is_internal_catalog_access_grant(id) {
                return Err(ApiError::ForbiddenMessage(
                    "internal access grants cannot be promoted or modified".into(),
                ));
            }
            sqlx::query(
                "UPDATE access_grants SET request_scoped = false, owner_ai_identity_id = NULL, provenance = 'operator', updated_at = now() WHERE id = $1",
            )
            .bind(id)
            .execute(pool)
            .await?
        }
        _ => {
            return Err(ApiError::BadRequest(format!(
                "unsupported entity type for promote_to_catalog: {entity}"
            )));
        }
    };
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

pub async fn remove_machine_from_fleet_scopes(pool: &PgPool, machine_id: Uuid) -> ApiResult<()> {
    sqlx::query("DELETE FROM fleet_scope_machines WHERE machine_id = $1")
        .bind(machine_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) async fn load_enabled_assignment_details(
    pool: &PgPool,
    identity_id: Uuid,
) -> ApiResult<Vec<(GrantAssignment, AccessGrantDetail)>> {
    ensure_bootstrap_assignment(pool, identity_id).await?;
    let rows: Vec<GrantAssignmentRow> = sqlx::query_as(
        "SELECT id, ai_identity_id, access_grant_id, requires_approval_for_shell,
                requires_approval_for_elevated, enabled, created_at
         FROM ai_grant_assignments
         WHERE ai_identity_id = $1 AND enabled = true
         ORDER BY created_at",
    )
    .bind(identity_id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let detail = load_access_grant_detail(pool, row.access_grant_id).await?;
        out.push((
            GrantAssignment {
                id: row.id,
                ai_identity_id: row.ai_identity_id,
                access_grant_id: row.access_grant_id,
                requires_approval_for_shell: row.requires_approval_for_shell,
                requires_approval_for_elevated: row.requires_approval_for_elevated,
                enabled: row.enabled,
                created_at: row.created_at,
            },
            detail,
        ));
    }
    Ok(out)
}

pub(crate) fn fleet_scope_has_wildcard(scope: &FleetScope) -> bool {
    hecate_protocol::permissions::machine_ids_allow_all(&scope.machine_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn seed_capability_profile_row(shell_policy: serde_json::Value) -> CapabilityProfileRow {
        CapabilityProfileRow {
            id: Uuid::new_v4(),
            name: "bootstrap".into(),
            description: String::new(),
            provenance: "seed".into(),
            request_scoped: false,
            owner_ai_identity_id: None,
            allowed_commands: vec!["system.info".into()],
            allowed_admin_commands: vec![],
            shell_policy,
            elevation_policy: serde_json::json!({}),
            max_output_bytes: 1_048_576,
            max_file_bytes: 52_428_800,
            timeout_secs: 30,
            max_concurrent: 4,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn capability_profile_row_with_empty_shell_policy_deserializes() {
        let profile = row_to_capability_profile(seed_capability_profile_row(serde_json::json!({})))
            .expect("bootstrap shell_policy should deserialize");
        assert_eq!(profile.shell_policy, ShellPolicy::default());
    }
}
