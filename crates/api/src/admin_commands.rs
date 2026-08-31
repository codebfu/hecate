//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use hecate_protocol::authz::PermissionRequestChanges;
use hecate_protocol::permissions::{admin_command_allowed, platform_command_allowed, ALLOWLIST_WILDCARD};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::authz::{self, store};
use crate::command_queue;
use crate::error::{ApiError, ApiResult};
use crate::feature_repo;
use crate::pagination::{CommandListQuery, ListQuery};
use crate::permission_requests::{self, PermissionRequestListQuery};
use crate::state::AppConfig;

async fn union_allowed_commands(pool: &PgPool, identity_id: Uuid) -> ApiResult<Vec<String>> {
    let assignments = store::load_enabled_assignment_details(pool, identity_id).await?;
    let mut out = Vec::new();
    for (_, detail) in assignments {
        for command in &detail.capability_profile.allowed_commands {
            if command == ALLOWLIST_WILDCARD {
                return Ok(vec![ALLOWLIST_WILDCARD.into()]);
            }
            if !out.contains(command) {
                out.push(command.clone());
            }
        }
    }
    Ok(out)
}

async fn union_allowed_admin_commands(pool: &PgPool, identity_id: Uuid) -> ApiResult<Vec<String>> {
    let assignments = store::load_enabled_assignment_details(pool, identity_id).await?;
    let mut out = Vec::new();
    for (_, detail) in assignments {
        for command in &detail.capability_profile.allowed_admin_commands {
            if command == ALLOWLIST_WILDCARD {
                return Ok(vec![ALLOWLIST_WILDCARD.into()]);
            }
            if !out.contains(command) {
                out.push(command.clone());
            }
        }
    }
    Ok(out)
}

pub async fn authorize_platform_command(
    pool: &PgPool,
    identity_id: Uuid,
    command_name: &str,
    _params: &Value,
) -> ApiResult<()> {
    let allowed = union_allowed_commands(pool, identity_id).await?;
    if !platform_command_allowed(&allowed, command_name) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub async fn execute_platform_command(
    pool: &PgPool,
    identity_id: Uuid,
    command_name: &str,
    params: Value,
) -> ApiResult<Value> {
    authorize_platform_command(pool, identity_id, command_name, &params).await?;

    match command_name {
        "permissions.request" => handle_permissions_request(pool, identity_id, params).await,
        other => Err(ApiError::BadRequest(format!(
            "unknown platform command: {other}"
        ))),
    }
}

async fn handle_permissions_request(
    pool: &PgPool,
    identity_id: Uuid,
    params: Value,
) -> ApiResult<Value> {
    let requested_changes: PermissionRequestChanges = params
        .get("requested_changes")
        .ok_or_else(|| ApiError::BadRequest("requested_changes required".into()))
        .and_then(|value| {
            serde_json::from_value(value.clone())
                .map_err(|e| ApiError::BadRequest(format!("invalid requested_changes: {e}")))
        })?;
    let reason = params
        .get("reason")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::BadRequest("reason required".into()))?
        .to_string();

    let request_id = permission_requests::create_request(
        pool,
        identity_id,
        requested_changes,
        reason,
    )
    .await?;

    Ok(serde_json::json!({
        "request_id": request_id,
        "status": "pending",
    }))
}

pub async fn authorize_admin_command(
    pool: &PgPool,
    identity_id: Uuid,
    command_name: &str,
    _params: &Value,
) -> ApiResult<()> {
    let allowed = union_allowed_admin_commands(pool, identity_id).await?;
    if !admin_command_allowed(&allowed, command_name) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub async fn execute_admin_command(
    pool: &PgPool,
    config: &AppConfig,
    identity_id: Uuid,
    command_name: &str,
    params: Value,
) -> ApiResult<Value> {
    authorize_admin_command(pool, identity_id, command_name, &params).await?;
    if command_name.starts_with("admin.repo.") {
        return execute_repo_command(
            pool,
            config,
            &identity_id.to_string(),
            command_name,
            params,
        )
        .await;
    }

    if command_name.starts_with("admin.authz.") {
        return execute_authz_command(pool, identity_id, command_name, params).await;
    }

    match command_name {
        "admin.permissions.read" => {
            let target = params
                .get("identity_id")
                .and_then(|value| value.as_str())
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| ApiError::BadRequest("invalid identity_id".into()))?;
            permission_requests::read_permissions(pool, identity_id, target).await
        }
        "admin.permissions.requests.list" => {
            let query = PermissionRequestListQuery {
                limit: params.get("limit").and_then(|v| v.as_i64()),
                offset: params.get("offset").and_then(|v| v.as_i64()),
                status: params
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                request_id: params
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .map(Uuid::parse_str)
                    .transpose()
                    .map_err(|_| ApiError::BadRequest("invalid request_id".into()))?,
            };
            let response = permission_requests::list_requests(pool, &query).await?;
            Ok(serde_json::to_value(response).map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.permissions.request.approve" => {
            let request_id = parse_uuid_param(&params, "request_id")?;
            permission_requests::approve_request(
                pool,
                request_id,
                &identity_id.to_string(),
                Some(identity_id),
            )
            .await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "admin.permissions.request.reject" => {
            let request_id = parse_uuid_param(&params, "request_id")?;
            let reason = params
                .get("reason")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            permission_requests::reject_request(
                pool,
                request_id,
                &identity_id.to_string(),
                reason,
                Some(identity_id),
            )
            .await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "admin.audit.list" => {
            let query = ListQuery {
                limit: params.get("limit").and_then(|v| v.as_i64()),
                offset: params.get("offset").and_then(|v| v.as_i64()),
            };
            let (limit, offset) =
                crate::pagination::resolve_list_pagination(query.limit, query.offset);
            let response = crate::audit::list_events(pool, limit, offset).await?;
            Ok(serde_json::to_value(response).map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.queue.list" => {
            let query = CommandListQuery {
                limit: params.get("limit").and_then(|v| v.as_i64()),
                offset: params.get("offset").and_then(|v| v.as_i64()),
                command_id: params
                    .get("command_id")
                    .and_then(|v| v.as_str())
                    .map(Uuid::parse_str)
                    .transpose()
                    .map_err(|_| ApiError::BadRequest("invalid command_id".into()))?,
                machine_id: params
                    .get("machine_id")
                    .and_then(|v| v.as_str())
                    .map(Uuid::parse_str)
                    .transpose()
                    .map_err(|_| ApiError::BadRequest("invalid machine_id".into()))?,
                include_recent: params.get("include_recent").and_then(|v| v.as_bool()),
            };
            let response = command_queue::list_active_commands(pool, &query).await?;
            Ok(serde_json::to_value(response).map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.queue.approve" => {
            let command_id = parse_uuid_param(&params, "command_id")?;
            command_queue::approve_pending_command(
                pool,
                command_id,
                &identity_id.to_string(),
                Some(identity_id),
            )
            .await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "admin.queue.cancel" => {
            let command_id = parse_uuid_param(&params, "command_id")?;
            command_queue::cancel_queued_command(pool, command_id, &identity_id.to_string(), true)
                .await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        other => Err(ApiError::BadRequest(format!(
            "unknown admin command: {other}"
        ))),
    }
}

async fn execute_authz_command(
    pool: &PgPool,
    identity_id: Uuid,
    command_name: &str,
    params: Value,
) -> ApiResult<Value> {
    use crate::authz::store::{
        AccessGrantInput, AccessGrantPatch, CapabilityProfileInput, CapabilityProfilePatch,
        FleetScopeInput, FleetScopePatch, GrantAssignmentInput, RemoveAssignmentsInput,
        SetGrantAssignmentsInput,
    };

    match command_name {
        "admin.authz.catalog" => {
            let catalog = authz::build_authz_catalog(pool).await?;
            Ok(serde_json::to_value(catalog).map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.fleet_scopes.list" => {
            Ok(serde_json::to_value(store::list_fleet_scopes(pool).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.fleet_scopes.read" | "admin.authz.fleet_scopes.preview" => {
            let id = parse_uuid_param(&params, "id")?;
            if command_name.ends_with(".preview") {
                let preview = authz::preview_fleet_scope(pool, id).await?;
                return Ok(serde_json::to_value(preview).map_err(|e| ApiError::Internal(e.into()))?);
            }
            Ok(serde_json::to_value(store::get_fleet_scope(pool, id).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.fleet_scopes.create" => {
            let input: FleetScopeInput = serde_json::from_value(params)
                .map_err(|e| ApiError::BadRequest(format!("invalid fleet scope: {e}")))?;
            Ok(serde_json::to_value(store::create_fleet_scope(pool, input).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.fleet_scopes.update" => {
            let id = parse_uuid_param(&params, "id")?;
            let patch: FleetScopePatch = serde_json::from_value(params)
                .map_err(|e| ApiError::BadRequest(format!("invalid fleet scope patch: {e}")))?;
            Ok(serde_json::to_value(store::update_fleet_scope(pool, id, patch).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.fleet_scopes.delete" => {
            let id = parse_uuid_param(&params, "id")?;
            store::delete_fleet_scope(pool, id).await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "admin.authz.capability_profiles.list" => {
            Ok(serde_json::to_value(store::list_capability_profiles(pool).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.capability_profiles.read" => {
            let id = parse_uuid_param(&params, "id")?;
            Ok(serde_json::to_value(store::get_capability_profile(pool, id).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.capability_profiles.create" => {
            let input: CapabilityProfileInput = serde_json::from_value(params)
                .map_err(|e| ApiError::BadRequest(format!("invalid capability profile: {e}")))?;
            Ok(serde_json::to_value(store::create_capability_profile(pool, input).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.capability_profiles.update" => {
            let id = parse_uuid_param(&params, "id")?;
            let patch: CapabilityProfilePatch = serde_json::from_value(params)
                .map_err(|e| ApiError::BadRequest(format!("invalid capability profile patch: {e}")))?;
            Ok(serde_json::to_value(store::update_capability_profile(pool, id, patch).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.capability_profiles.delete" => {
            let id = parse_uuid_param(&params, "id")?;
            store::delete_capability_profile(pool, id).await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "admin.authz.access_grants.list" => {
            Ok(serde_json::to_value(store::list_access_grants(pool).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.access_grants.read" => {
            let id = parse_uuid_param(&params, "id")?;
            Ok(serde_json::to_value(store::get_access_grant(pool, id).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.access_grants.create" => {
            let input: AccessGrantInput = serde_json::from_value(params)
                .map_err(|e| ApiError::BadRequest(format!("invalid access grant: {e}")))?;
            Ok(serde_json::to_value(store::create_access_grant(pool, input).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.access_grants.update" => {
            let id = parse_uuid_param(&params, "id")?;
            let patch: AccessGrantPatch = serde_json::from_value(params)
                .map_err(|e| ApiError::BadRequest(format!("invalid access grant patch: {e}")))?;
            Ok(serde_json::to_value(store::update_access_grant(pool, id, patch).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.access_grants.delete" => {
            let id = parse_uuid_param(&params, "id")?;
            store::delete_access_grant(pool, id).await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "admin.authz.assignments.read" => {
            let target = params
                .get("identity_id")
                .and_then(|value| value.as_str())
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| ApiError::BadRequest("invalid identity_id".into()))?
                .unwrap_or(identity_id);
            Ok(serde_json::to_value(store::load_grant_assignments(pool, target).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.assignments.add" => {
            let target = params
                .get("identity_id")
                .and_then(|value| value.as_str())
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| ApiError::BadRequest("invalid identity_id".into()))?
                .unwrap_or(identity_id);
            let assignment: GrantAssignmentInput = serde_json::from_value(params)
                .map_err(|e| ApiError::BadRequest(format!("invalid assignment: {e}")))?;
            let input = SetGrantAssignmentsInput {
                assignments: vec![assignment],
            };
            let current = store::load_grant_assignments(pool, target).await?;
            let mut merged = SetGrantAssignmentsInput {
                assignments: current
                    .into_iter()
                    .map(|entry| GrantAssignmentInput {
                        access_grant_id: entry.access_grant.id,
                        requires_approval_for_shell: entry.requires_approval_for_shell,
                        requires_approval_for_elevated: entry.requires_approval_for_elevated,
                        enabled: entry.enabled,
                    })
                    .collect(),
            };
            merged.assignments.extend(input.assignments);
            Ok(serde_json::to_value(store::set_grant_assignments(pool, target, merged).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.assignments.remove" => {
            let target = params
                .get("identity_id")
                .and_then(|value| value.as_str())
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| ApiError::BadRequest("invalid identity_id".into()))?
                .unwrap_or(identity_id);
            let input: RemoveAssignmentsInput = serde_json::from_value(params)
                .map_err(|e| ApiError::BadRequest(format!("invalid remove request: {e}")))?;
            Ok(serde_json::to_value(store::remove_assignments(pool, target, input).await?)
                .map_err(|e| ApiError::Internal(e.into()))?)
        }
        "admin.authz.effective_rights.read" => {
            let target = params
                .get("identity_id")
                .and_then(|value| value.as_str())
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| ApiError::BadRequest("invalid identity_id".into()))?
                .unwrap_or(identity_id);
            let report = authz::compute_effective_rights(pool, target).await?;
            Ok(serde_json::to_value(report).map_err(|e| ApiError::Internal(e.into()))?)
        }
        other => Err(ApiError::BadRequest(format!("unknown admin command: {other}"))),
    }
}

pub async fn execute_repo_command(
    pool: &PgPool,
    config: &AppConfig,
    actor: &str,
    command_name: &str,
    params: Value,
) -> ApiResult<Value> {
    let result = match command_name {
        "admin.repo.sources.list" => {
            let sources = feature_repo::sources::list(pool).await?;
            serde_json::to_value(sources).map_err(|error| ApiError::Internal(error.into()))
        }
        "admin.repo.sources.add" => {
            let id = required_string_param(&params, "id")?;
            let url = required_string_param(&params, "url")?;
            let public_key_b64 = required_string_param(&params, "public_key_b64")?;
            let priority = params
                .get("priority")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .try_into()
                .map_err(|_| ApiError::BadRequest("priority must fit in a 32-bit integer".into()))?;
            let source =
                feature_repo::sources::add(pool, id, url, public_key_b64, priority).await?;
            serde_json::to_value(source).map_err(|error| ApiError::Internal(error.into()))
        }
        "admin.repo.sources.update" => {
            let id = required_string_param(&params, "id")?;
            let url = optional_string_param(&params, "url")?;
            let public_key_b64 = optional_string_param(&params, "public_key_b64")?;
            let priority = match params.get("priority") {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    value
                        .as_i64()
                        .ok_or_else(|| ApiError::BadRequest("priority must be an integer".into()))?
                        .try_into()
                        .map_err(|_| {
                            ApiError::BadRequest("priority must fit in a 32-bit integer".into())
                        })?,
                ),
            };
            let source =
                feature_repo::sources::update(pool, id, url, public_key_b64, priority).await?;
            serde_json::to_value(source).map_err(|error| ApiError::Internal(error.into()))
        }
        "admin.repo.sources.enable" | "admin.repo.sources.disable" => {
            let id = required_string_param(&params, "id")?;
            let source =
                feature_repo::sources::set_enabled(pool, id, command_name.ends_with(".enable"))
                    .await?;
            serde_json::to_value(source).map_err(|error| ApiError::Internal(error.into()))
        }
        "admin.repo.sources.remove" => {
            let id = required_string_param(&params, "id")?;
            feature_repo::sources::remove(pool, id).await?;
            Ok(serde_json::json!({ "id": id, "removed": true }))
        }
        "admin.repo.list" => feature_repo::install::list(pool).await,
        "admin.repo.status" => feature_repo::install::status(pool).await,
        "admin.repo.refresh" => feature_repo::install::refresh(pool, config).await,
        "admin.repo.install" => {
            let id = required_string_param(&params, "id")?;
            let version = optional_string_param(&params, "version")?;
            let source_id = optional_string_param(&params, "source_id")?;
            feature_repo::install::install(pool, config, id, version, source_id).await
        }
        "admin.repo.upgrade" => {
            let id = required_string_param(&params, "id")?;
            let version = optional_string_param(&params, "version")?;
            feature_repo::install::upgrade(pool, config, id, version).await
        }
        "admin.repo.upgrade_all" => feature_repo::install::upgrade_all(pool, config).await,
        "admin.repo.pin" => {
            let id = required_string_param(&params, "id")?;
            let version = required_string_param(&params, "version")?;
            feature_repo::install::pin(pool, config, id, version).await
        }
        "admin.repo.unpin" => {
            let id = required_string_param(&params, "id")?;
            feature_repo::install::unpin(pool, config, id).await
        }
        "admin.repo.uninstall" => {
            let id = required_string_param(&params, "id")?;
            feature_repo::install::uninstall(pool, id).await
        }
        other => Err(ApiError::BadRequest(format!(
            "unknown admin command: {other}"
        ))),
    }?;

    if !matches!(
        command_name,
        "admin.repo.sources.list" | "admin.repo.list" | "admin.repo.status"
    ) {
        let target = params.get("id").and_then(Value::as_str).unwrap_or("");
        audit_repo_mutation(pool, actor, command_name, target, &params).await?;
    }
    Ok(result)
}

fn required_string_param<'a>(params: &'a Value, field: &str) -> ApiResult<&'a str> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::BadRequest(format!("{field} required")))
}

fn optional_string_param<'a>(params: &'a Value, field: &str) -> ApiResult<Option<&'a str>> {
    match params.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.trim())),
        Some(Value::String(_)) => Err(ApiError::BadRequest(format!("{field} must not be empty"))),
        Some(_) => Err(ApiError::BadRequest(format!("{field} must be a string"))),
    }
}

async fn audit_repo_mutation(
    pool: &PgPool,
    actor: &str,
    action: &str,
    target: &str,
    params: &Value,
) -> ApiResult<()> {
    crate::audit::append_audit(pool, actor, action, target, "", params).await
}

fn parse_uuid_param(params: &Value, field: &str) -> ApiResult<Uuid> {
    params
        .get(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| ApiError::BadRequest(format!("{field} required")))
        .and_then(|value| {
            Uuid::parse_str(value).map_err(|_| ApiError::BadRequest(format!("invalid {field}")))
        })
}

#[cfg(test)]
mod tests {
    use hecate_protocol::permissions::{admin_command_allowed, platform_command_allowed, CapabilityProfileRules};

    #[test]
    fn platform_command_allowed_includes_permissions_request_by_default_rules() {
        let rules = CapabilityProfileRules {
            allowed_commands: vec!["system.info".into(), "permissions.request".into()],
            allowed_admin_commands: vec![],
            shell_policy: Default::default(),
            elevation_policy: Default::default(),
            max_output_bytes: hecate_protocol::permissions::DEFAULT_MAX_OUTPUT_BYTES,
            max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
            timeout_secs: hecate_protocol::permissions::DEFAULT_TIMEOUT_SECS,
            max_concurrent: hecate_protocol::permissions::DEFAULT_MAX_CONCURRENT,
        };
        assert!(platform_command_allowed(
            &rules.allowed_commands,
            "permissions.request"
        ));
        assert!(!admin_command_allowed(
            &rules.allowed_admin_commands,
            "admin.audit.list"
        ));
    }

    #[test]
    fn admin_wildcard_allows_all_admin_commands() {
        assert!(admin_command_allowed(&["*".into()], "admin.queue.approve"));
    }
}
