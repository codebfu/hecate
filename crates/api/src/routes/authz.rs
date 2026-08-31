//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use hecate_protocol::authz::{
    AccessGrantDetail, AuthzCatalogResponse, CapabilityProfile, EffectiveRightsReport, FleetScope,
    FleetScopePreview, ResolvedGrantAssignment,
};
use uuid::Uuid;

use crate::audit::append_audit;
use crate::authz::{
    build_authz_catalog, compute_effective_rights, create_access_grant, create_capability_profile,
    create_fleet_scope, delete_access_grant, delete_capability_profile, delete_fleet_scope,
    list_access_grants, list_capability_profiles, list_fleet_scopes, load_grant_assignments,
    preview_fleet_scope, promote_to_catalog, remove_assignments, set_grant_assignments, update_access_grant,
    update_capability_profile, update_fleet_scope, AccessGrantInput, AccessGrantPatch,
    CapabilityProfileInput, CapabilityProfilePatch, FleetScopeInput, FleetScopePatch,
    RemoveAssignmentsInput, SetGrantAssignmentsInput,
};
use crate::admin_auth;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/fleet-scopes", get(list_fleet_scopes_handler).post(create_fleet_scope_handler))
        .route(
            "/api/v1/admin/fleet-scopes/{id}",
            patch(update_fleet_scope_handler).delete(delete_fleet_scope_handler),
        )
        .route(
            "/api/v1/admin/fleet-scopes/{id}/preview",
            get(preview_fleet_scope_handler),
        )
        .route(
            "/api/v1/admin/fleet-scopes/{id}/promote",
            post(promote_fleet_scope_handler),
        )
        .route(
            "/api/v1/admin/capability-profiles",
            get(list_capability_profiles_handler).post(create_capability_profile_handler),
        )
        .route(
            "/api/v1/admin/capability-profiles/{id}",
            patch(update_capability_profile_handler).delete(delete_capability_profile_handler),
        )
        .route(
            "/api/v1/admin/capability-profiles/{id}/promote",
            post(promote_capability_profile_handler),
        )
        .route(
            "/api/v1/admin/access-grants",
            get(list_access_grants_handler).post(create_access_grant_handler),
        )
        .route(
            "/api/v1/admin/access-grants/{id}",
            patch(update_access_grant_handler).delete(delete_access_grant_handler),
        )
        .route(
            "/api/v1/admin/access-grants/{id}/promote",
            post(promote_access_grant_handler),
        )
        .route(
            "/api/v1/admin/ai-identities/{id}/grant-assignments",
            get(get_grant_assignments).put(put_grant_assignments),
        )
        .route(
            "/api/v1/admin/ai-identities/{id}/grant-assignments/remove",
            post(remove_grant_assignments),
        )
        .route(
            "/api/v1/admin/ai-identities/{id}/effective-rights",
            get(get_effective_rights),
        )
        .route("/api/v1/admin/authz-catalog", get(get_authz_catalog))
}

async fn list_fleet_scopes_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<FleetScope>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(list_fleet_scopes(&state.pool).await?))
}

async fn create_fleet_scope_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<FleetScopeInput>,
) -> ApiResult<Json<FleetScope>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let created = create_fleet_scope(&state.pool, body).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.fleet_scope.create",
        &created.id.to_string(),
        "",
        &serde_json::json!({ "name": created.name }),
    )
    .await?;
    Ok(Json(created))
}

async fn update_fleet_scope_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<FleetScopePatch>,
) -> ApiResult<Json<FleetScope>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let updated = update_fleet_scope(&state.pool, id, body).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.fleet_scope.update",
        &id.to_string(),
        "",
        &serde_json::json!({ "fleet_scope_id": id }),
    )
    .await?;
    Ok(Json(updated))
}

async fn delete_fleet_scope_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    delete_fleet_scope(&state.pool, id).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.fleet_scope.delete",
        &id.to_string(),
        "",
        &serde_json::json!({ "fleet_scope_id": id }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn preview_fleet_scope_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<FleetScopePreview>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(preview_fleet_scope(&state.pool, id).await?))
}

async fn list_capability_profiles_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<CapabilityProfile>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(list_capability_profiles(&state.pool).await?))
}

async fn create_capability_profile_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<CapabilityProfileInput>,
) -> ApiResult<Json<CapabilityProfile>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let created = create_capability_profile(&state.pool, body).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.capability_profile.create",
        &created.id.to_string(),
        "",
        &serde_json::json!({ "name": created.name }),
    )
    .await?;
    Ok(Json(created))
}

async fn update_capability_profile_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<CapabilityProfilePatch>,
) -> ApiResult<Json<CapabilityProfile>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let updated = update_capability_profile(&state.pool, id, body).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.capability_profile.update",
        &id.to_string(),
        "",
        &serde_json::json!({ "capability_profile_id": id }),
    )
    .await?;
    Ok(Json(updated))
}

async fn delete_capability_profile_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    delete_capability_profile(&state.pool, id).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.capability_profile.delete",
        &id.to_string(),
        "",
        &serde_json::json!({ "capability_profile_id": id }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_access_grants_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<Vec<AccessGrantDetail>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(list_access_grants(&state.pool).await?))
}

async fn create_access_grant_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<AccessGrantInput>,
) -> ApiResult<Json<AccessGrantDetail>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let created = create_access_grant(&state.pool, body).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.access_grant.create",
        &created.grant.id.to_string(),
        "",
        &serde_json::json!({ "name": created.grant.name }),
    )
    .await?;
    Ok(Json(created))
}

async fn update_access_grant_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<AccessGrantPatch>,
) -> ApiResult<Json<AccessGrantDetail>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let updated = update_access_grant(&state.pool, id, body).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.access_grant.update",
        &id.to_string(),
        "",
        &serde_json::json!({ "access_grant_id": id }),
    )
    .await?;
    Ok(Json(updated))
}

async fn delete_access_grant_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    delete_access_grant(&state.pool, id).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.access_grant.delete",
        &id.to_string(),
        "",
        &serde_json::json!({ "access_grant_id": id }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_grant_assignments(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<ResolvedGrantAssignment>>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(load_grant_assignments(&state.pool, id).await?))
}

async fn put_grant_assignments(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<SetGrantAssignmentsInput>,
) -> ApiResult<Json<Vec<ResolvedGrantAssignment>>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let assignments = set_grant_assignments(&state.pool, id, body).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.assignments.set",
        &id.to_string(),
        "",
        &serde_json::json!({
            "ai_identity_id": id,
            "assignment_count": assignments.len(),
        }),
    )
    .await?;
    Ok(Json(assignments))
}

async fn remove_grant_assignments(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<RemoveAssignmentsInput>,
) -> ApiResult<Json<Vec<ResolvedGrantAssignment>>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    let assignments = remove_assignments(&state.pool, id, body.clone()).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.assignments.remove",
        &id.to_string(),
        "",
        &serde_json::json!({
            "ai_identity_id": id,
            "assignment_ids": body.assignment_ids,
            "reason": body.reason,
        }),
    )
    .await?;
    Ok(Json(assignments))
}

async fn get_effective_rights(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<EffectiveRightsReport>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(compute_effective_rights(&state.pool, id).await?))
}

async fn get_authz_catalog(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<AuthzCatalogResponse>> {
    admin_auth::require_admin_read(&state, &jar).await?;
    Ok(Json(build_authz_catalog(&state.pool).await?))
}

async fn promote_fleet_scope_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    promote_to_catalog(&state.pool, "fleet_scope", id).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.fleet_scope.promote",
        &id.to_string(),
        "",
        &serde_json::json!({ "fleet_scope_id": id }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn promote_capability_profile_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    promote_to_catalog(&state.pool, "capability_profile", id).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.capability_profile.promote",
        &id.to_string(),
        "",
        &serde_json::json!({ "capability_profile_id": id }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn promote_access_grant_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = admin_auth::require_admin(&state, &jar, &headers).await?;
    promote_to_catalog(&state.pool, "access_grant", id).await?;
    append_audit(
        &state.pool,
        &admin.session.login,
        "authz.access_grant.promote",
        &id.to_string(),
        "",
        &serde_json::json!({ "access_grant_id": id }),
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
