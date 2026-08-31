//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use hecate_protocol::authz::{AccessGrantDetail, AuthzCatalogResponse, CapabilityProfile};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiResult;

use super::store;

pub async fn build_admin_catalog(pool: &PgPool) -> ApiResult<AuthzCatalogResponse> {
    Ok(AuthzCatalogResponse {
        fleet_scopes: store::list_fleet_scopes(pool).await?,
        capability_profiles: store::list_capability_profiles(pool).await?,
        access_grants: store::list_access_grants(pool).await?,
    })
}

/// S12 — self-service catalog: assignable entities only, without full fleet cartography.
pub async fn build_self_service_catalog(
    pool: &PgPool,
    identity_id: Uuid,
) -> ApiResult<AuthzCatalogResponse> {
    let catalog = build_admin_catalog(pool).await?;
    Ok(AuthzCatalogResponse {
        fleet_scopes: catalog
            .fleet_scopes
            .into_iter()
            .filter(|scope| catalog_entity_visible(scope.request_scoped, scope.owner_ai_identity_id, identity_id))
            .map(strip_fleet_scope_for_self_service)
            .collect(),
        capability_profiles: catalog
            .capability_profiles
            .into_iter()
            .filter(|profile| {
                catalog_entity_visible(profile.request_scoped, profile.owner_ai_identity_id, identity_id)
            })
            .map(strip_capability_profile_for_self_service)
            .collect(),
        access_grants: catalog
            .access_grants
            .into_iter()
            .filter(|grant| {
                catalog_entity_visible(
                    grant.grant.request_scoped,
                    grant.grant.owner_ai_identity_id,
                    identity_id,
                )
            })
            .map(strip_access_grant_for_self_service)
            .collect(),
    })
}

fn catalog_entity_visible(request_scoped: bool, owner: Option<Uuid>, identity_id: Uuid) -> bool {
    !request_scoped || owner == Some(identity_id)
}

fn strip_fleet_scope_for_self_service(mut scope: hecate_protocol::authz::FleetScope) -> hecate_protocol::authz::FleetScope {
    scope.machine_ids.clear();
    scope.tags.clear();
    scope
}

fn strip_capability_profile_for_self_service(mut profile: CapabilityProfile) -> CapabilityProfile {
    profile.shell_policy = Default::default();
    profile.elevation_policy = Default::default();
    profile
}

fn strip_access_grant_for_self_service(detail: AccessGrantDetail) -> AccessGrantDetail {
    AccessGrantDetail {
        grant: detail.grant,
        fleet_scope: strip_fleet_scope_for_self_service(detail.fleet_scope),
        capability_profile: strip_capability_profile_for_self_service(detail.capability_profile),
    }
}
