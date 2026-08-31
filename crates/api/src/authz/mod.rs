//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Granular authorization: fleet scopes, capability profiles, access grants, assignments.

pub mod catalog;
pub mod effective_rights;
pub mod evaluator;
pub mod store;

pub use catalog::{build_admin_catalog, build_admin_catalog as build_authz_catalog, build_self_service_catalog};
pub use effective_rights::compute_effective_rights;
pub use evaluator::{
    authorize_agent_command, check_max_concurrent, count_active_commands, find_matching_grants,
    fleet_scope_matches, identity_can_access_machine, preview_fleet_scope,
    select_most_restrictive_grant, MatchingGrant,
};
pub use store::{
    create_access_grant, create_capability_profile, create_fleet_scope, delete_access_grant,
    delete_capability_profile, delete_fleet_scope, ensure_bootstrap_assignment, get_access_grant, get_capability_profile,
    get_fleet_scope, list_access_grants, list_capability_profiles, list_fleet_scopes,
    load_grant_assignments, promote_to_catalog, remove_assignments, remove_machine_from_fleet_scopes,
    set_grant_assignments, update_access_grant, update_capability_profile, update_fleet_scope,
    AccessGrantInput, AccessGrantPatch, CapabilityProfileInput, CapabilityProfilePatch,
    FleetScopeInput, FleetScopePatch, GrantAssignmentInput, RemoveAssignmentsInput,
    SetGrantAssignmentsInput,
};
