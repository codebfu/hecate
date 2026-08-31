//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shell / cwd / env policy — re-exported from `hecate-lampad-helper-base`.
//!
//! The implementation lives in helper-base so helpers can enforce the same
//! primitives without depending on the full protocol crate.

pub use hecate_lampad_helper_base::policy::{
    allowlist_has_wildcard, canonicalize_binary, check_cwd_policy, check_elevation_wrapper_denied,
    check_env_policy, check_shell_policy, cwd_matches_allowed, normalize_path,
    normalize_path_no_traversal, reject_path_traversal, validate_argv, PolicyError,
    ALLOWLIST_WILDCARD, DANGEROUS_ENV_KEYS,
};

use crate::permissions::ElevationPolicy;

/// Adapter preserving the historical `&ElevationPolicy` signature for server/agent callers.
pub fn check_elevation_policy(
    argv: &[String],
    policy: &ElevationPolicy,
) -> Result<(), PolicyError> {
    hecate_lampad_helper_base::policy::check_elevation_policy(
        argv,
        policy.enabled,
        &policy.allowed_binaries,
    )
}
