//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Agent/server update helpers: version comparison, busy detection, outdated status.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiResult;

pub const ACTIVE_COMMAND_STATUSES: &[&str] = &[
    "pending_approval",
    "queued",
    "dispatched",
    "running",
];

/// Compare dotted numeric version segments (e.g. 0.1.0 vs 0.2.0).
pub fn version_is_older(current: &str, target: &str) -> bool {
    let parse = |value: &str| -> Vec<u32> {
        value
            .split('.')
            .filter_map(|part| part.parse().ok())
            .collect()
    };
    let current_parts = parse(current);
    let target_parts = parse(target);
    let max_len = current_parts.len().max(target_parts.len());

    for index in 0..max_len {
        let current_part = current_parts.get(index).copied().unwrap_or(0);
        let target_part = target_parts.get(index).copied().unwrap_or(0);
        if current_part < target_part {
            return true;
        }
        if current_part > target_part {
            return false;
        }
    }
    false
}

pub async fn is_machine_busy(pool: &PgPool, machine_id: Uuid) -> ApiResult<bool> {
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM command_queue
            WHERE machine_id = $1
              AND status = ANY($2::command_status[])
         )",
    )
    .bind(machine_id)
    .bind(ACTIVE_COMMAND_STATUSES)
    .fetch_one(pool)
    .await?;
    Ok(busy)
}

pub async fn is_fleet_busy(pool: &PgPool) -> ApiResult<bool> {
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM command_queue cq
            JOIN machines m ON m.id = cq.machine_id
            WHERE m.deleted_at IS NULL
              AND cq.status = ANY($1::command_status[])
         )",
    )
    .bind(ACTIVE_COMMAND_STATUSES)
    .fetch_one(pool)
    .await?;
    Ok(busy)
}

pub async fn latest_component_release_version(
    pool: &PgPool,
    os: &str,
    arch: &str,
    component: &str,
) -> ApiResult<Option<String>> {
    crate::feature_repo::releases::latest_component_version(pool, os, arch, component).await
}

/// True when a reported version is older than a known latest release.
pub fn component_is_outdated(current: Option<&str>, latest: Option<&str>) -> bool {
    match (
        current.map(str::trim).filter(|value| !value.is_empty()),
        latest.map(str::trim).filter(|value| !value.is_empty()),
    ) {
        (Some(current), Some(latest)) => version_is_older(current, latest),
        _ => false,
    }
}

pub async fn has_pending_agent_update(pool: &PgPool, machine_id: Uuid) -> ApiResult<bool> {
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM command_queue
            WHERE machine_id = $1
              AND command_name IN ('agent.update', 'helper.install')
              AND status = ANY($2::command_status[])
         )",
    )
    .bind(machine_id)
    .bind(ACTIVE_COMMAND_STATUSES)
    .fetch_one(pool)
    .await?;
    Ok(pending)
}

pub async fn has_pending_system_reboot(pool: &PgPool, machine_id: Uuid) -> ApiResult<bool> {
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM command_queue
            WHERE machine_id = $1
              AND command_name = 'system.reboot'
              AND status = ANY($2::command_status[])
         )",
    )
    .bind(machine_id)
    .bind(ACTIVE_COMMAND_STATUSES)
    .fetch_one(pool)
    .await?;
    Ok(pending)
}

pub async fn has_other_active_commands(pool: &PgPool, machine_id: Uuid) -> ApiResult<bool> {
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM command_queue
            WHERE machine_id = $1
              AND command_name NOT IN ('agent.update', 'helper.install')
              AND status = ANY($2::command_status[])
         )",
    )
    .bind(machine_id)
    .bind(ACTIVE_COMMAND_STATUSES)
    .fetch_one(pool)
    .await?;
    Ok(busy)
}

pub async fn pending_agent_update_created_at(
    pool: &PgPool,
    machine_id: Uuid,
) -> ApiResult<Option<DateTime<Utc>>> {
    let created_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT created_at FROM command_queue
         WHERE machine_id = $1
           AND command_name IN ('agent.update', 'helper.install')
           AND status = ANY($2::command_status[])
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(machine_id)
    .bind(ACTIVE_COMMAND_STATUSES)
    .fetch_optional(pool)
    .await?;
    Ok(created_at)
}

pub fn compute_agent_update_status(
    agent_state: Option<&str>,
    agent_version: Option<&str>,
    latest_version: Option<&str>,
    has_pending_update: bool,
    blocked_by_other_commands: bool,
) -> &'static str {
    if agent_state != Some("active") {
        return "not_applicable";
    }
    let Some(current) = agent_version.filter(|v| !v.is_empty()) else {
        return "unknown";
    };
    let Some(latest) = latest_version else {
        return "up_to_date";
    };
    if !version_is_older(current, latest) {
        return "up_to_date";
    }
    if has_pending_update {
        return "update_pending";
    }
    if blocked_by_other_commands {
        return "blocked_busy";
    }
    "outdated"
}

pub fn compute_desktop_update_status(
    agent_state: Option<&str>,
    desktop_version: Option<&str>,
    latest_version: Option<&str>,
    has_pending_update: bool,
    blocked_by_other_commands: bool,
    pending_install: bool,
) -> &'static str {
    if agent_state != Some("active") {
        return "not_applicable";
    }
    let Some(current) = desktop_version.map(str::trim).filter(|v| !v.is_empty()) else {
        if pending_install {
            return "update_pending";
        }
        return "not_installed";
    };
    let Some(latest) = latest_version else {
        return "up_to_date";
    };
    if !version_is_older(current, latest) {
        return "up_to_date";
    }
    if has_pending_update {
        return "update_pending";
    }
    if blocked_by_other_commands {
        return "blocked_busy";
    }
    "outdated"
}

pub fn compute_proxmox_update_status(
    agent_state: Option<&str>,
    proxmox_version: Option<&str>,
    latest_version: Option<&str>,
    has_pending_update: bool,
    blocked_by_other_commands: bool,
    pending_install: bool,
) -> &'static str {
    if agent_state != Some("active") {
        return "not_applicable";
    }
    let Some(current) = proxmox_version.map(str::trim).filter(|v| !v.is_empty()) else {
        if pending_install {
            return "update_pending";
        }
        return "not_installed";
    };
    let Some(latest) = latest_version else {
        return "up_to_date";
    };
    if !version_is_older(current, latest) {
        return "up_to_date";
    }
    if has_pending_update {
        return "update_pending";
    }
    if blocked_by_other_commands {
        return "blocked_busy";
    }
    "outdated"
}

pub async fn machine_update_extra(
    pool: &PgPool,
    machine_id: Uuid,
    os: &str,
    arch: &str,
    agent_state: Option<&str>,
    agent_version: Option<&str>,
    desktop_version: Option<&str>,
    proxmox_version: Option<&str>,
) -> ApiResult<Value> {
    let has_pending_update = has_pending_agent_update(pool, machine_id).await?;
    let pending_install =
        crate::helper_install::pending_install_component(pool, machine_id).await?;
    let pending_package_update = has_pending_update && pending_install.is_none();
    let blocked_by_other_commands = has_other_active_commands(pool, machine_id).await?;
    let latest_agent = latest_component_release_version(pool, os, arch, "agent").await?;
    let latest_desktop = latest_component_release_version(pool, os, arch, "desktop").await?;
    let latest_proxmox = latest_component_release_version(pool, os, arch, "proxmox").await?;
    let agent_status = compute_agent_update_status(
        agent_state,
        agent_version,
        latest_agent.as_deref(),
        pending_package_update,
        blocked_by_other_commands,
    );
    let desktop_status = compute_desktop_update_status(
        agent_state,
        desktop_version,
        latest_desktop.as_deref(),
        pending_package_update,
        blocked_by_other_commands,
        pending_install.as_deref() == Some("desktop"),
    );
    let proxmox_status = compute_proxmox_update_status(
        agent_state,
        proxmox_version,
        latest_proxmox.as_deref(),
        pending_package_update,
        blocked_by_other_commands,
        pending_install.as_deref() == Some("proxmox"),
    );
    let update_requested_at = if has_pending_update {
        pending_agent_update_created_at(pool, machine_id).await?
    } else {
        None
    };
    Ok(json!({
        "agent_busy": blocked_by_other_commands,
        "agent_update_status": agent_status,
        "latest_agent_version": latest_agent,
        "agent_update_requested_at": update_requested_at,
        "desktop_update_status": desktop_status,
        "latest_desktop_version": latest_desktop,
        "proxmox_update_status": proxmox_status,
        "latest_proxmox_version": latest_proxmox,
        "installable_helpers": crate::helper_install::installable_helpers(
            agent_state,
            desktop_version,
            proxmox_version,
            latest_desktop.as_deref(),
            latest_proxmox.as_deref(),
            pending_install.as_deref(),
        ),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_older_compares_semver_parts() {
        assert!(version_is_older("0.1.0", "0.1.1"));
        assert!(version_is_older("0.1.9", "0.2.0"));
        assert!(!version_is_older("1.0.0", "0.9.9"));
        assert!(!version_is_older("0.1.0", "0.1.0"));
    }

    #[test]
    fn compute_agent_update_status_cases() {
        assert_eq!(
            compute_agent_update_status(Some("active"), Some("0.1.0"), Some("0.2.0"), false, false),
            "outdated"
        );
        assert_eq!(
            compute_agent_update_status(Some("active"), Some("0.1.0"), Some("0.2.0"), true, false),
            "update_pending"
        );
        assert_eq!(
            compute_agent_update_status(Some("active"), Some("0.1.0"), Some("0.2.0"), false, true),
            "blocked_busy"
        );
        assert_eq!(
            compute_agent_update_status(Some("active"), Some("0.2.0"), Some("0.2.0"), false, false),
            "up_to_date"
        );
    }

    #[test]
    fn compute_desktop_update_status_cases() {
        assert_eq!(
            compute_desktop_update_status(Some("active"), None, Some("0.2.0"), false, false, false),
            "not_installed"
        );
        assert_eq!(
            compute_desktop_update_status(Some("active"), None, Some("0.2.0"), false, false, true),
            "update_pending"
        );
        assert_eq!(
            compute_desktop_update_status(
                Some("active"),
                Some("0.1.0"),
                Some("0.2.0"),
                false,
                false,
                false
            ),
            "outdated"
        );
        assert_eq!(
            compute_desktop_update_status(
                Some("active"),
                Some("0.2.0"),
                Some("0.2.0"),
                false,
                false,
                false
            ),
            "up_to_date"
        );
    }

    #[test]
    fn compute_proxmox_update_status_cases() {
        assert_eq!(
            compute_proxmox_update_status(Some("active"), None, Some("0.2.0"), false, false, false),
            "not_installed"
        );
        assert_eq!(
            compute_proxmox_update_status(Some("active"), None, Some("0.2.0"), false, false, true),
            "update_pending"
        );
        assert_eq!(
            compute_proxmox_update_status(
                Some("active"),
                Some("0.1.0"),
                Some("0.2.0"),
                false,
                false,
                false
            ),
            "outdated"
        );
        assert_eq!(
            compute_proxmox_update_status(
                Some("active"),
                Some("0.2.0"),
                Some("0.2.0"),
                false,
                false,
                false
            ),
            "up_to_date"
        );
    }

    #[test]
    fn component_is_outdated_requires_both_versions() {
        assert!(component_is_outdated(Some("1.0.0"), Some("1.0.1")));
        assert!(!component_is_outdated(Some("1.0.1"), Some("1.0.1")));
        assert!(!component_is_outdated(None, Some("1.0.1")));
        assert!(!component_is_outdated(Some("1.0.0"), None));
    }
}
