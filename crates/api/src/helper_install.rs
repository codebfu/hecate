//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shared validation and enqueue for first-time helper installs (`helper.install`).

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::machines;
use crate::updates::{
    has_other_active_commands, has_pending_agent_update, has_pending_system_reboot,
    latest_component_release_version, ACTIVE_COMMAND_STATUSES,
};

pub const COMMAND_NAME: &str = "helper.install";
pub const HELPER_COMPONENTS: &[&str] = &["desktop", "proxmox"];
/// Keep in lockstep with `command_dispatch::AGENT_UPDATE_TIMEOUT_SECS`.
const TIMEOUT_SECS: i32 = 600;

pub fn is_package_update_command(command_name: &str) -> bool {
    command_name == "agent.update" || command_name == COMMAND_NAME
}

pub fn parse_helper_component(params: &Value) -> ApiResult<String> {
    let component = params
        .get("component")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::BadRequest("component is required".into()))?;
    if !HELPER_COMPONENTS.contains(&component) {
        return Err(ApiError::BadRequest(format!(
            "unsupported helper component '{component}'"
        )));
    }
    Ok(component.to_string())
}

/// Component requested by an in-flight first-install command, if any.
pub fn parse_pending_install_component(command_name: &str, params: &Value) -> Option<String> {
    if command_name == COMMAND_NAME {
        return parse_helper_component(params).ok();
    }
    if command_name == "agent.update" {
        let install = params.get("install")?.as_array()?;
        let first = install.first()?.as_str()?.trim();
        if HELPER_COMPONENTS.contains(&first) {
            return Some(first.to_string());
        }
    }
    None
}

pub fn helper_is_installed(
    component: &str,
    desktop_version: Option<&str>,
    proxmox_version: Option<&str>,
) -> bool {
    let current = match component {
        "desktop" => desktop_version,
        "proxmox" => proxmox_version,
        _ => None,
    };
    current
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

pub fn installable_helpers(
    agent_state: Option<&str>,
    desktop_version: Option<&str>,
    proxmox_version: Option<&str>,
    latest_desktop: Option<&str>,
    latest_proxmox: Option<&str>,
    pending_install_component: Option<&str>,
) -> Vec<Value> {
    if agent_state != Some("active") {
        return Vec::new();
    }
    let mut helpers = Vec::new();
    if !helper_is_installed("desktop", desktop_version, proxmox_version)
        && pending_install_component != Some("desktop")
    {
        if let Some(version) = latest_desktop.map(str::trim).filter(|value| !value.is_empty()) {
            helpers.push(json!({ "component": "desktop", "version": version }));
        }
    }
    if !helper_is_installed("proxmox", desktop_version, proxmox_version)
        && pending_install_component != Some("proxmox")
    {
        if let Some(version) = latest_proxmox.map(str::trim).filter(|value| !value.is_empty()) {
            helpers.push(json!({ "component": "proxmox", "version": version }));
        }
    }
    helpers
}

pub async fn installable_helpers_for_machine(
    pool: &PgPool,
    machine_id: Uuid,
    os: &str,
    arch: &str,
    agent_state: Option<&str>,
    desktop_version: Option<&str>,
    proxmox_version: Option<&str>,
) -> ApiResult<Vec<Value>> {
    let latest_desktop = latest_component_release_version(pool, os, arch, "desktop").await?;
    let latest_proxmox = latest_component_release_version(pool, os, arch, "proxmox").await?;
    let pending = pending_install_component(pool, machine_id).await?;
    Ok(installable_helpers(
        agent_state,
        desktop_version,
        proxmox_version,
        latest_desktop.as_deref(),
        latest_proxmox.as_deref(),
        pending.as_deref(),
    ))
}

pub async fn pending_install_component(
    pool: &PgPool,
    machine_id: Uuid,
) -> ApiResult<Option<String>> {
    let row: Option<(String, Value)> = sqlx::query_as(
        "SELECT command_name, params FROM command_queue
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
    Ok(row.and_then(|(name, params)| parse_pending_install_component(&name, &params)))
}

pub async fn ensure_can_install(
    pool: &PgPool,
    machine_id: Uuid,
    component: &str,
) -> ApiResult<()> {
    if !HELPER_COMPONENTS.contains(&component) {
        return Err(ApiError::BadRequest(format!(
            "unsupported helper component '{component}'"
        )));
    }
    let machine = machines::load_machine_row(pool, machine_id).await?;
    let agent_state = machines::load_agent_state(pool, machine_id).await?;
    if agent_state.as_deref() != Some("active") {
        return Err(ApiError::BadRequest("agent is not active".into()));
    }
    if helper_is_installed(
        component,
        machine.desktop_version.as_deref(),
        machine.proxmox_version.as_deref(),
    ) {
        return Err(ApiError::BadRequest(format!(
            "{component} helper is already installed"
        )));
    }
    if has_pending_system_reboot(pool, machine_id).await? {
        return Err(ApiError::Conflict(
            "machine is rebooting; wait for system.reboot to finish".into(),
        ));
    }
    if has_other_active_commands(pool, machine_id).await? {
        return Err(ApiError::Conflict("machine is busy with commands".into()));
    }
    if has_pending_agent_update(pool, machine_id).await? {
        return Err(ApiError::Conflict("a package update is already queued".into()));
    }
    let release = crate::feature_repo::releases::get_pinned_release(
        pool,
        component,
        &machine.os,
        &machine.arch,
    )
    .await?;
    match release {
        None => {
            return Err(ApiError::BadRequest(format!(
                "no {component} helper package is available for {}/{} (install/pin the feature first)",
                machine.os, machine.arch
            )));
        }
        Some(release) if release.signature.trim().is_empty() => {
            return Err(ApiError::BadRequest(format!(
                "latest {component} helper release is not signed"
            )));
        }
        Some(_) => {}
    }
    Ok(())
}

pub async fn enqueue_helper_install(
    pool: &PgPool,
    machine_id: Uuid,
    ai_identity_id: Option<Uuid>,
    component: &str,
) -> ApiResult<Uuid> {
    ensure_can_install(pool, machine_id, component).await?;
    let command_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO command_queue (id, machine_id, ai_identity_id, command_name, params, status, timeout_secs)
         VALUES ($1, $2, $3, 'helper.install', $4, 'queued', $5)",
    )
    .bind(command_id)
    .bind(machine_id)
    .bind(ai_identity_id)
    .bind(json!({ "component": component }))
    .bind(TIMEOUT_SECS)
    .execute(pool)
    .await?;
    Ok(command_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_helper_component_requires_known_name() {
        assert_eq!(
            parse_helper_component(&json!({ "component": "proxmox" })).unwrap(),
            "proxmox"
        );
        assert!(parse_helper_component(&json!({ "component": "agent" })).is_err());
        assert!(parse_helper_component(&json!({})).is_err());
    }

    #[test]
    fn parse_pending_install_component_from_helper_install_and_agent_update() {
        assert_eq!(
            parse_pending_install_component(
                "helper.install",
                &json!({ "component": "desktop" })
            )
            .as_deref(),
            Some("desktop")
        );
        assert_eq!(
            parse_pending_install_component(
                "agent.update",
                &json!({ "install": ["proxmox"] })
            )
            .as_deref(),
            Some("proxmox")
        );
        assert!(parse_pending_install_component("agent.update", &json!({})).is_none());
        assert!(parse_pending_install_component("shell.run", &json!({})).is_none());
    }

    #[test]
    fn installable_helpers_lists_missing_os_compatible_packages() {
        let helpers = installable_helpers(
            Some("active"),
            None,
            None,
            Some("1.0.15"),
            Some("1.0.15"),
            None,
        );
        assert_eq!(helpers.len(), 2);
        assert_eq!(helpers[0]["component"], "desktop");
        assert_eq!(helpers[1]["component"], "proxmox");

        let linux_desktop_only = installable_helpers(
            Some("active"),
            None,
            None,
            Some("1.0.15"),
            None,
            None,
        );
        assert_eq!(linux_desktop_only.len(), 1);
        assert_eq!(linux_desktop_only[0]["component"], "desktop");

        let pending = installable_helpers(
            Some("active"),
            None,
            None,
            Some("1.0.15"),
            Some("1.0.15"),
            Some("proxmox"),
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["component"], "desktop");

        let installed = installable_helpers(
            Some("active"),
            Some("1.0.0"),
            Some("1.0.0"),
            Some("1.0.15"),
            Some("1.0.15"),
            None,
        );
        assert!(installed.is_empty());
    }
}
