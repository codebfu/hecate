//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Command queue dispatch for agent pull.

use hecate_protocol::authz::CapabilityProfile;
use hecate_protocol::task::{AgentTask, PullResponse, TaskExecutionPolicy};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::permissions;
use crate::state::AppConfig;
use crate::task_crypto::sign_task;
use crate::updates::{
    has_other_active_commands, has_pending_agent_update, has_pending_system_reboot,
    version_is_older,
};

/// Maximum commands claimed per pull request.
pub const PULL_BATCH_LIMIT: i64 = 10;

/// Wall-clock budget for download + verify + replace of agent/desktop binaries.
pub const AGENT_UPDATE_TIMEOUT_SECS: i32 = 600;

pub const RELEASE_ARTIFACT_PATH_PREFIX: &str = "/api/v1/agent/releases";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimedCommand {
    pub id: Uuid,
    pub ai_identity_id: Option<Uuid>,
    pub command_name: String,
    pub params: Value,
    pub timeout_secs: i32,
    pub matched_grant_assignment_id: Option<Uuid>,
    pub execution_policy_snapshot: Value,
}

#[derive(Debug, Clone)]
pub struct DispatchedCommand {
    pub command: ClaimedCommand,
    pub execution_policy: TaskExecutionPolicy,
    pub policy_timeout_secs: u32,
}

#[derive(Debug, Clone)]
struct PendingRelease {
    version: String,
    sha256: String,
    signature: String,
    public_key_b64: String,
}

async fn load_pending_release(
    pool: &PgPool,
    feature_id: &str,
    os: &str,
    arch: &str,
) -> ApiResult<Option<PendingRelease>> {
    let Some(release) =
        crate::feature_repo::releases::get_pinned_release(pool, feature_id, os, arch).await?
    else {
        return Ok(None);
    };
    Ok(Some(PendingRelease {
        version: release.version,
        sha256: release.sha256,
        signature: release.signature,
        public_key_b64: release.public_key_b64,
    }))
}

pub fn sign_task_for_command(
    task_signing_privkey_b64: &str,
    command_id: Uuid,
    machine_id: Uuid,
    command_name: &str,
    params: &Value,
    execution_policy: &TaskExecutionPolicy,
) -> ApiResult<String> {
    let _ = machine_id;
    sign_task(
        task_signing_privkey_b64,
        command_id,
        command_name,
        params,
        execution_policy,
    )
}

pub fn build_pull_response(
    task_signing_privkey_b64: &str,
    machine_id: Uuid,
    commands: &[DispatchedCommand],
) -> ApiResult<PullResponse> {
    build_pull_response_with_keys(task_signing_privkey_b64, machine_id, commands, None)
}

pub fn build_pull_response_with_keys(
    task_signing_privkey_b64: &str,
    machine_id: Uuid,
    commands: &[DispatchedCommand],
    key_material: Option<hecate_protocol::task::KeyMaterialPayload>,
) -> ApiResult<PullResponse> {
    let tasks = commands
        .iter()
        .map(|entry| {
            let command = &entry.command;
            let params = prepare_command_params(command);
            let timeout_secs =
                effective_timeout_secs(command.timeout_secs, entry.policy_timeout_secs);
            let execution_policy = entry.execution_policy.clone();
            let server_task_sig = sign_task_for_command(
                task_signing_privkey_b64,
                command.id,
                machine_id,
                &command.command_name,
                &params,
                &execution_policy,
            )?;
            Ok(AgentTask::ExecuteCommand {
                command_id: command.id,
                command_name: command.command_name.clone(),
                params,
                timeout_secs,
                execution_policy,
                server_task_sig,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(PullResponse {
        tasks,
        key_material,
    })
}

fn execution_policy_for_command(
    command: &ClaimedCommand,
    profile: &CapabilityProfile,
) -> TaskExecutionPolicy {
    if command.ai_identity_id.is_none()
        && crate::helper_install::is_package_update_command(&command.command_name)
    {
        TaskExecutionPolicy {
            allowed_commands: vec![command.command_name.clone()],
            shell_policy: profile.shell_policy.clone(),
            elevation_policy: profile.elevation_policy.clone(),
            max_output_bytes: profile.max_output_bytes,
            max_file_bytes: profile.max_file_bytes,
        }
    } else {
        TaskExecutionPolicy::from(profile)
    }
}

fn policy_timeout_for_command(command: &ClaimedCommand, profile: &CapabilityProfile) -> u32 {
    if crate::helper_install::is_package_update_command(&command.command_name) {
        (command.timeout_secs.max(1) as u32).max(profile.timeout_secs)
    } else {
        profile.timeout_secs
    }
}

fn effective_timeout_secs(queue_secs: i32, policy_timeout_secs: u32) -> u32 {
    (queue_secs.max(1) as u32).min(policy_timeout_secs)
}

pub fn prepare_command_params(command: &ClaimedCommand) -> Value {
    if command.command_name == "file.push"
        || (command.command_name == "desktop.clipboard.set"
            && command
                .params
                .get("artifact_id")
                .and_then(|v| v.as_str())
                .is_some())
    {
        let mut params = command.params.clone();
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "artifact_download_path".into(),
                Value::String(crate::command_artifacts::command_artifact_api_path(command.id)),
            );
        }
        params
    } else {
        command.params.clone()
    }
}

pub fn release_artifact_api_path(version: &str) -> String {
    hecate_protocol::release_artifacts::release_artifact_api_path(
        version,
        hecate_protocol::release_artifacts::ReleaseComponent::Agent,
    )
}

pub fn desktop_release_artifact_api_path(version: &str) -> String {
    hecate_protocol::release_artifacts::release_artifact_api_path(
        version,
        hecate_protocol::release_artifacts::ReleaseComponent::Desktop,
    )
}

pub fn proxmox_release_artifact_api_path(version: &str) -> String {
    hecate_protocol::release_artifacts::release_artifact_api_path(
        version,
        hecate_protocol::release_artifacts::ReleaseComponent::Proxmox,
    )
}

fn empty_offer(
    current_version: &str,
    reason: Option<String>,
) -> hecate_protocol::agent::UpdateOfferResponse {
    hecate_protocol::agent::UpdateOfferResponse {
        available: false,
        current_version: current_version.to_string(),
        target_version: None,
        artifact_path: None,
        sha256: None,
        signature: None,
        release_public_key_b64: None,
        reason,
        desktop: None,
        proxmox: None,
        key_material: None,
        server_task_sig: None,
    }
}

pub async fn load_task_signing_privkey(pool: &PgPool, machine_id: Uuid) -> ApiResult<String> {
    let privkey: Option<String> = sqlx::query_scalar(
        "SELECT task_signing_privkey FROM agents WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;
    let stored = privkey.unwrap_or_default();
    crate::crypto::unwrap_task_signing_privkey(&stored)
        .map_err(|error| ApiError::Internal(error))
}

pub async fn enqueue_agent_update(
    pool: &PgPool,
    machine_id: Uuid,
    ai_identity_id: Option<Uuid>,
) -> ApiResult<Uuid> {
    if has_other_active_commands(pool, machine_id).await? {
        return Err(ApiError::Conflict(
            "machine is busy with commands".into(),
        ));
    }
    if has_pending_system_reboot(pool, machine_id).await? {
        return Err(ApiError::Conflict(
            "machine is rebooting; wait for system.reboot to finish".into(),
        ));
    }
    if has_pending_agent_update(pool, machine_id).await? {
        return Err(ApiError::Conflict("agent update is already queued".into()));
    }

    let command_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO command_queue (id, machine_id, ai_identity_id, command_name, params, status, timeout_secs)
         VALUES ($1, $2, $3, 'agent.update', '{}', 'queued', $4)",
    )
    .bind(command_id)
    .bind(machine_id)
    .bind(ai_identity_id)
    .bind(AGENT_UPDATE_TIMEOUT_SECS)
    .execute(pool)
    .await?;

    Ok(command_id)
}

pub async fn build_update_offer_response(
    pool: &PgPool,
    config: &AppConfig,
    machine_id: Uuid,
    agent_version: &str,
    desktop_version: Option<&str>,
    proxmox_version: Option<&str>,
) -> ApiResult<hecate_protocol::agent::UpdateOfferResponse> {
    use hecate_protocol::agent::UpdateOfferResponse;

    let machine: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT os, arch, agent_version FROM machines WHERE id = $1",
    )
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;

    let Some((os, arch, reported_version)) = machine else {
        return Ok(empty_offer(agent_version, Some("machine not found".into())));
    };

    let current = if agent_version.trim().is_empty() {
        reported_version.as_deref().unwrap_or("0.0.0")
    } else {
        agent_version
    };

    // Exclude the in-flight agent.update itself; otherwise admin "Update" always
    // self-blocks when the agent fetches the offer after the command is claimed.
    if has_other_active_commands(pool, machine_id).await? {
        return Ok(empty_offer(
            current,
            Some("machine is busy with AI commands".into()),
        ));
    }

    // Fleet package offers come from installed feature-repo pins + mirrored artifacts.
    let agent_release = load_pending_release(pool, "agent", &os, &arch).await?;
    let desktop_release = load_pending_release(pool, "desktop", &os, &arch).await?;
    let proxmox_release = load_pending_release(pool, "proxmox", &os, &arch).await?;

    let resolved_key =
        crate::server_settings::resolve_release_signing_public_key_b64(pool, config).await?;
    let release_public_key_b64 = agent_release
        .as_ref()
        .map(|release| release.public_key_b64.as_str())
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| resolved_key.trim());
    let install_component =
        crate::helper_install::pending_install_component(pool, machine_id).await?;

    let agent_parts = if install_component.is_some() {
        AgentReleaseOfferParts {
            available: false,
            target_version: None,
            artifact_path: None,
            sha256: None,
            signature: None,
            offer_key: if release_public_key_b64.is_empty() {
                None
            } else {
                Some(release_public_key_b64.to_string())
            },
            reason: None,
        }
    } else {
        decide_agent_release_offer(
            &os,
            &arch,
            current,
            agent_release.as_ref(),
            release_public_key_b64,
        )
    };
    let agent_available = agent_parts.available;
    let target_version = agent_parts.target_version;
    let artifact_path = agent_parts.artifact_path;
    let sha256 = agent_parts.sha256;
    let signature = agent_parts.signature;
    let mut offer_key = agent_parts.offer_key;
    let mut reason = agent_parts.reason;

    let desktop = match install_component.as_deref() {
        Some("desktop") => first_install_desktop_offer(
            desktop_version,
            desktop_release.as_ref(),
            release_public_key_b64,
        ),
        Some(_) => None,
        None => existing_desktop_offer(
            desktop_version,
            desktop_release.as_ref(),
            release_public_key_b64,
        ),
    };

    let proxmox = match install_component.as_deref() {
        Some("proxmox") => first_install_proxmox_offer(
            proxmox_version,
            proxmox_release.as_ref(),
            release_public_key_b64,
        ),
        Some(_) => None,
        None => existing_proxmox_offer(
            proxmox_version,
            proxmox_release.as_ref(),
            release_public_key_b64,
        ),
    };

    let desktop_available = desktop.as_ref().is_some_and(|d| d.available);
    let proxmox_available = proxmox.as_ref().is_some_and(|offer| offer.available);
    let available = agent_available || desktop_available || proxmox_available;

    if available {
        reason = None;
        if offer_key.is_none() && !release_public_key_b64.is_empty() {
            offer_key = Some(release_public_key_b64.to_string());
        }
    }

    let mut offer = UpdateOfferResponse {
        available,
        current_version: current.to_string(),
        target_version,
        artifact_path,
        sha256,
        signature,
        release_public_key_b64: offer_key,
        reason,
        desktop,
        proxmox,
        key_material: Some(
            crate::key_rotation::build_key_material_payload(pool, config, machine_id).await?,
        ),
        server_task_sig: None,
    };
    attach_self_update_sigs(pool, machine_id, &mut offer).await?;
    Ok(offer)
}

async fn attach_self_update_sigs(
    pool: &PgPool,
    machine_id: Uuid,
    offer: &mut hecate_protocol::agent::UpdateOfferResponse,
) -> ApiResult<()> {
    let privkey = load_task_signing_privkey(pool, machine_id).await?;
    if privkey.trim().is_empty() {
        return Ok(());
    }
    let policy = TaskExecutionPolicy::default();
    if offer.available {
        if let (Some(path), Some(sha), Some(version)) = (
            offer.artifact_path.as_deref(),
            offer.sha256.as_deref(),
            offer.target_version.as_deref(),
        ) {
            let params = hecate_protocol::task::self_update_sign_params(
                "self_update",
                path,
                sha,
                version,
            );
            offer.server_task_sig = Some(sign_task_for_command(
                &privkey,
                machine_id,
                machine_id,
                "self_update",
                &params,
                &policy,
            )?);
        }
    }
    if let Some(desktop) = offer.desktop.as_mut() {
        if desktop.available {
            if let (Some(path), Some(sha), Some(version)) = (
                desktop.artifact_path.as_deref(),
                desktop.sha256.as_deref(),
                desktop.target_version.as_deref(),
            ) {
                let params = hecate_protocol::task::self_update_sign_params(
                    "desktop_update",
                    path,
                    sha,
                    version,
                );
                desktop.server_task_sig = Some(sign_task_for_command(
                    &privkey,
                    machine_id,
                    machine_id,
                    "self_update",
                    &params,
                    &policy,
                )?);
            }
        }
    }
    if let Some(proxmox) = offer.proxmox.as_mut() {
        if proxmox.available {
            if let (Some(path), Some(sha), Some(version)) = (
                proxmox.artifact_path.as_deref(),
                proxmox.sha256.as_deref(),
                proxmox.target_version.as_deref(),
            ) {
                let params = hecate_protocol::task::self_update_sign_params(
                    "proxmox_update",
                    path,
                    sha,
                    version,
                );
                proxmox.server_task_sig = Some(sign_task_for_command(
                    &privkey,
                    machine_id,
                    machine_id,
                    "self_update",
                    &params,
                    &policy,
                )?);
            }
        }
    }
    Ok(())
}

fn signed_helper_release_ready(release: &PendingRelease, release_public_key_b64: &str) -> bool {
    !release.signature.trim().is_empty() && !release_public_key_b64.trim().is_empty()
}

fn existing_desktop_offer(
    desktop_version: Option<&str>,
    desktop_release: Option<&PendingRelease>,
    release_public_key_b64: &str,
) -> Option<hecate_protocol::agent::DesktopUpdateOffer> {
    match (desktop_version, desktop_release) {
        (Some(local_desktop), Some(release))
            if signed_helper_release_ready(release, release_public_key_b64)
                && version_is_older(local_desktop, &release.version) =>
        {
            Some(hecate_protocol::agent::DesktopUpdateOffer {
                available: true,
                current_version: Some(local_desktop.to_string()),
                target_version: Some(release.version.clone()),
                artifact_path: Some(desktop_release_artifact_api_path(&release.version)),
                sha256: Some(release.sha256.clone()),
                signature: Some(release.signature.clone()),
                server_task_sig: None,
            })
        }
        (Some(local_desktop), Some(release)) => Some(hecate_protocol::agent::DesktopUpdateOffer {
            available: false,
            current_version: Some(local_desktop.to_string()),
            target_version: Some(release.version.clone()),
            artifact_path: None,
            sha256: None,
            signature: None,
            server_task_sig: None,
        }),
        (Some(local_desktop), None) => Some(hecate_protocol::agent::DesktopUpdateOffer {
            available: false,
            current_version: Some(local_desktop.to_string()),
            target_version: None,
            artifact_path: None,
            sha256: None,
            signature: None,
            server_task_sig: None,
        }),
        (None, _) => None,
    }
}

fn first_install_desktop_offer(
    desktop_version: Option<&str>,
    desktop_release: Option<&PendingRelease>,
    release_public_key_b64: &str,
) -> Option<hecate_protocol::agent::DesktopUpdateOffer> {
    let release = desktop_release?;
    let current_version = desktop_version
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if signed_helper_release_ready(release, release_public_key_b64) {
        Some(hecate_protocol::agent::DesktopUpdateOffer {
            available: true,
            current_version,
            target_version: Some(release.version.clone()),
            artifact_path: Some(desktop_release_artifact_api_path(&release.version)),
            sha256: Some(release.sha256.clone()),
            signature: Some(release.signature.clone()),
            server_task_sig: None,
        })
    } else {
        Some(hecate_protocol::agent::DesktopUpdateOffer {
            available: false,
            current_version,
            target_version: Some(release.version.clone()),
            artifact_path: None,
            sha256: None,
            signature: None,
            server_task_sig: None,
        })
    }
}

fn existing_proxmox_offer(
    proxmox_version: Option<&str>,
    proxmox_release: Option<&PendingRelease>,
    release_public_key_b64: &str,
) -> Option<hecate_protocol::agent::ProxmoxUpdateOffer> {
    match (proxmox_version, proxmox_release) {
        (Some(local_proxmox), Some(release))
            if signed_helper_release_ready(release, release_public_key_b64)
                && version_is_older(local_proxmox, &release.version) =>
        {
            Some(hecate_protocol::agent::ProxmoxUpdateOffer {
                available: true,
                current_version: Some(local_proxmox.to_string()),
                target_version: Some(release.version.clone()),
                artifact_path: Some(proxmox_release_artifact_api_path(&release.version)),
                sha256: Some(release.sha256.clone()),
                signature: Some(release.signature.clone()),
                server_task_sig: None,
            })
        }
        (Some(local_proxmox), Some(release)) => Some(hecate_protocol::agent::ProxmoxUpdateOffer {
            available: false,
            current_version: Some(local_proxmox.to_string()),
            target_version: Some(release.version.clone()),
            artifact_path: None,
            sha256: None,
            signature: None,
            server_task_sig: None,
        }),
        (Some(local_proxmox), None) => Some(hecate_protocol::agent::ProxmoxUpdateOffer {
            available: false,
            current_version: Some(local_proxmox.to_string()),
            target_version: None,
            artifact_path: None,
            sha256: None,
            signature: None,
            server_task_sig: None,
        }),
        (None, _) => None,
    }
}

fn first_install_proxmox_offer(
    proxmox_version: Option<&str>,
    proxmox_release: Option<&PendingRelease>,
    release_public_key_b64: &str,
) -> Option<hecate_protocol::agent::ProxmoxUpdateOffer> {
    let release = proxmox_release?;
    let current_version = proxmox_version
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if signed_helper_release_ready(release, release_public_key_b64) {
        Some(hecate_protocol::agent::ProxmoxUpdateOffer {
            available: true,
            current_version,
            target_version: Some(release.version.clone()),
            artifact_path: Some(proxmox_release_artifact_api_path(&release.version)),
            sha256: Some(release.sha256.clone()),
            signature: Some(release.signature.clone()),
            server_task_sig: None,
        })
    } else {
        Some(hecate_protocol::agent::ProxmoxUpdateOffer {
            available: false,
            current_version,
            target_version: Some(release.version.clone()),
            artifact_path: None,
            sha256: None,
            signature: None,
            server_task_sig: None,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AgentReleaseOfferParts {
    available: bool,
    target_version: Option<String>,
    artifact_path: Option<String>,
    sha256: Option<String>,
    signature: Option<String>,
    offer_key: Option<String>,
    reason: Option<String>,
}

fn decide_agent_release_offer(
    os: &str,
    arch: &str,
    current: &str,
    agent_release: Option<&PendingRelease>,
    release_public_key_b64: &str,
) -> AgentReleaseOfferParts {
    match agent_release {
        None => AgentReleaseOfferParts {
            available: false,
            target_version: None,
            artifact_path: None,
            sha256: None,
            signature: None,
            offer_key: None,
            reason: Some(format!("no release available for {os}/{arch}")),
        },
        Some(release) if !version_is_older(current, &release.version) => AgentReleaseOfferParts {
            available: false,
            target_version: Some(release.version.clone()),
            artifact_path: None,
            sha256: None,
            signature: None,
            offer_key: None,
            reason: Some("agent is already up to date".into()),
        },
        Some(release) if release.signature.trim().is_empty() => AgentReleaseOfferParts {
            available: false,
            target_version: Some(release.version.clone()),
            artifact_path: None,
            sha256: None,
            signature: None,
            offer_key: None,
            reason: Some("latest release is not signed (re-install the feature from the repository)".into()),
        },
        Some(release) if release_public_key_b64.trim().is_empty() => AgentReleaseOfferParts {
            available: false,
            target_version: Some(release.version.clone()),
            artifact_path: None,
            sha256: None,
            signature: None,
            offer_key: None,
            reason: Some("server release signing key is not configured".into()),
        },
        Some(release) => AgentReleaseOfferParts {
            available: true,
            target_version: Some(release.version.clone()),
            artifact_path: Some(release_artifact_api_path(&release.version)),
            sha256: Some(release.sha256.clone()),
            signature: Some(release.signature.clone()),
            offer_key: Some(release_public_key_b64.trim().to_string()),
            reason: None,
        },
    }
}

pub async fn claim_queued_commands(
    pool: &PgPool,
    machine_id: Uuid,
) -> ApiResult<Vec<ClaimedCommand>> {
    let commands = sqlx::query_as::<_, ClaimedCommand>(
        "UPDATE command_queue
         SET status = 'dispatched',
             dispatched_at = now(),
             dispatched_agent_id = $1,
             reboot_phase = CASE
                 WHEN command_name = 'system.reboot' THEN 'initiated'
                 ELSE reboot_phase
             END
         WHERE id IN (
             SELECT id
             FROM command_queue
             WHERE machine_id = $1
               AND status = 'queued'
               AND cancel_requested_at IS NULL
             ORDER BY created_at
             LIMIT $2
             FOR UPDATE SKIP LOCKED
         )
         RETURNING id, ai_identity_id, command_name, params, timeout_secs,
                   matched_grant_assignment_id, execution_policy_snapshot",
    )
    .bind(machine_id)
    .bind(PULL_BATCH_LIMIT)
    .fetch_all(pool)
    .await?;

    Ok(commands)
}

pub async fn load_dispatched_commands(
    pool: &PgPool,
    machine_id: Uuid,
) -> ApiResult<Vec<DispatchedCommand>> {
    let commands = claim_queued_commands(pool, machine_id).await?;
    let mut dispatched = Vec::with_capacity(commands.len());
    for command in commands {
        if let Some(identity_id) = command.ai_identity_id {
            if command.matched_grant_assignment_id.is_none() {
                cancel_dispatched_command(pool, command.id, "matched grant assignment missing")
                    .await?;
                continue;
            }
            if let Err(error) = permissions::authorize_command(
                pool,
                identity_id,
                machine_id,
                &command.command_name,
                &command.params,
            )
            .await
            {
                cancel_dispatched_command(
                    pool,
                    command.id,
                    &format!("re-authorization failed: {error}"),
                )
                .await?;
                continue;
            }
        }

        let execution_policy: TaskExecutionPolicy = if command.ai_identity_id.is_some() {
            serde_json::from_value(command.execution_policy_snapshot.clone()).map_err(|error| {
                ApiError::Internal(anyhow::anyhow!("invalid execution_policy_snapshot: {error}"))
            })?
        } else {
            let profile = default_admin_capability_profile(&command);
            execution_policy_for_command(&command, &profile)
        };
        let profile = snapshot_profile(&command, &execution_policy);
        let policy_timeout_secs = policy_timeout_for_command(&command, &profile);
        dispatched.push(DispatchedCommand {
            policy_timeout_secs,
            execution_policy,
            command,
        });
    }
    Ok(dispatched)
}

async fn cancel_dispatched_command(pool: &PgPool, command_id: Uuid, reason: &str) -> ApiResult<()> {
    sqlx::query(
        "UPDATE command_queue
         SET status = 'cancelled',
             finished_at = now(),
             cancel_requested_at = COALESCE(cancel_requested_at, now())
         WHERE id = $1 AND status = 'dispatched'",
    )
    .bind(command_id)
    .execute(pool)
    .await?;
    tracing::warn!(
        command_id = %command_id,
        reason = reason,
        "command cancelled at dispatch after authorization failure"
    );
    Ok(())
}

fn default_admin_capability_profile(command: &ClaimedCommand) -> CapabilityProfile {
    use chrono::Utc;
    use hecate_protocol::authz::AuthzProvenance;
    CapabilityProfile {
        id: Uuid::nil(),
        name: "admin-bootstrap".into(),
        description: String::new(),
        provenance: AuthzProvenance::Seed,
        request_scoped: false,
        owner_ai_identity_id: None,
        allowed_commands: vec![command.command_name.clone()],
        allowed_admin_commands: vec![],
        shell_policy: Default::default(),
        elevation_policy: Default::default(),
        max_output_bytes: hecate_protocol::permissions::DEFAULT_MAX_OUTPUT_BYTES,
        max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
        timeout_secs: hecate_protocol::permissions::DEFAULT_TIMEOUT_SECS,
        max_concurrent: hecate_protocol::permissions::DEFAULT_MAX_CONCURRENT,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn snapshot_profile(command: &ClaimedCommand, policy: &TaskExecutionPolicy) -> CapabilityProfile {
    let mut profile = default_admin_capability_profile(command);
    profile.allowed_commands = policy.allowed_commands.clone();
    profile.shell_policy = policy.shell_policy.clone();
    profile.elevation_policy = policy.elevation_policy.clone();
    profile.max_output_bytes = policy.max_output_bytes;
    profile.max_file_bytes = policy.max_file_bytes;
    profile
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_artifacts;
    use crate::task_crypto::generate_task_signing_keypair;

    fn empty_snapshot() -> Value {
        serde_json::json!({})
    }

    fn sample_claimed(command_name: &str) -> ClaimedCommand {
        ClaimedCommand {
            id: Uuid::nil(),
            ai_identity_id: None,
            command_name: command_name.into(),
            params: serde_json::json!({}),
            timeout_secs: 30,
            matched_grant_assignment_id: None,
            execution_policy_snapshot: empty_snapshot(),
        }
    }

    #[test]
    fn sign_task_is_deterministic() {
        let (privkey, _) = generate_task_signing_keypair();
        let command_id = Uuid::nil();
        let machine_id = Uuid::from_u128(1);
        let params = serde_json::json!({ "argv": ["/usr/bin/uptime"] });
        let policy = TaskExecutionPolicy {
            allowed_commands: vec!["shell.run".into()],
            shell_policy: hecate_protocol::permissions::ShellPolicy {
                allowed_binaries: vec!["/usr/bin/uptime".into()],
                allowed_cwd: vec!["/".into()],
                allowed_env: vec![],
            },
            elevation_policy: hecate_protocol::permissions::ElevationPolicy::default(),
            max_output_bytes: 1_048_576,
            max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
        };

        let first = sign_task_for_command(
            &privkey,
            command_id,
            machine_id,
            "shell.run",
            &params,
            &policy,
        )
        .unwrap();
        let second = sign_task_for_command(
            &privkey,
            command_id,
            machine_id,
            "shell.run",
            &params,
            &policy,
        )
        .unwrap();
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[test]
    fn build_pull_response_maps_execute_command_tasks() {
        let (privkey, _) = generate_task_signing_keypair();
        let machine_id = Uuid::from_u128(42);
        let command_id = Uuid::from_u128(7);
        let commands = vec![DispatchedCommand {
            command: ClaimedCommand {
                id: command_id,
                ai_identity_id: None,
                command_name: "system.info".into(),
                params: serde_json::json!({}),
                timeout_secs: 30,
                matched_grant_assignment_id: None,
                execution_policy_snapshot: empty_snapshot(),
            },
            execution_policy: TaskExecutionPolicy {
                allowed_commands: vec!["system.info".into()],
                shell_policy: hecate_protocol::permissions::ShellPolicy::default(),
                elevation_policy: hecate_protocol::permissions::ElevationPolicy::default(),
                max_output_bytes: 1_048_576,
                max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
            },
            policy_timeout_secs: 30,
        }];

        let response = build_pull_response(&privkey, machine_id, &commands).unwrap();
        assert_eq!(response.tasks.len(), 1);
        match &response.tasks[0] {
            AgentTask::ExecuteCommand {
                command_id: id,
                command_name,
                timeout_secs,
                execution_policy,
                server_task_sig,
                ..
            } => {
                assert_eq!(*id, command_id);
                assert_eq!(command_name, "system.info");
                assert_eq!(*timeout_secs, 30);
                assert_eq!(execution_policy.allowed_commands, vec!["system.info"]);
                assert!(!server_task_sig.is_empty());
            }
            other => panic!("unexpected task: {other:?}"),
        }
    }

    #[test]
    fn prepare_command_params_injects_artifact_download_path() {
        let command_id = Uuid::from_u128(99);
        let command = ClaimedCommand {
            id: command_id,
            ai_identity_id: Some(Uuid::new_v4()),
            command_name: "file.push".into(),
            params: serde_json::json!({
                "dest_path": "/tmp/app.conf",
                "artifact_id": "00000000-0000-4000-8000-000000000001",
                "sha256": "abc"
            }),
            timeout_secs: 30,
            matched_grant_assignment_id: Some(Uuid::new_v4()),
            execution_policy_snapshot: empty_snapshot(),
        };
        let params = prepare_command_params(&command);
        assert_eq!(
            params.get("artifact_download_path").and_then(|v| v.as_str()),
            Some(command_artifacts::command_artifact_api_path(command_id).as_str())
        );
    }

    #[test]
    fn version_is_older_compares_semver_parts() {
        assert!(version_is_older("0.1.0", "0.1.1"));
        assert!(version_is_older("0.1.9", "0.2.0"));
        assert!(!version_is_older("1.0.0", "0.9.9"));
        assert!(!version_is_older("0.1.0", "0.1.0"));
    }

    #[test]
    fn execution_policy_for_admin_agent_update() {
        let command = sample_claimed("agent.update");
        let profile = default_admin_capability_profile(&command);
        let policy = execution_policy_for_command(&command, &profile);
        assert_eq!(policy.allowed_commands, vec!["agent.update"]);
    }

    #[test]
    fn decide_agent_release_offer_requires_signing_key() {
        let release = PendingRelease {
            version: "1.2.3".into(),
            sha256: "abc".into(),
            signature: "sig".into(),
            public_key_b64: "pubkey-b64".into(),
        };
        let missing = decide_agent_release_offer("linux", "x86_64", "1.0.0", Some(&release), "");
        assert!(!missing.available);
        assert_eq!(
            missing.reason.as_deref(),
            Some("server release signing key is not configured")
        );
        assert!(missing.offer_key.is_none());

        let ready =
            decide_agent_release_offer("linux", "x86_64", "1.0.0", Some(&release), "pubkey-b64");
        assert!(ready.available);
        assert_eq!(ready.offer_key.as_deref(), Some("pubkey-b64"));
        assert_eq!(ready.target_version.as_deref(), Some("1.2.3"));
        assert!(ready.reason.is_none());
    }

    #[test]
    fn admin_agent_update_keeps_queue_timeout_budget() {
        let admin_update = ClaimedCommand {
            timeout_secs: AGENT_UPDATE_TIMEOUT_SECS,
            ..sample_claimed("agent.update")
        };
        let profile = default_admin_capability_profile(&admin_update);
        assert_eq!(profile.timeout_secs, 30);

        let policy_timeout = policy_timeout_for_command(&admin_update, &profile);
        assert_eq!(policy_timeout, AGENT_UPDATE_TIMEOUT_SECS as u32);
        assert_eq!(
            effective_timeout_secs(admin_update.timeout_secs, policy_timeout),
            AGENT_UPDATE_TIMEOUT_SECS as u32
        );

        let ai_update = ClaimedCommand {
            ai_identity_id: Some(Uuid::from_u128(1)),
            ..admin_update.clone()
        };
        assert_eq!(
            policy_timeout_for_command(&ai_update, &profile),
            AGENT_UPDATE_TIMEOUT_SECS as u32
        );

        let helper_install = ClaimedCommand {
            command_name: "helper.install".into(),
            params: serde_json::json!({ "component": "proxmox" }),
            ..admin_update
        };
        assert_eq!(
            policy_timeout_for_command(&helper_install, &profile),
            AGENT_UPDATE_TIMEOUT_SECS as u32
        );
        let helper_policy = execution_policy_for_command(&helper_install, &profile);
        assert_eq!(helper_policy.allowed_commands, vec!["helper.install"]);
    }

    #[test]
    fn first_install_offer_is_available_without_local_version() {
        let release = PendingRelease {
            version: "1.0.15".into(),
            sha256: "abc".into(),
            signature: "sig".into(),
            public_key_b64: "pubkey".into(),
        };
        let desktop = first_install_desktop_offer(None, Some(&release), "pubkey");
        assert!(desktop.as_ref().is_some_and(|offer| offer.available));
        assert!(desktop.unwrap().current_version.is_none());

        let proxmox = first_install_proxmox_offer(None, Some(&release), "pubkey");
        assert!(proxmox.as_ref().is_some_and(|offer| offer.available));
        assert_eq!(proxmox.unwrap().target_version.as_deref(), Some("1.0.15"));

        assert!(existing_desktop_offer(None, Some(&release), "pubkey").is_none());
        assert!(existing_proxmox_offer(None, Some(&release), "pubkey").is_none());
    }
}
