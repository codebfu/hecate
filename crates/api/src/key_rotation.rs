//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Ed25519 key rotation: task signing, agent identity request, release dual-key, cron purge.

use chrono::{DateTime, Duration, Utc};
use hecate_protocol::task::{KeyContinuityAttestation, KeyMaterialPayload};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::append_audit;
use crate::crypto::{unwrap_task_signing_privkey, wrap_task_signing_privkey};
use crate::error::{ApiError, ApiResult};
use crate::server_settings;
use crate::task_crypto::{
    generate_task_signing_keypair, sign_continuity, task_signing_pubkey_from_privkey,
};

const DEFAULT_OVERLAP_SECS: u64 = 604_800;
const CRON_TICK_SECS: u64 = 3_600;

#[derive(Debug, Deserialize)]
pub struct RotateKeysBody {
    pub machine_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct AgentKeyMaterialRow {
    pub task_signing_privkey: String,
    pub task_signing_pubkey_previous_b64: Option<String>,
    pub task_signing_previous_expires_at: Option<DateTime<Utc>>,
    pub task_signing_continuity_sig_b64: Option<String>,
    pub task_signing_continuity_chain: Vec<KeyContinuityAttestation>,
    pub credential_rotation_requested_at: Option<DateTime<Utc>>,
    pub credential_pubkey_previous: Option<String>,
    pub credential_pubkey_previous_expires_at: Option<DateTime<Utc>>,
}

pub async fn overlap_secs(pool: &PgPool) -> ApiResult<u64> {
    Ok(server_settings::key_rotation_overlap_secs(pool)
        .await?
        .unwrap_or(DEFAULT_OVERLAP_SECS)
        .max(60))
}

pub async fn rotate_task_signing_for_agent(pool: &PgPool, machine_id: Uuid) -> ApiResult<()> {
    let overlap = overlap_secs(pool).await?;
    let expires_at = Utc::now() + Duration::seconds(overlap as i64);

    let current: Option<(String,)> = sqlx::query_as(
        "SELECT task_signing_privkey FROM agents WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;

    let Some((current_privkey,)) = current else {
        return Err(ApiError::NotFound);
    };

    let current_plain = if current_privkey.trim().is_empty() {
        String::new()
    } else {
        unwrap_task_signing_privkey(&current_privkey)
            .map_err(|error| ApiError::Internal(error))?
    };

    let previous_pubkey = if current_plain.trim().is_empty() {
        None
    } else {
        Some(task_signing_pubkey_from_privkey(&current_plain)?)
    };

    let (new_plain, new_pubkey) = generate_task_signing_keypair();
    let continuity_sig = if let Some(prev_pub) = previous_pubkey.as_ref() {
        Some(sign_continuity(&current_plain, prev_pub, &new_pubkey)?)
    } else {
        None
    };

    let existing_chain: serde_json::Value = sqlx::query_scalar(
        "SELECT COALESCE(task_signing_continuity_chain, '[]'::jsonb) FROM agents WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_one(pool)
    .await?;
    let mut chain: Vec<KeyContinuityAttestation> =
        serde_json::from_value(existing_chain).unwrap_or_default();
    if let (Some(prev_pub), Some(sig)) = (previous_pubkey.as_ref(), continuity_sig.as_ref()) {
        chain.push(KeyContinuityAttestation {
            previous_pubkey_b64: prev_pub.clone(),
            successor_pubkey_b64: new_pubkey.clone(),
            signature_b64: sig.clone(),
        });
        if chain.len() > 3 {
            let skip = chain.len() - 3;
            chain = chain[skip..].to_vec();
        }
    }
    let chain_json = serde_json::to_value(&chain).unwrap_or_else(|_| serde_json::json!([]));
    let wrapped_new = wrap_task_signing_privkey(&new_plain)
        .map_err(|error| ApiError::Internal(error))?;

    sqlx::query(
        "UPDATE agents SET
            task_signing_privkey_previous = CASE
                WHEN $2::text = '' THEN NULL ELSE task_signing_privkey END,
            task_signing_pubkey_previous_b64 = $3,
            task_signing_previous_expires_at = CASE
                WHEN $3::text IS NULL THEN NULL ELSE $4 END,
            task_signing_privkey = $2,
            task_signing_continuity_sig_b64 = $5,
            task_signing_continuity_chain = $6
         WHERE machine_id = $1",
    )
    .bind(machine_id)
    .bind(&wrapped_new)
    .bind(previous_pubkey.as_deref())
    .bind(expires_at)
    .bind(continuity_sig.as_deref())
    .bind(chain_json)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn rotate_task_signing_all(pool: &PgPool) -> ApiResult<u64> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT machine_id FROM agents WHERE state <> 'revoked'::agent_state",
    )
    .fetch_all(pool)
    .await?;

    let mut count = 0u64;
    for id in ids {
        rotate_task_signing_for_agent(pool, id).await?;
        count += 1;
    }
    server_settings::set_task_signing_last_rotated_at(pool, Some(Utc::now())).await?;
    Ok(count)
}

pub async fn request_credential_rotation_for_agent(
    pool: &PgPool,
    machine_id: Uuid,
) -> ApiResult<()> {
    let updated = sqlx::query(
        "UPDATE agents SET credential_rotation_requested_at = now()
         WHERE machine_id = $1 AND state <> 'revoked'::agent_state",
    )
    .bind(machine_id)
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

pub async fn request_credential_rotation_all(pool: &PgPool) -> ApiResult<u64> {
    let result = sqlx::query(
        "UPDATE agents SET credential_rotation_requested_at = now()
         WHERE state <> 'revoked'::agent_state",
    )
    .execute(pool)
    .await?;
    server_settings::set_credential_rotation_last_requested_at(pool, Some(Utc::now())).await?;
    Ok(result.rows_affected())
}

pub async fn apply_credential_rotation(
    pool: &PgPool,
    machine_id: Uuid,
    new_public_key: &str,
) -> ApiResult<DateTime<Utc>> {
    let new_public_key = new_public_key.trim();
    if new_public_key.is_empty() {
        return Err(ApiError::BadRequest("new_public_key is required".into()));
    }

    let overlap = overlap_secs(pool).await?;
    let expires_at = Utc::now() + Duration::seconds(overlap as i64);

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT credential_pubkey FROM agents WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;

    let Some((old_pubkey,)) = row else {
        return Err(ApiError::NotFound);
    };

    if old_pubkey.trim() == new_public_key {
        return Err(ApiError::BadRequest(
            "new_public_key must differ from the current credential".into(),
        ));
    }

    sqlx::query(
        "UPDATE agents SET
            credential_pubkey_previous = credential_pubkey,
            credential_pubkey_previous_expires_at = $2,
            credential_pubkey = $3,
            credential_rotation_requested_at = NULL
         WHERE machine_id = $1",
    )
    .bind(machine_id)
    .bind(expires_at)
    .bind(new_public_key)
    .execute(pool)
    .await?;

    Ok(expires_at)
}

pub async fn load_agent_key_material(
    pool: &PgPool,
    machine_id: Uuid,
) -> ApiResult<Option<AgentKeyMaterialRow>> {
    let row: Option<(
        String,
        Option<String>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<String>,
        Option<DateTime<Utc>>,
        Option<String>,
        serde_json::Value,
    )> = sqlx::query_as(
        "SELECT task_signing_privkey,
                task_signing_pubkey_previous_b64,
                task_signing_previous_expires_at,
                credential_rotation_requested_at,
                credential_pubkey_previous,
                credential_pubkey_previous_expires_at,
                task_signing_continuity_sig_b64,
                COALESCE(task_signing_continuity_chain, '[]'::jsonb)
         FROM agents WHERE machine_id = $1",
    )
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Ok(None),
        Some((
            task_signing_privkey,
            task_signing_pubkey_previous_b64,
            task_signing_previous_expires_at,
            credential_rotation_requested_at,
            credential_pubkey_previous,
            credential_pubkey_previous_expires_at,
            task_signing_continuity_sig_b64,
            chain_json,
        )) => {
            let plaintext = unwrap_task_signing_privkey(&task_signing_privkey)?;
            let chain: Vec<KeyContinuityAttestation> =
                serde_json::from_value(chain_json).unwrap_or_default();
            Ok(Some(AgentKeyMaterialRow {
                task_signing_privkey: plaintext,
                task_signing_pubkey_previous_b64,
                task_signing_previous_expires_at,
                task_signing_continuity_sig_b64,
                task_signing_continuity_chain: chain,
                credential_rotation_requested_at,
                credential_pubkey_previous,
                credential_pubkey_previous_expires_at,
            }))
        }
    }
}

pub async fn build_key_material_payload(
    pool: &PgPool,
    env: &crate::state::AppConfig,
    machine_id: Uuid,
) -> ApiResult<KeyMaterialPayload> {
    let agent = load_agent_key_material(pool, machine_id).await?;
    let release = server_settings::resolve_release_keys(pool, env).await?;

    let mut payload = KeyMaterialPayload {
        release_public_key_b64: server_settings::optional_release_public_key(&release.current),
        release_public_key_previous_b64: release.previous.clone(),
        release_key_overlap_until: release.overlap_until.map(|ts| ts.to_rfc3339()),
        release_key_continuity_sig_b64: release.continuity_sig_b64.clone(),
        ..Default::default()
    };

    let Some(agent) = agent else {
        return Ok(payload);
    };

    if !agent.task_signing_privkey.trim().is_empty() {
        payload.task_signing_pubkey_b64 =
            Some(task_signing_pubkey_from_privkey(&agent.task_signing_privkey)?);
        payload.task_signing_continuity_sig_b64 = agent.task_signing_continuity_sig_b64.clone();
        payload.task_signing_continuity_chain = agent.task_signing_continuity_chain.clone();
    }

    let now = Utc::now();
    if let (Some(prev), Some(expires)) = (
        agent.task_signing_pubkey_previous_b64.as_ref(),
        agent.task_signing_previous_expires_at,
    ) {
        if expires > now && !prev.trim().is_empty() {
            payload.task_signing_pubkey_previous_b64 = Some(prev.clone());
            payload.task_signing_overlap_until = Some(expires.to_rfc3339());
        }
    }

    let previous_still_active = agent
        .credential_pubkey_previous_expires_at
        .is_some_and(|expires| expires > now)
        && agent
            .credential_pubkey_previous
            .as_ref()
            .is_some_and(|k| !k.trim().is_empty());

    payload.rotate_credential =
        agent.credential_rotation_requested_at.is_some() && !previous_still_active;

    Ok(payload)
}

/// Purge expired previous keys (agents + release settings).
pub async fn purge_expired_keys(pool: &PgPool) -> ApiResult<u64> {
    let agent_result = sqlx::query(
        "UPDATE agents SET
            credential_pubkey_previous = NULL,
            credential_pubkey_previous_expires_at = NULL
         WHERE credential_pubkey_previous_expires_at IS NOT NULL
           AND credential_pubkey_previous_expires_at <= now()",
    )
    .execute(pool)
    .await?;

    let task_result = sqlx::query(
        "UPDATE agents SET
            task_signing_privkey_previous = NULL,
            task_signing_pubkey_previous_b64 = NULL,
            task_signing_previous_expires_at = NULL
         WHERE task_signing_previous_expires_at IS NOT NULL
           AND task_signing_previous_expires_at <= now()",
    )
    .execute(pool)
    .await?;

    let mut purged = agent_result.rows_affected() + task_result.rows_affected();

    if server_settings::purge_expired_release_previous(pool).await? {
        purged += 1;
    }

    Ok(purged)
}

async fn scheduled_rotation_due(pool: &PgPool) -> ApiResult<bool> {
    let interval = server_settings::key_rotation_interval_secs(pool)
        .await?
        .unwrap_or(DEFAULT_OVERLAP_SECS);
    if interval == 0 {
        return Ok(false);
    }

    let last_task = server_settings::task_signing_last_rotated_at(pool).await?;
    let last_cred = server_settings::credential_rotation_last_requested_at(pool).await?;
    let last = match (last_task, last_cred) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    Ok(match last {
        None => true,
        Some(ts) => Utc::now() >= ts + Duration::seconds(interval as i64),
    })
}

pub async fn run_key_rotation_tick(pool: &PgPool) -> ApiResult<()> {
    let purged = purge_expired_keys(pool).await?;
    if purged > 0 {
        append_audit(
            pool,
            "system",
            "settings.key_overlap_expired",
            "",
            "",
            &serde_json::json!({ "purged_rows": purged }),
        )
        .await?;
    }

    if !scheduled_rotation_due(pool).await? {
        return Ok(());
    }

    let task_count = rotate_task_signing_all(pool).await?;
    let cred_count = request_credential_rotation_all(pool).await?;
    append_audit(
        pool,
        "system",
        "settings.keys_rotated",
        "",
        "",
        &serde_json::json!({
            "source": "cron",
            "task_signing_agents": task_count,
            "credential_rotation_agents": cred_count,
        }),
    )
    .await?;
    Ok(())
}

pub fn spawn_key_rotation_loop(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(CRON_TICK_SECS));
        loop {
            ticker.tick().await;
            if let Err(error) = run_key_rotation_tick(&pool).await {
                tracing::warn!(error = %error, "key rotation tick failed");
            }
        }
    });
}
