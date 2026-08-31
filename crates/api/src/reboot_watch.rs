//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Watch system.reboot commands through agent offline → online before completion.
//!
//! Fast VMs can reboot in a few seconds — shorter than [`OFFLINE_AFTER_SECS`] and the
//! watcher tick. Relying only on a stale `last_seen_at` therefore misses the cycle and
//! leaves the command stuck in `dispatched` until the stale-command reaper expires it
//! (blocking the machine the whole time).
//!
//! Heartbeat `uptime_secs` detects an agent process restart even when the offline
//! window was never observed: if uptime is lower than the age of the reboot claim
//! (or lower than the previously stored uptime), the reboot cycle is complete.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiResult;
use crate::machines::OFFLINE_AFTER_SECS;

/// Seconds without heartbeat after which an *in-flight reboot* is treated as agent_down.
/// Shorter than [`OFFLINE_AFTER_SECS`] so medium-speed reboots still progress.
const REBOOT_DOWN_AFTER_SECS: i64 = 5;

/// Mark reboot commands as agent_down when the machine has gone offline.
pub async fn mark_reboot_agent_down(pool: &PgPool) -> ApiResult<u64> {
    let result = sqlx::query(
        "UPDATE command_queue cq
         SET reboot_phase = 'agent_down',
             status = 'running'
         FROM machines m
         WHERE cq.machine_id = m.id
           AND cq.command_name = 'system.reboot'
           AND cq.status IN ('dispatched', 'running')
           AND cq.reboot_phase = 'initiated'
           AND (
               m.status = 'offline'
               OR m.last_seen_at IS NULL
               OR m.last_seen_at < now() - ($1 * interval '1 second')
           )",
    )
    .bind(REBOOT_DOWN_AFTER_SECS)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Complete reboot commands after the agent has been seen offline then online again.
pub async fn complete_reboot_agent_up(pool: &PgPool) -> ApiResult<u64> {
    let completed: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE command_queue cq
         SET status = 'completed',
             finished_at = now(),
             reboot_phase = NULL
         FROM machines m
         WHERE cq.machine_id = m.id
           AND cq.command_name = 'system.reboot'
           AND cq.status IN ('dispatched', 'running')
           AND cq.reboot_phase = 'agent_down'
           AND m.status = 'online'
           AND m.last_seen_at IS NOT NULL
           AND m.last_seen_at >= now() - ($1 * interval '1 second')
         RETURNING cq.id",
    )
    .bind(OFFLINE_AFTER_SECS)
    .fetch_all(pool)
    .await?;

    write_reboot_results(
        pool,
        &completed,
        "reboot cycle observed: agent went offline then online",
    )
    .await?;

    Ok(completed.len() as u64)
}

/// Complete in-flight reboots when a heartbeat proves the agent process restarted.
///
/// Call **before** persisting the new `agent_uptime_secs` so the previous value remains
/// available for comparison.
pub async fn complete_reboot_on_agent_restart(
    pool: &PgPool,
    machine_id: Uuid,
    uptime_secs: i64,
) -> ApiResult<u64> {
    let completed: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE command_queue cq
         SET status = 'completed',
             finished_at = now(),
             reboot_phase = NULL
         FROM machines m
         WHERE cq.machine_id = m.id
           AND m.id = $1
           AND cq.command_name = 'system.reboot'
           AND cq.status IN ('dispatched', 'running')
           AND cq.reboot_phase IN ('initiated', 'agent_down')
           AND cq.dispatched_at IS NOT NULL
           AND (
               -- Uptime shorter than claim age ⇒ process cannot predate the reboot claim.
               $2::bigint < EXTRACT(EPOCH FROM (now() - cq.dispatched_at))::bigint
               OR (
                   m.agent_uptime_secs IS NOT NULL
                   AND $2::bigint + 2 < m.agent_uptime_secs
               )
           )
         RETURNING cq.id",
    )
    .bind(machine_id)
    .bind(uptime_secs)
    .fetch_all(pool)
    .await?;

    write_reboot_results(
        pool,
        &completed,
        "reboot cycle observed: agent uptime reset after restart",
    )
    .await?;

    Ok(completed.len() as u64)
}

async fn write_reboot_results(
    pool: &PgPool,
    completed: &[Uuid],
    message: &str,
) -> ApiResult<()> {
    for command_id in completed {
        sqlx::query(
            "INSERT INTO command_results (command_id, stdout, stderr, exit_code, truncated, byte_count)
             VALUES ($1, $2, '', 0, false, $3)
             ON CONFLICT (command_id) DO NOTHING",
        )
        .bind(command_id)
        .bind(message)
        .bind(message.len() as i32)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn tick_reboot_watch(pool: &PgPool) -> ApiResult<(u64, u64)> {
    let down = mark_reboot_agent_down(pool).await?;
    let up = complete_reboot_agent_up(pool).await?;
    Ok((down, up))
}

pub fn spawn_reboot_watcher(pool: PgPool) {
    tokio::spawn(async move {
        // Tick often enough to catch short offline windows on fast VMs.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            ticker.tick().await;
            match tick_reboot_watch(&pool).await {
                Ok((0, 0)) => {}
                Ok((down, up)) => {
                    tracing::info!(
                        agent_down = down,
                        completed = up,
                        "system.reboot watcher progressed"
                    );
                }
                Err(error) => {
                    tracing::warn!(error = %error, "system.reboot watcher failed");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_threshold_matches_machines() {
        assert_eq!(OFFLINE_AFTER_SECS, 30);
    }

    #[test]
    fn reboot_down_is_stricter_than_fleet_offline() {
        assert!(REBOOT_DOWN_AFTER_SECS < OFFLINE_AFTER_SECS);
        assert!(REBOOT_DOWN_AFTER_SECS >= 2);
    }
}
