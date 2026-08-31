//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::append_audit;
use crate::error::{ApiError, ApiResult};
use crate::pagination::{self, CommandListQuery, PaginatedResponse};

const ACTIVE_STATUSES: &str =
    "'pending_approval', 'queued', 'dispatched', 'running'";
const TERMINAL_STATUSES: &str =
    "'completed', 'failed', 'expired', 'cancelled'";

/// Shared SELECT list for queue rows (active or historical).
const COMMAND_ROW_SELECT: &str = r#"
    cq.id,
    cq.machine_id,
    m.hostname AS machine_hostname,
    cq.ai_identity_id,
    ai.name AS ai_identity_name,
    cq.command_name,
    cq.params,
    cq.status,
    cq.reboot_phase,
    cq.created_at,
    cq.dispatched_at,
    cq.finished_at
"#;

pub async fn list_active_commands(
    pool: &PgPool,
    query: &CommandListQuery,
) -> ApiResult<PaginatedResponse<Value>> {
    let (limit, mut offset) = pagination::resolve_list_pagination(query.limit, query.offset);
    let include_recent = query.include_recent.unwrap_or(false);
    let machine_id = query.machine_id;

    // Deep-link: always resolve the exact command, even when terminal / expired.
    if let Some(command_id) = query.command_id {
        if let Some(row) = load_command_row(pool, command_id).await? {
            let status = row
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let is_active = matches!(
                status,
                "pending_approval" | "queued" | "dispatched" | "running"
            );
            if !is_active {
                // Terminal (completed/failed/expired/cancelled): still show for Audit deep-links.
                return Ok(PaginatedResponse {
                    items: vec![row],
                    total: 1,
                    limit,
                    offset: 0,
                });
            }
            if let Some(index) =
                command_queue_index(pool, command_id, machine_id, include_recent).await?
            {
                offset = pagination::page_offset_for_index(index, limit);
            }
        } else {
            return Ok(PaginatedResponse {
                items: vec![],
                total: 0,
                limit,
                offset: 0,
            });
        }
    }

    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*)::bigint
         FROM command_queue cq
         JOIN machines m ON m.id = cq.machine_id
         WHERE m.deleted_at IS NULL
           AND ($1::uuid IS NULL OR cq.machine_id = $1)
           AND ({})",
        status_predicate(include_recent)
    ))
    .bind(machine_id)
    .fetch_one(pool)
    .await?;

    let rows: Vec<Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t) FROM (
            SELECT {COMMAND_ROW_SELECT}
            FROM command_queue cq
            JOIN machines m ON m.id = cq.machine_id
            LEFT JOIN ai_identities ai ON ai.id = cq.ai_identity_id
            WHERE m.deleted_at IS NULL
              AND ($1::uuid IS NULL OR cq.machine_id = $1)
              AND ({})
            ORDER BY cq.created_at DESC, cq.id DESC
            LIMIT $2 OFFSET $3
         ) t",
        status_predicate(include_recent)
    ))
    .bind(machine_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(PaginatedResponse {
        items: rows,
        total,
        limit,
        offset,
    })
}

fn status_predicate(include_recent: bool) -> String {
    if include_recent {
        format!(
            "(cq.status IN ({ACTIVE_STATUSES})
              OR (
                   cq.status IN ({TERMINAL_STATUSES})
                   AND COALESCE(cq.finished_at, cq.created_at) > now() - interval '24 hours'
                 ))"
        )
    } else {
        format!("cq.status IN ({ACTIVE_STATUSES})")
    }
}

async fn load_command_row(pool: &PgPool, command_id: Uuid) -> ApiResult<Option<Value>> {
    let row: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t) FROM (
            SELECT {COMMAND_ROW_SELECT}
            FROM command_queue cq
            JOIN machines m ON m.id = cq.machine_id
            LEFT JOIN ai_identities ai ON ai.id = cq.ai_identity_id
            WHERE cq.id = $1
              AND m.deleted_at IS NULL
         ) t"
    ))
    .bind(command_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

async fn command_queue_index(
    pool: &PgPool,
    command_id: Uuid,
    machine_id: Option<Uuid>,
    include_recent: bool,
) -> ApiResult<Option<i64>> {
    let index: Option<i64> = sqlx::query_scalar(&format!(
        "SELECT position
         FROM (
             SELECT cq.id,
                    ROW_NUMBER() OVER (ORDER BY cq.created_at DESC, cq.id DESC) - 1 AS position
             FROM command_queue cq
             JOIN machines m ON m.id = cq.machine_id
             WHERE m.deleted_at IS NULL
               AND ($1::uuid IS NULL OR cq.machine_id = $1)
               AND ({})
         ) ranked
         WHERE id = $2",
        status_predicate(include_recent)
    ))
    .bind(machine_id)
    .bind(command_id)
    .fetch_optional(pool)
    .await?;
    Ok(index)
}

pub async fn approve_pending_command(
    pool: &PgPool,
    command_id: Uuid,
    actor: &str,
    block_self_for_ai: Option<Uuid>,
) -> ApiResult<()> {
    if let Some(caller) = block_self_for_ai {
        let owner: Option<Uuid> = sqlx::query_scalar(
            "SELECT ai_identity_id FROM command_queue WHERE id = $1",
        )
        .bind(command_id)
        .fetch_optional(pool)
        .await?;

        if owner == Some(caller) {
            return Err(ApiError::Forbidden);
        }
    }

    let updated = sqlx::query(
        "UPDATE command_queue SET status = 'queued'
         WHERE id = $1 AND status = 'pending_approval'",
    )
    .bind(command_id)
    .execute(pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::Conflict("cannot approve".into()));
    }

    append_audit(
        pool,
        actor,
        "command.approve",
        &command_id.to_string(),
        "",
        &serde_json::json!({ "command_id": command_id }),
    )
    .await?;

    Ok(())
}

pub async fn cancel_queued_command(
    pool: &PgPool,
    command_id: Uuid,
    actor: &str,
    include_pending_approval: bool,
) -> ApiResult<()> {
    // Admin/operator cancel may force-clear in-flight work (dispatched/running) when an
    // agent dies or stalls after claim. Identity cancel remains limited to queued only.
    let updated = if include_pending_approval {
        sqlx::query(
            "UPDATE command_queue
             SET status = 'cancelled',
                 cancel_requested_at = now(),
                 finished_at = COALESCE(finished_at, now()),
                 reboot_phase = NULL
             WHERE id = $1
               AND status IN ('pending_approval', 'queued', 'dispatched', 'running')",
        )
        .bind(command_id)
        .execute(pool)
        .await?
    } else {
        sqlx::query(
            "UPDATE command_queue
             SET status = 'cancelled',
                 cancel_requested_at = now(),
                 finished_at = COALESCE(finished_at, now()),
                 reboot_phase = NULL
             WHERE id = $1 AND status = 'queued'",
        )
        .bind(command_id)
        .execute(pool)
        .await?
    };

    if updated.rows_affected() == 0 {
        return Err(ApiError::Conflict("cannot cancel".into()));
    }

    append_audit(
        pool,
        actor,
        "command.cancel",
        &command_id.to_string(),
        "",
        &serde_json::json!({ "command_id": command_id }),
    )
    .await?;

    Ok(())
}

/// Extra grace after `timeout_secs` so the agent can still post a late timeout result.
const STALE_DISPATCH_GRACE_SECS: i32 = 60;

/// Mark dispatched/running commands past their timeout (+ grace) as expired.
///
/// Without this, a crash or network loss after claim leaves the row forever in
/// `dispatched`, blocking the machine and cluttering the action queue.
pub async fn expire_stale_dispatched_commands(pool: &PgPool) -> ApiResult<u64> {
    let result = sqlx::query(
        "UPDATE command_queue
         SET status = 'expired',
             finished_at = COALESCE(finished_at, now()),
             reboot_phase = NULL
         WHERE status IN ('dispatched', 'running')
           AND dispatched_at IS NOT NULL
           AND dispatched_at
               + ((timeout_secs + $1) * interval '1 second')
               < now()",
    )
    .bind(STALE_DISPATCH_GRACE_SECS)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub fn spawn_stale_command_reaper(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            ticker.tick().await;
            match expire_stale_dispatched_commands(&pool).await {
                Ok(0) => {}
                Ok(count) => {
                    tracing::info!(count, "expired stale dispatched commands");
                }
                Err(error) => {
                    tracing::warn!(error = %error, "stale command reaper failed");
                }
            }
        }
    });
}
