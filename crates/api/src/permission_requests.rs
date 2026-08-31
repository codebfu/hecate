//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use chrono::{DateTime, Utc};
use hecate_protocol::authz::{PermissionRequestChanges, PermissionRequestClass};
use hecate_protocol::permission_request::{
    PermissionRequestDetail, PermissionRequestStatus, PermissionRequestSummary,
};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::append_audit;
use crate::authz;
use crate::error::{ApiError, ApiResult};
use crate::pagination::{self, PaginatedResponse};
use crate::permission_request_workflow::{
    ai_may_approve_standard_tier1, apply_approved_changes, build_preview,
    validate_and_classify, validate_reason, validate_remove_assignments,
};

#[derive(Debug, Deserialize)]
pub struct PermissionRequestListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub status: Option<String>,
    pub request_id: Option<Uuid>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct PermissionRequestRow {
    id: Uuid,
    ai_identity_id: Uuid,
    ai_identity_name: String,
    requested_changes: serde_json::Value,
    reason: String,
    request_class: String,
    review_reason: Option<String>,
    status: String,
    reviewed_by: Option<String>,
    reviewed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

pub async fn create_request(
    pool: &PgPool,
    identity_id: Uuid,
    requested_changes: PermissionRequestChanges,
    reason: String,
) -> ApiResult<Uuid> {
    validate_reason(&reason)?;
    validate_remove_assignments(pool, identity_id, &requested_changes).await?;
    let request_class = validate_and_classify(pool, &requested_changes).await?;

    let active: bool = sqlx::query_scalar(
        "SELECT active FROM ai_identities WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(identity_id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    if !active {
        return Err(ApiError::Forbidden);
    }

    let pending_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM ai_permission_requests
            WHERE ai_identity_id = $1 AND status = 'pending' AND request_class = $2::permission_request_class
         )",
    )
    .bind(identity_id)
    .bind(request_class.as_str())
    .fetch_one(pool)
    .await?;

    if pending_exists {
        return Err(ApiError::Conflict("pending permission request already exists".into()));
    }

    let request_id = Uuid::new_v4();
    let changes_json = serde_json::to_value(&requested_changes)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    sqlx::query(
        "INSERT INTO ai_permission_requests (
            id, ai_identity_id, requested_changes, reason, request_class, status
         ) VALUES ($1, $2, $3, $4, $5::permission_request_class, 'pending')",
    )
    .bind(request_id)
    .bind(identity_id)
    .bind(changes_json)
    .bind(reason.trim())
    .bind(request_class.as_str())
    .execute(pool)
    .await?;

    append_audit(
        pool,
        &identity_id.to_string(),
        "ai_permissions.request",
        &request_id.to_string(),
        "",
        &serde_json::json!({
            "request_id": request_id,
            "ai_identity_id": identity_id,
        }),
    )
    .await?;

    Ok(request_id)
}

pub async fn list_requests(
    pool: &PgPool,
    query: &PermissionRequestListQuery,
) -> ApiResult<PaginatedResponse<PermissionRequestDetail>> {
    let (limit, mut offset) = pagination::resolve_list_pagination(query.limit, query.offset);
    let status_filter = query.status.as_deref().unwrap_or("pending");

    if PermissionRequestStatus::parse(status_filter).is_none() {
        return Err(ApiError::BadRequest("invalid status".into()));
    }

    if let Some(request_id) = query.request_id {
        if let Some(index) = request_index(pool, request_id, status_filter).await? {
            offset = pagination::page_offset_for_index(index, limit);
        }
    }

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint
         FROM ai_permission_requests pr
         JOIN ai_identities ai ON ai.id = pr.ai_identity_id
         WHERE ai.deleted_at IS NULL
           AND pr.status = $1::permission_request_status",
    )
    .bind(status_filter)
    .fetch_one(pool)
    .await?;

    let rows: Vec<PermissionRequestRow> = sqlx::query_as(
        "SELECT pr.id,
                pr.ai_identity_id,
                ai.name AS ai_identity_name,
                pr.requested_changes,
                pr.reason,
                pr.request_class::text AS request_class,
                pr.review_reason,
                pr.status::text AS status,
                pr.reviewed_by,
                pr.reviewed_at,
                pr.created_at
         FROM ai_permission_requests pr
         JOIN ai_identities ai ON ai.id = pr.ai_identity_id
         WHERE ai.deleted_at IS NULL
           AND pr.status = $1::permission_request_status
         ORDER BY pr.created_at, pr.id
         LIMIT $2 OFFSET $3",
    )
    .bind(status_filter)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(row_to_detail(pool, row).await?);
    }

    Ok(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    })
}

async fn request_index(pool: &PgPool, request_id: Uuid, status: &str) -> ApiResult<Option<i64>> {
    let index: Option<i64> = sqlx::query_scalar(
        "SELECT position
         FROM (
             SELECT pr.id,
                    ROW_NUMBER() OVER (ORDER BY pr.created_at, pr.id) - 1 AS position
             FROM ai_permission_requests pr
             JOIN ai_identities ai ON ai.id = pr.ai_identity_id
             WHERE ai.deleted_at IS NULL
               AND pr.status = $1::permission_request_status
         ) ranked
         WHERE id = $2",
    )
    .bind(status)
    .bind(request_id)
    .fetch_optional(pool)
    .await?;
    Ok(index)
}

async fn row_to_detail(pool: &PgPool, row: PermissionRequestRow) -> ApiResult<PermissionRequestDetail> {
    let status = PermissionRequestStatus::parse(&row.status)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("invalid permission request status")))?;
    let request_class = PermissionRequestClass::parse(&row.request_class)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("invalid permission request class")))?;
    let requested_changes: PermissionRequestChanges =
        serde_json::from_value(row.requested_changes)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    let current_assignments =
        authz::store::load_grant_assignments(pool, row.ai_identity_id).await?;
    let preview = build_preview(pool, row.ai_identity_id, &requested_changes).await?;

    Ok(PermissionRequestDetail {
        summary: PermissionRequestSummary {
            id: row.id,
            ai_identity_id: row.ai_identity_id,
            ai_identity_name: row.ai_identity_name,
            status,
            reason: row.reason,
            request_class,
            created_at: row.created_at,
            reviewed_at: row.reviewed_at,
            reviewed_by: row.reviewed_by,
        },
        current_assignments,
        requested_changes,
        request_preview: preview,
        review_reason: row.review_reason,
    })
}

async fn load_pending_request(pool: &PgPool, request_id: Uuid) -> ApiResult<PermissionRequestRow> {
    sqlx::query_as(
        "SELECT pr.id,
                pr.ai_identity_id,
                ai.name AS ai_identity_name,
                pr.requested_changes,
                pr.reason,
                pr.request_class::text AS request_class,
                pr.review_reason,
                pr.status::text AS status,
                pr.reviewed_by,
                pr.reviewed_at,
                pr.created_at
         FROM ai_permission_requests pr
         JOIN ai_identities ai ON ai.id = pr.ai_identity_id
         WHERE pr.id = $1
           AND ai.deleted_at IS NULL",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)
}

pub async fn approve_request(
    pool: &PgPool,
    request_id: Uuid,
    reviewer: &str,
    block_self_for_ai: Option<Uuid>,
) -> ApiResult<()> {
    let row = load_pending_request(pool, request_id).await?;

    if row.status != "pending" {
        return Err(ApiError::Conflict("cannot approve".into()));
    }

    if block_self_for_ai == Some(row.ai_identity_id) {
        return Err(ApiError::Forbidden);
    }

    let request_class = PermissionRequestClass::parse(&row.request_class)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("invalid request class")))?;
    let requested_changes: PermissionRequestChanges =
        serde_json::from_value(row.requested_changes.clone())
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

    if let Some(ai_id) = block_self_for_ai {
        if request_class == PermissionRequestClass::Admin {
            return Err(ApiError::Forbidden);
        }
        if !ai_may_approve_standard_tier1(&requested_changes) {
            return Err(ApiError::Forbidden);
        }
        let _ = ai_id;
    }

    apply_approved_changes(pool, row.ai_identity_id, &requested_changes).await?;

    let updated = sqlx::query(
        "UPDATE ai_permission_requests
         SET status = 'approved', reviewed_by = $2, reviewed_at = now()
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(request_id)
    .bind(reviewer)
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::Conflict("cannot approve".into()));
    }

    append_audit(
        pool,
        reviewer,
        "ai_permissions.request.approve",
        &request_id.to_string(),
        "",
        &serde_json::json!({
            "request_id": request_id,
            "ai_identity_id": row.ai_identity_id,
        }),
    )
    .await?;

    Ok(())
}

pub async fn reject_request(
    pool: &PgPool,
    request_id: Uuid,
    reviewer: &str,
    review_reason: Option<String>,
    block_self_for_ai: Option<Uuid>,
) -> ApiResult<()> {
    let row = load_pending_request(pool, request_id).await?;

    if row.status != "pending" {
        return Err(ApiError::Conflict("cannot reject".into()));
    }

    if block_self_for_ai == Some(row.ai_identity_id) {
        return Err(ApiError::Forbidden);
    }

    let updated = sqlx::query(
        "UPDATE ai_permission_requests
         SET status = 'rejected',
             reviewed_by = $2,
             reviewed_at = now(),
             review_reason = $3
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(request_id)
    .bind(reviewer)
    .bind(review_reason.as_deref())
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(ApiError::Conflict("cannot reject".into()));
    }

    append_audit(
        pool,
        reviewer,
        "ai_permissions.request.reject",
        &request_id.to_string(),
        "",
        &serde_json::json!({
            "request_id": request_id,
            "ai_identity_id": row.ai_identity_id,
            "review_reason": review_reason,
        }),
    )
    .await?;

    Ok(())
}

pub async fn read_permissions(
    pool: &PgPool,
    caller_id: Uuid,
    identity_id: Option<Uuid>,
) -> ApiResult<serde_json::Value> {
    let target_id = identity_id.unwrap_or(caller_id);

    let identity: Option<(Uuid, String, bool)> = sqlx::query_as(
        "SELECT id, name, active FROM ai_identities
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(target_id)
    .fetch_optional(pool)
    .await?;

    let Some(identity) = identity else {
        return Err(ApiError::NotFound);
    };

    let effective = authz::compute_effective_rights(pool, target_id).await?;

    Ok(serde_json::json!({
        "identity": {
            "id": identity.0,
            "name": identity.1,
            "active": identity.2,
        },
        "effective_rights": effective,
    }))
}
