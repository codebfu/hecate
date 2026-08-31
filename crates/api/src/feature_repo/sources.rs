//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};

use super::fetch::parse_public_https_url;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RepoSource {
    pub id: String,
    pub url: String,
    pub public_key_b64: String,
    pub enabled: bool,
    pub priority: i32,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_index_generated_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn list(pool: &PgPool) -> ApiResult<Vec<RepoSource>> {
    Ok(sqlx::query_as(
        "SELECT id, url, public_key_b64, enabled, priority, last_sync_at,
                last_index_generated_at, last_error, created_at
         FROM repo_sources
         ORDER BY priority DESC, id",
    )
    .fetch_all(pool)
    .await?)
}

pub async fn get(pool: &PgPool, id: &str) -> ApiResult<RepoSource> {
    sqlx::query_as(
        "SELECT id, url, public_key_b64, enabled, priority, last_sync_at,
                last_index_generated_at, last_error, created_at
         FROM repo_sources
         WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)
}

pub async fn add(
    pool: &PgPool,
    id: &str,
    url: &str,
    public_key_b64: &str,
    priority: i32,
) -> ApiResult<RepoSource> {
    validate_source_id(id)?;
    parse_public_https_url(url)?;
    validate_public_key_b64(public_key_b64)?;

    sqlx::query(
        "INSERT INTO repo_sources (id, url, public_key_b64, enabled, priority)
         VALUES ($1, $2, $3, true, $4)",
    )
    .bind(id)
    .bind(url.trim_end_matches('/'))
    .bind(public_key_b64.trim())
    .bind(priority)
    .execute(pool)
    .await
    .map_err(|error| {
        if matches!(&error, sqlx::Error::Database(db) if db.is_unique_violation()) {
            ApiError::Conflict(format!("repository source {id} already exists"))
        } else {
            error.into()
        }
    })?;
    get(pool, id).await
}

pub const OFFICIAL_SOURCE_ID: &str = "official";

pub async fn update(
    pool: &PgPool,
    id: &str,
    url: Option<&str>,
    public_key_b64: Option<&str>,
    priority: Option<i32>,
) -> ApiResult<RepoSource> {
    if url.is_none() && public_key_b64.is_none() && priority.is_none() {
        return Err(ApiError::BadRequest(
            "provide at least one of url, public_key_b64, or priority".into(),
        ));
    }

    let current = get(pool, id).await?;
    if id == OFFICIAL_SOURCE_ID {
        if let Some(value) = url {
            let normalized = value.trim_end_matches('/');
            if normalized != current.url {
                return Err(ApiError::BadRequest(
                    "official repository source URL is read-only".into(),
                ));
            }
        }
    }
    let next_url = match url {
        Some(value) => {
            parse_public_https_url(value)?;
            value.trim_end_matches('/').to_string()
        }
        None => current.url,
    };
    let next_key = match public_key_b64 {
        Some(value) => {
            validate_public_key_b64(value)?;
            value.trim().to_string()
        }
        None => current.public_key_b64,
    };
    let next_priority = priority.unwrap_or(current.priority);

    let result = sqlx::query(
        "UPDATE repo_sources
         SET url = $2,
             public_key_b64 = $3,
             priority = $4,
             last_error = NULL
         WHERE id = $1",
    )
    .bind(id)
    .bind(&next_url)
    .bind(&next_key)
    .bind(next_priority)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    get(pool, id).await
}

pub async fn set_enabled(pool: &PgPool, id: &str, enabled: bool) -> ApiResult<RepoSource> {
    let result = sqlx::query(
        "UPDATE repo_sources
         SET enabled = $2
         WHERE id = $1",
    )
    .bind(id)
    .bind(enabled)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    get(pool, id).await
}

pub async fn remove(pool: &PgPool, id: &str) -> ApiResult<()> {
    if id == OFFICIAL_SOURCE_ID {
        return Err(ApiError::BadRequest(
            "official repository source cannot be removed".into(),
        ));
    }
    let result = sqlx::query("DELETE FROM repo_sources WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|error| {
            if matches!(&error, sqlx::Error::Database(db) if db.constraint() == Some("installed_features_source_id_fkey")) {
                ApiError::Conflict(format!("repository source {id} has installed features"))
            } else {
                error.into()
            }
        })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

pub async fn mark_sync(
    pool: &PgPool,
    id: &str,
    error: Option<&str>,
    index_generated_at: Option<DateTime<Utc>>,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE repo_sources
         SET last_sync_at = now(),
             last_error = $2,
             last_index_generated_at = COALESCE($3, last_index_generated_at)
         WHERE id = $1",
    )
    .bind(id)
    .bind(error)
    .bind(index_generated_at)
    .execute(pool)
    .await?;
    Ok(())
}

fn validate_source_id(id: &str) -> ApiResult<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApiError::BadRequest(
            "source id must contain only letters, digits, '.', '_' or '-'".into(),
        ));
    }
    Ok(())
}

fn validate_public_key_b64(public_key_b64: &str) -> ApiResult<()> {
    let public_key = BASE64
        .decode(public_key_b64.trim())
        .map_err(|_| ApiError::BadRequest("repository public key is not valid base64".into()))?;
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| ApiError::BadRequest("repository public key must be 32 bytes".into()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| ApiError::BadRequest("repository public key is invalid".into()))?;
    Ok(())
}
