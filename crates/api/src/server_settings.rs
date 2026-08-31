//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};
use crate::state::AppConfig;

const ENROLLMENT_AUTO_APPROVE: &str = "enrollment_auto_approve";
const PROXY_ENROLLMENT_AUTO_APPROVE: &str = "proxy_enrollment_auto_approve";
const ENROLLMENT_TOKEN_TTL_MINUTES: &str = "enrollment_token_ttl_minutes";
const PROXY_ENROLLMENT_TOKEN_TTL_MINUTES: &str = "proxy_enrollment_token_ttl_minutes";
const SERVER_UPDATE_REQUESTED_AT: &str = "server_update_requested_at";
const RELEASE_SIGNING_PUBLIC_KEY_B64: &str = "release_signing_public_key_b64";
const RELEASE_SIGNING_PUBLIC_KEY_PREVIOUS_B64: &str = "release_signing_public_key_previous_b64";
const RELEASE_SIGNING_KEY_OVERLAP_UNTIL: &str = "release_signing_key_overlap_until";
const RELEASE_SIGNING_KEY_CONTINUITY_SIG_B64: &str = "release_signing_key_continuity_sig_b64";
const KEY_ROTATION_OVERLAP_SECS: &str = "key_rotation_overlap_secs";
const KEY_ROTATION_INTERVAL_SECS: &str = "key_rotation_interval_secs";
const TASK_SIGNING_LAST_ROTATED_AT: &str = "task_signing_last_rotated_at";
const CREDENTIAL_ROTATION_LAST_REQUESTED_AT: &str = "credential_rotation_last_requested_at";
const AUTHZ_TAGS_INCLUDE_AUTO: &str = "authz_tags_include_auto";
const AUTHZ_TAGS_INCLUDE_OPERATOR: &str = "authz_tags_include_operator";
const AUTHZ_TAGS_INCLUDE_AGENT_CUSTOM: &str = "authz_tags_include_agent_custom";
const CONTENT_POLICY_LOCKOUT_SECONDS: &str = "content_policy_lockout_seconds";

const DEFAULT_KEY_ROTATION_OVERLAP_SECS: u64 = 604_800;
const DEFAULT_CONTENT_POLICY_LOCKOUT_SECONDS: u64 = 3600;
/// Default enrollment token TTL: 1 hour. Clamp matches the former 1..=720 hour window.
pub const DEFAULT_ENROLLMENT_TOKEN_TTL_MINUTES: u64 = 60;
pub const MIN_ENROLLMENT_TOKEN_TTL_MINUTES: u64 = 60;
pub const MAX_ENROLLMENT_TOKEN_TTL_MINUTES: u64 = 720 * 60;

#[derive(Clone, Debug)]
pub struct ReleaseKeys {
    pub current: String,
    pub previous: Option<String>,
    pub overlap_until: Option<chrono::DateTime<chrono::Utc>>,
    pub continuity_sig_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminSettingsView {
    pub release_signing_public_key_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_signing_public_key_previous_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_signing_key_overlap_until: Option<String>,
    pub enrollment_auto_approve: bool,
    pub proxy_enrollment_auto_approve: bool,
    pub enrollment_token_ttl_minutes: u64,
    pub proxy_enrollment_token_ttl_minutes: u64,
    pub authz_tags_include_auto: bool,
    pub authz_tags_include_operator: bool,
    pub authz_tags_include_agent_custom: bool,
    pub content_policy_lockout_seconds: u64,
    pub key_rotation_overlap_secs: u64,
    pub key_rotation_interval_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_key_continuity_sig_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_signing_last_rotated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_rotation_last_requested_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAdminSettingsBody {
    pub release_signing_public_key_b64: Option<String>,
    /// Required when rotating the release public key: Ed25519 sig by the *previous*
    /// release private key over `continuity_v1\\n{old}\\n{new}` (produced offline).
    pub release_key_continuity_sig_b64: Option<String>,
    pub enrollment_auto_approve: Option<bool>,
    pub proxy_enrollment_auto_approve: Option<bool>,
    pub enrollment_token_ttl_minutes: Option<u64>,
    pub proxy_enrollment_token_ttl_minutes: Option<u64>,
    pub authz_tags_include_auto: Option<bool>,
    pub authz_tags_include_operator: Option<bool>,
    pub authz_tags_include_agent_custom: Option<bool>,
    pub content_policy_lockout_seconds: Option<u64>,
    pub key_rotation_overlap_secs: Option<u64>,
    pub key_rotation_interval_secs: Option<u64>,
}

/// Resolves the release signing public key from DB `server_settings` (preferred) or env fallback.
pub async fn resolve_release_signing_public_key_b64(
    pool: &PgPool,
    env: &AppConfig,
) -> ApiResult<String> {
    Ok(resolve_release_keys(pool, env).await?.current)
}

pub async fn resolve_release_keys(pool: &PgPool, env: &AppConfig) -> ApiResult<ReleaseKeys> {
    let current = resolve_string_setting(
        pool,
        RELEASE_SIGNING_PUBLIC_KEY_B64,
        &env.release_signing_public_key_b64,
    )
    .await?;
    let previous_raw = get_string_setting(pool, RELEASE_SIGNING_PUBLIC_KEY_PREVIOUS_B64).await?;
    let overlap_until = get_timestamp_setting(pool, RELEASE_SIGNING_KEY_OVERLAP_UNTIL).await?;
    let now = chrono::Utc::now();
    let previous = match (previous_raw, overlap_until) {
        (Some(prev), Some(until)) if until > now && !prev.trim().is_empty() => {
            Some(prev.trim().to_string())
        }
        (Some(prev), None) if !prev.trim().is_empty() => Some(prev.trim().to_string()),
        _ => None,
    };
    let overlap_until = if previous.is_some() {
        overlap_until
    } else {
        None
    };
    Ok(ReleaseKeys {
        current,
        previous,
        overlap_until,
        continuity_sig_b64: get_string_setting(pool, RELEASE_SIGNING_KEY_CONTINUITY_SIG_B64)
            .await?
            .filter(|value| !value.trim().is_empty()),
    })
}

/// Returns `Some` when the resolved key is non-empty after trim.
pub fn optional_release_public_key(resolved: &str) -> Option<String> {
    let trimmed = resolved.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub async fn get_admin_settings(pool: &PgPool, env: &AppConfig) -> ApiResult<AdminSettingsView> {
    let keys = resolve_release_keys(pool, env).await?;
    Ok(AdminSettingsView {
        release_signing_public_key_b64: keys.current,
        release_signing_public_key_previous_b64: keys.previous.clone(),
        release_signing_key_overlap_until: keys.overlap_until.map(|ts| ts.to_rfc3339()),
        enrollment_auto_approve: enrollment_auto_approve(pool).await?,
        proxy_enrollment_auto_approve: proxy_enrollment_auto_approve(pool).await?,
        enrollment_token_ttl_minutes: enrollment_token_ttl_minutes(pool).await?,
        proxy_enrollment_token_ttl_minutes: proxy_enrollment_token_ttl_minutes(pool).await?,
        authz_tags_include_auto: authz_tags_include_auto(pool).await?,
        authz_tags_include_operator: authz_tags_include_operator(pool).await?,
        authz_tags_include_agent_custom: authz_tags_include_agent_custom(pool).await?,
        content_policy_lockout_seconds: content_policy_lockout_seconds(pool).await?,
        key_rotation_overlap_secs: key_rotation_overlap_secs(pool)
            .await?
            .unwrap_or(DEFAULT_KEY_ROTATION_OVERLAP_SECS),
        key_rotation_interval_secs: key_rotation_interval_secs(pool)
            .await?
            .unwrap_or(DEFAULT_KEY_ROTATION_OVERLAP_SECS),
        release_key_continuity_sig_b64: keys.continuity_sig_b64.clone(),
        task_signing_last_rotated_at: task_signing_last_rotated_at(pool)
            .await?
            .map(|ts| ts.to_rfc3339()),
        credential_rotation_last_requested_at: credential_rotation_last_requested_at(pool)
            .await?
            .map(|ts| ts.to_rfc3339()),
    })
}

pub async fn update_admin_settings(
    pool: &PgPool,
    env: &AppConfig,
    body: &UpdateAdminSettingsBody,
) -> ApiResult<AdminSettingsView> {
    if let Some(public_key) = &body.release_signing_public_key_b64 {
        rotate_or_set_release_public_key(
            pool,
            env,
            public_key.trim(),
            body.release_key_continuity_sig_b64.as_deref(),
        )
        .await?;
    }

    if let Some(auto_approve) = body.enrollment_auto_approve {
        set_enrollment_auto_approve(pool, auto_approve).await?;
    }

    if let Some(auto_approve) = body.proxy_enrollment_auto_approve {
        set_proxy_enrollment_auto_approve(pool, auto_approve).await?;
    }

    if let Some(minutes) = body.enrollment_token_ttl_minutes {
        set_enrollment_token_ttl_minutes(pool, minutes).await?;
    }

    if let Some(minutes) = body.proxy_enrollment_token_ttl_minutes {
        set_proxy_enrollment_token_ttl_minutes(pool, minutes).await?;
    }

    if let Some(value) = body.authz_tags_include_auto {
        set_bool_setting(pool, AUTHZ_TAGS_INCLUDE_AUTO, value).await?;
    }
    if let Some(value) = body.authz_tags_include_operator {
        set_bool_setting(pool, AUTHZ_TAGS_INCLUDE_OPERATOR, value).await?;
    }
    if let Some(value) = body.authz_tags_include_agent_custom {
        set_bool_setting(pool, AUTHZ_TAGS_INCLUDE_AGENT_CUSTOM, value).await?;
    }
    if let Some(seconds) = body.content_policy_lockout_seconds {
        if seconds < 60 {
            return Err(ApiError::BadRequest(
                "content_policy_lockout_seconds must be at least 60".into(),
            ));
        }
        set_u64_setting(pool, CONTENT_POLICY_LOCKOUT_SECONDS, seconds).await?;
    }

    if let Some(overlap) = body.key_rotation_overlap_secs {
        if overlap < 60 {
            return Err(ApiError::BadRequest(
                "key_rotation_overlap_secs must be at least 60".into(),
            ));
        }
        set_u64_setting(pool, KEY_ROTATION_OVERLAP_SECS, overlap).await?;
    }

    if let Some(interval) = body.key_rotation_interval_secs {
        if interval != 0 && interval < 60 {
            return Err(ApiError::BadRequest(
                "key_rotation_interval_secs must be 0 (disabled) or at least 60".into(),
            ));
        }
        let overlap = body
            .key_rotation_overlap_secs
            .or(key_rotation_overlap_secs(pool).await?)
            .unwrap_or(DEFAULT_KEY_ROTATION_OVERLAP_SECS);
        if interval != 0 && interval < overlap {
            return Err(ApiError::BadRequest(
                "key_rotation_interval_secs must be greater than or equal to key_rotation_overlap_secs".into(),
            ));
        }
        set_u64_setting(pool, KEY_ROTATION_INTERVAL_SECS, interval).await?;
    }

    get_admin_settings(pool, env).await
}

/// When the admin sets a new release pubkey that differs from current, keep the old as previous.
/// Rotation of an already-published key requires a continuity signature from the previous
/// private key (produced offline) so agents can ratchet without TOFU.
pub async fn rotate_or_set_release_public_key(
    pool: &PgPool,
    env: &AppConfig,
    new_key: &str,
    continuity_sig_b64: Option<&str>,
) -> ApiResult<bool> {
    let current = resolve_release_signing_public_key_b64(pool, env).await?;
    let new_key = new_key.trim();
    if new_key == current.trim() {
        set_string_setting(pool, RELEASE_SIGNING_PUBLIC_KEY_B64, new_key).await?;
        return Ok(false);
    }

    if !current.trim().is_empty() {
        let sig = continuity_sig_b64
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "release_key_continuity_sig_b64 is required when rotating the release public key"
                        .into(),
                )
            })?;
        crate::task_crypto::verify_continuity_pubkey(current.trim(), new_key, sig)?;
        let overlap = key_rotation_overlap_secs(pool)
            .await?
            .unwrap_or(DEFAULT_KEY_ROTATION_OVERLAP_SECS)
            .max(60);
        let until = chrono::Utc::now() + chrono::Duration::seconds(overlap as i64);
        set_string_setting(pool, RELEASE_SIGNING_PUBLIC_KEY_PREVIOUS_B64, current.trim()).await?;
        set_timestamp_setting(pool, RELEASE_SIGNING_KEY_OVERLAP_UNTIL, Some(until)).await?;
        set_string_setting(pool, RELEASE_SIGNING_KEY_CONTINUITY_SIG_B64, sig).await?;
    } else {
        set_string_setting(pool, RELEASE_SIGNING_PUBLIC_KEY_PREVIOUS_B64, "").await?;
        set_timestamp_setting(pool, RELEASE_SIGNING_KEY_OVERLAP_UNTIL, None).await?;
        set_string_setting(pool, RELEASE_SIGNING_KEY_CONTINUITY_SIG_B64, "").await?;
    }

    set_string_setting(pool, RELEASE_SIGNING_PUBLIC_KEY_B64, new_key).await?;
    Ok(true)
}

pub async fn purge_expired_release_previous(pool: &PgPool) -> ApiResult<bool> {
    let until = get_timestamp_setting(pool, RELEASE_SIGNING_KEY_OVERLAP_UNTIL).await?;
    let Some(until) = until else {
        return Ok(false);
    };
    if until > chrono::Utc::now() {
        return Ok(false);
    }
    set_string_setting(pool, RELEASE_SIGNING_PUBLIC_KEY_PREVIOUS_B64, "").await?;
    set_timestamp_setting(pool, RELEASE_SIGNING_KEY_OVERLAP_UNTIL, None).await?;
    Ok(true)
}

pub async fn key_rotation_overlap_secs(pool: &PgPool) -> ApiResult<Option<u64>> {
    get_u64_setting(pool, KEY_ROTATION_OVERLAP_SECS).await
}

pub async fn key_rotation_interval_secs(pool: &PgPool) -> ApiResult<Option<u64>> {
    get_u64_setting(pool, KEY_ROTATION_INTERVAL_SECS).await
}

pub async fn task_signing_last_rotated_at(
    pool: &PgPool,
) -> ApiResult<Option<chrono::DateTime<chrono::Utc>>> {
    get_timestamp_setting(pool, TASK_SIGNING_LAST_ROTATED_AT).await
}

pub async fn set_task_signing_last_rotated_at(
    pool: &PgPool,
    ts: Option<chrono::DateTime<chrono::Utc>>,
) -> ApiResult<()> {
    set_timestamp_setting(pool, TASK_SIGNING_LAST_ROTATED_AT, ts).await
}

pub async fn credential_rotation_last_requested_at(
    pool: &PgPool,
) -> ApiResult<Option<chrono::DateTime<chrono::Utc>>> {
    get_timestamp_setting(pool, CREDENTIAL_ROTATION_LAST_REQUESTED_AT).await
}

pub async fn set_credential_rotation_last_requested_at(
    pool: &PgPool,
    ts: Option<chrono::DateTime<chrono::Utc>>,
) -> ApiResult<()> {
    set_timestamp_setting(pool, CREDENTIAL_ROTATION_LAST_REQUESTED_AT, ts).await
}

pub async fn enrollment_auto_approve(pool: &PgPool) -> ApiResult<bool> {
    get_bool_setting(pool, ENROLLMENT_AUTO_APPROVE, false).await
}

pub async fn set_enrollment_auto_approve(pool: &PgPool, enabled: bool) -> ApiResult<()> {
    set_bool_setting(pool, ENROLLMENT_AUTO_APPROVE, enabled).await
}

pub async fn proxy_enrollment_auto_approve(pool: &PgPool) -> ApiResult<bool> {
    get_bool_setting(pool, PROXY_ENROLLMENT_AUTO_APPROVE, false).await
}

pub async fn set_proxy_enrollment_auto_approve(pool: &PgPool, enabled: bool) -> ApiResult<()> {
    set_bool_setting(pool, PROXY_ENROLLMENT_AUTO_APPROVE, enabled).await
}

fn clamp_enrollment_token_ttl_minutes(minutes: u64) -> ApiResult<u64> {
    if !(MIN_ENROLLMENT_TOKEN_TTL_MINUTES..=MAX_ENROLLMENT_TOKEN_TTL_MINUTES).contains(&minutes) {
        return Err(ApiError::BadRequest(format!(
            "enrollment token TTL must be between {MIN_ENROLLMENT_TOKEN_TTL_MINUTES} and {MAX_ENROLLMENT_TOKEN_TTL_MINUTES} minutes"
        )));
    }
    Ok(minutes)
}

pub async fn enrollment_token_ttl_minutes(pool: &PgPool) -> ApiResult<u64> {
    Ok(get_u64_setting(pool, ENROLLMENT_TOKEN_TTL_MINUTES)
        .await?
        .unwrap_or(DEFAULT_ENROLLMENT_TOKEN_TTL_MINUTES)
        .clamp(
            MIN_ENROLLMENT_TOKEN_TTL_MINUTES,
            MAX_ENROLLMENT_TOKEN_TTL_MINUTES,
        ))
}

pub async fn set_enrollment_token_ttl_minutes(pool: &PgPool, minutes: u64) -> ApiResult<()> {
    let minutes = clamp_enrollment_token_ttl_minutes(minutes)?;
    set_u64_setting(pool, ENROLLMENT_TOKEN_TTL_MINUTES, minutes).await
}

pub async fn proxy_enrollment_token_ttl_minutes(pool: &PgPool) -> ApiResult<u64> {
    Ok(get_u64_setting(pool, PROXY_ENROLLMENT_TOKEN_TTL_MINUTES)
        .await?
        .unwrap_or(DEFAULT_ENROLLMENT_TOKEN_TTL_MINUTES)
        .clamp(
            MIN_ENROLLMENT_TOKEN_TTL_MINUTES,
            MAX_ENROLLMENT_TOKEN_TTL_MINUTES,
        ))
}

pub async fn set_proxy_enrollment_token_ttl_minutes(pool: &PgPool, minutes: u64) -> ApiResult<()> {
    let minutes = clamp_enrollment_token_ttl_minutes(minutes)?;
    set_u64_setting(pool, PROXY_ENROLLMENT_TOKEN_TTL_MINUTES, minutes).await
}

pub async fn authz_tags_include_auto(pool: &PgPool) -> ApiResult<bool> {
    get_bool_setting(pool, AUTHZ_TAGS_INCLUDE_AUTO, true).await
}

pub async fn authz_tags_include_operator(pool: &PgPool) -> ApiResult<bool> {
    get_bool_setting(pool, AUTHZ_TAGS_INCLUDE_OPERATOR, true).await
}

pub async fn authz_tags_include_agent_custom(pool: &PgPool) -> ApiResult<bool> {
    get_bool_setting(pool, AUTHZ_TAGS_INCLUDE_AGENT_CUSTOM, false).await
}

pub async fn authz_tag_sources(pool: &PgPool) -> ApiResult<hecate_protocol::machine_tags::AuthzTagSources> {
    Ok(hecate_protocol::machine_tags::AuthzTagSources {
        auto: authz_tags_include_auto(pool).await?,
        operator: authz_tags_include_operator(pool).await?,
        agent_custom: authz_tags_include_agent_custom(pool).await?,
    })
}

pub async fn content_policy_lockout_seconds(pool: &PgPool) -> ApiResult<u64> {
    Ok(get_u64_setting(pool, CONTENT_POLICY_LOCKOUT_SECONDS)
        .await?
        .unwrap_or(DEFAULT_CONTENT_POLICY_LOCKOUT_SECONDS)
        .max(60))
}

async fn set_bool_setting(pool: &PgPool, key: &str, enabled: bool) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO server_settings (key, value, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(key)
    .bind(serde_json::json!(enabled))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn server_update_requested_at(
    pool: &PgPool,
) -> ApiResult<Option<chrono::DateTime<chrono::Utc>>> {
    get_timestamp_setting(pool, SERVER_UPDATE_REQUESTED_AT).await
}

pub async fn set_server_update_requested_at(
    pool: &PgPool,
    requested_at: Option<chrono::DateTime<chrono::Utc>>,
) -> ApiResult<()> {
    set_timestamp_setting(pool, SERVER_UPDATE_REQUESTED_AT, requested_at).await
}

async fn resolve_string_setting(
    pool: &PgPool,
    key: &str,
    env_default: &str,
) -> ApiResult<String> {
    match get_string_setting(pool, key).await? {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Ok(env_default.to_string()),
    }
}

async fn get_string_setting(pool: &PgPool, key: &str) -> ApiResult<Option<String>> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM server_settings WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(value.and_then(|value| value.as_str().map(str::to_string)))
}

async fn set_string_setting(pool: &PgPool, key: &str, value: &str) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO server_settings (key, value, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(key)
    .bind(serde_json::json!(value))
    .execute(pool)
    .await?;
    Ok(())
}

async fn get_u64_setting(pool: &PgPool, key: &str) -> ApiResult<Option<u64>> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM server_settings WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(value.and_then(parse_json_u64))
}

async fn set_u64_setting(pool: &PgPool, key: &str, value: u64) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO server_settings (key, value, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(key)
    .bind(serde_json::json!(value))
    .execute(pool)
    .await?;
    Ok(())
}

async fn get_timestamp_setting(
    pool: &PgPool,
    key: &str,
) -> ApiResult<Option<chrono::DateTime<chrono::Utc>>> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM server_settings WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(value.and_then(parse_json_timestamp))
}

async fn set_timestamp_setting(
    pool: &PgPool,
    key: &str,
    timestamp: Option<chrono::DateTime<chrono::Utc>>,
) -> ApiResult<()> {
    let value = match timestamp {
        Some(ts) => serde_json::json!(ts.to_rfc3339()),
        None => serde_json::Value::Null,
    };
    sqlx::query(
        "INSERT INTO server_settings (key, value, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

fn parse_json_timestamp(value: serde_json::Value) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Some(text) = value.as_str() {
        return chrono::DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|ts| ts.with_timezone(&chrono::Utc));
    }
    None
}

async fn get_bool_setting(pool: &PgPool, key: &str, default: bool) -> ApiResult<bool> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM server_settings WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(value.map(parse_json_bool).unwrap_or(default))
}

fn parse_json_bool(value: serde_json::Value) -> bool {
    if value.is_boolean() {
        return value.as_bool().unwrap_or(false);
    }
    if let Some(n) = value.as_i64() {
        return n != 0;
    }
    if let Some(s) = value.as_str() {
        return s.eq_ignore_ascii_case("true");
    }
    false
}

fn parse_json_u64(value: serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    if let Some(n) = value.as_i64() {
        return u64::try_from(n).ok();
    }
    value
        .as_str()
        .and_then(|text| text.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_bool_handles_common_shapes() {
        assert!(!parse_json_bool(serde_json::json!(false)));
        assert!(parse_json_bool(serde_json::json!(true)));
        assert!(!parse_json_bool(serde_json::json!(0)));
        assert!(parse_json_bool(serde_json::json!(1)));
        assert!(parse_json_bool(serde_json::json!("true")));
        assert!(!parse_json_bool(serde_json::json!("false")));
        assert!(!parse_json_bool(serde_json::json!({})));
    }

    #[test]
    fn optional_release_public_key_skips_blank() {
        assert_eq!(optional_release_public_key(""), None);
        assert_eq!(optional_release_public_key("   "), None);
        assert_eq!(
            optional_release_public_key("  abc=  "),
            Some("abc=".into())
        );
    }
}
