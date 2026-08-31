//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Startup helpers for the official feature repository and release signing keys.

use sqlx::PgPool;

use crate::error::ApiResult;
use crate::server_settings;
use crate::state::AppConfig;

use super::install;

pub const OFFICIAL_SOURCE_ID: &str = "official";
pub const OFFICIAL_REPO_URL: &str = "https://repo.hecate-mcp.com";
pub const OFFICIAL_PUBLIC_KEY_B64: &str = "kHWEtm3yvH9wV2PPb2FMB9XJ0oM68CvUXTUxzAWeGTo=";

pub async fn ensure_official_source(pool: &PgPool, config: &AppConfig) -> ApiResult<()> {
    let public_key = if config.release_signing_public_key_b64.trim().is_empty() {
        OFFICIAL_PUBLIC_KEY_B64
    } else {
        config.release_signing_public_key_b64.trim()
    };
    sqlx::query(
        "INSERT INTO repo_sources (id, url, public_key_b64, enabled, priority)
         VALUES ($1, $2, $3, true, 100)
         ON CONFLICT (id) DO UPDATE
         SET url = EXCLUDED.url,
             public_key_b64 = EXCLUDED.public_key_b64,
             priority = EXCLUDED.priority",
    )
    .bind(OFFICIAL_SOURCE_ID)
    .bind(config.hecate_repo_url.trim_end_matches('/'))
    .bind(public_key)
    .execute(pool)
    .await?;

    // Prefer the deployment env key so every install converges without manual DB edits.
    align_release_signing_key_from_env(pool, config).await?;
    Ok(())
}

async fn align_release_signing_key_from_env(pool: &PgPool, config: &AppConfig) -> ApiResult<()> {
    let env_key = config.release_signing_public_key_b64.trim();
    if env_key.is_empty() {
        return Ok(());
    }
    let current = server_settings::resolve_release_signing_public_key_b64(pool, config).await?;
    if current.trim() == env_key {
        return Ok(());
    }
    let rotated = server_settings::rotate_or_set_release_public_key(pool, config, env_key, None).await?;
    if rotated {
        tracing::info!("aligned release signing public key from environment");
    }
    Ok(())
}

/// Pull canonical fleet update signatures from installed feature manifests.
pub async fn sync_installed_update_signatures(pool: &PgPool) -> ApiResult<u64> {
    install::sync_installed_update_signatures(pool).await
}
