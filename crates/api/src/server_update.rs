//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Graceful server self-update via host service restart trigger.

use chrono::Utc;
use sqlx::PgPool;

use crate::error::{ApiError, ApiResult};
use crate::server_settings;
use crate::state::AppConfig;
use crate::updates::is_fleet_busy;

pub struct ServerUpdateStatus {
    pub hecate_version: String,
    pub hecate_app_tag: String,
    pub update_requested: bool,
    pub update_requested_at: Option<chrono::DateTime<Utc>>,
    pub fleet_busy: bool,
    pub can_apply: bool,
}

pub async fn get_server_update_status(
    pool: &PgPool,
    config: &AppConfig,
) -> ApiResult<ServerUpdateStatus> {
    let requested_at = server_settings::server_update_requested_at(pool).await?;
    let fleet_busy = is_fleet_busy(pool).await?;
    let update_requested = requested_at.is_some();
    let can_apply = update_requested && !fleet_busy;
    Ok(ServerUpdateStatus {
        hecate_version: hecate_protocol::HECATE_VERSION.to_string(),
        hecate_app_tag: config.hecate_app_tag.clone(),
        update_requested,
        update_requested_at: requested_at,
        fleet_busy,
        can_apply,
    })
}

pub async fn request_server_update(pool: &PgPool) -> ApiResult<()> {
    server_settings::set_server_update_requested_at(pool, Some(Utc::now())).await
}

pub async fn try_apply_server_update(pool: &PgPool, config: &AppConfig) -> ApiResult<bool> {
    let status = get_server_update_status(pool, config).await?;
    if !status.can_apply {
        return Ok(false);
    }

    if let Some(parent) = config.server_update_trigger_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| ApiError::Internal(error.into()))?;
    }

    let payload = format!("{}\n", Utc::now().to_rfc3339());
    tokio::fs::write(&config.server_update_trigger_path, payload.as_bytes())
        .await
        .map_err(|error| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to write server update trigger at {}: {error}",
                config.server_update_trigger_path.display()
            ))
        })?;

    server_settings::set_server_update_requested_at(pool, None).await?;
    tracing::info!(
        path = %config.server_update_trigger_path.display(),
        "server update trigger written"
    );
    Ok(true)
}

pub fn spawn_server_update_loop(pool: PgPool, config: std::sync::Arc<AppConfig>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            ticker.tick().await;
            if let Err(error) = try_apply_server_update(&pool, &config).await {
                tracing::warn!(error = %error, "server update loop failed");
            }
        }
    });
}
