//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

mod authz;
mod machines;
mod admin_auth;
mod admin_commands;
mod command_dispatch;
mod command_queue;
mod command_definitions;
mod command_artifacts;
mod helper_install;
mod content_policy;
mod desktop_sessions;
mod proxmox_sessions;
mod agent_auth;
mod audit;
mod backup;
mod backup_crypto;
mod task_crypto;
mod crypto;
mod enrollment;
mod error;
mod feature_repo;
mod internal_auth;
mod key_rotation;
mod pagination;
mod permissions;
mod permission_request_workflow;
mod permission_requests;
mod proxy_auth;
mod reboot_watch;
mod routes;
mod server_settings;
mod server_update;
mod session;
mod state;
mod webauthn_store;
mod updates;

use std::net::SocketAddr;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = state::AppConfig::from_env()?;
    config.validate_production_secrets()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    tracing::info!("Running database migrations...");
    sqlx::migrate!("../../migrations").run(&pool).await?;
    feature_repo::bootstrap::ensure_official_source(&pool, &config).await?;
    if let Err(error) = feature_repo::bootstrap::sync_installed_update_signatures(&pool).await {
        tracing::warn!(error = %error, "failed to sync fleet update signatures from feature manifests");
    }

    let webauthn = state::build_webauthn(&config).await?;
    let config = std::sync::Arc::new(config);
    let app_state = state::AppState {
        pool: pool.clone(),
        config: config.clone(),
        webauthn: std::sync::Arc::new(webauthn),
        webauthn_challenges: webauthn_store::RegistrationChallengeStore::new(),
        webauthn_auth_challenges: webauthn_store::AuthenticationChallengeStore::new(),
    };

    tokio::spawn(machines::run_offline_sweeper(pool.clone()));
    server_update::spawn_server_update_loop(pool.clone(), app_state.config.clone());
    command_artifacts::spawn_artifact_cleanup_loop(pool.clone());
    command_queue::spawn_stale_command_reaper(pool.clone());
    reboot_watch::spawn_reboot_watcher(pool.clone());
    key_rotation::spawn_key_rotation_loop(pool.clone());

    let app = routes::router(app_state);
    let addr: SocketAddr = config.bind_addr.parse()?;
    tracing::info!("Hecate API listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
