//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;
use std::sync::Arc;

use sqlx::PgPool;
use webauthn_rs::prelude::*;

use crate::webauthn_store::{AuthenticationChallengeStore, RegistrationChallengeStore};

pub const DEV_SESSION_SECRET: &str = "dev-session-secret-change-me";
pub const DEV_API_KEY_PEPPER: &str = "dev-api-pepper-change-me";
pub const DEV_INTERNAL_TOKEN: &str = "dev-internal-token-change-me";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HecateEnv {
    Development,
    Production,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
    pub webauthn: Arc<Webauthn>,
    pub webauthn_challenges: RegistrationChallengeStore,
    pub webauthn_auth_challenges: AuthenticationChallengeStore,
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub hecate_env: HecateEnv,
    pub database_url: String,
    pub session_secret: String,
    pub api_key_pepper: String,
    pub internal_token: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub bind_addr: String,
    pub cors_allowed_origins: Vec<String>,
    pub release_artifacts_dir: PathBuf,
    pub hecate_repo_url: String,
    pub hecate_repo_mirror_dir: PathBuf,
    pub command_artifacts_dir: PathBuf,
    pub command_artifact_ttl_hours: i64,
    pub release_signing_public_key_b64: String,
    pub hecate_app_tag: String,
    pub server_update_trigger_path: PathBuf,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let command_artifact_ttl_hours = std::env::var("COMMAND_ARTIFACT_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(24);

        let hecate_env = {
            let raw = std::env::var("HECATE_ENV").map_err(|_| {
                anyhow::anyhow!(
                    "HECATE_ENV must be set explicitly to 'development' or 'production'"
                )
            })?;
            parse_hecate_env(&raw)?
        };
        // Default secrets require an explicit opt-in even in development.
        let allow_dev_secret_defaults = hecate_env == HecateEnv::Development
            && std::env::var("ALLOW_INSECURE_DEV").as_deref() == Ok("1");

        Ok(Self {
            hecate_env,
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://hecate:hecate@localhost:5432/hecate".into()),
            session_secret: match std::env::var("SESSION_SECRET") {
                Ok(value) => value,
                Err(_) if allow_dev_secret_defaults => DEV_SESSION_SECRET.into(),
                Err(_) => String::new(),
            },
            api_key_pepper: match std::env::var("API_KEY_PEPPER") {
                Ok(value) => value,
                Err(_) if allow_dev_secret_defaults => DEV_API_KEY_PEPPER.into(),
                Err(_) => String::new(),
            },
            internal_token: match std::env::var("INTERNAL_TOKEN") {
                Ok(value) => value,
                Err(_) if allow_dev_secret_defaults => DEV_INTERNAL_TOKEN.into(),
                Err(_) => String::new(),
            },
            rp_id: std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".into()),
            rp_origin: std::env::var("WEBAUTHN_RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            bind_addr: std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            cors_allowed_origins: parse_cors_allowed_origins(
                &std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_else(|_| default_cors_origins()),
            ),
            release_artifacts_dir: PathBuf::from(
                std::env::var("RELEASE_ARTIFACTS_DIR")
                    .unwrap_or_else(|_| "/opt/hecate/releases".into()),
            ),
            hecate_repo_url: std::env::var("HECATE_REPO_URL")
                .unwrap_or_else(|_| "https://repo.hecate-mcp.com".into()),
            hecate_repo_mirror_dir: PathBuf::from(
                std::env::var("HECATE_REPO_MIRROR_DIR")
                    .unwrap_or_else(|_| "/opt/hecate/releases/feature-repo".into()),
            ),
            command_artifacts_dir: PathBuf::from(
                std::env::var("COMMAND_ARTIFACTS_DIR")
                    .unwrap_or_else(|_| "/opt/hecate/command-artifacts".into()),
            ),
            command_artifact_ttl_hours,
            release_signing_public_key_b64: std::env::var("RELEASE_SIGNING_PUBLIC_KEY_B64")
                .unwrap_or_default(),
            hecate_app_tag: std::env::var("HECATE_APP_TAG").unwrap_or_else(|_| "1.0.0".into()),
            server_update_trigger_path: PathBuf::from(
                std::env::var("SERVER_UPDATE_TRIGGER_PATH")
                    .unwrap_or_else(|_| "/opt/hecate/run/server-update.trigger".into()),
            ),
        })
    }

    pub fn validate_production_secrets(&self) -> anyhow::Result<()> {
        if self.session_secret.is_empty()
            || self.api_key_pepper.is_empty()
            || self.internal_token.is_empty()
        {
            anyhow::bail!(
                "SESSION_SECRET, API_KEY_PEPPER, and INTERNAL_TOKEN are required \
                 (set ALLOW_INSECURE_DEV=1 to use development defaults)"
            );
        }
        if self.hecate_env == HecateEnv::Production
            && (self.session_secret == DEV_SESSION_SECRET
                || self.api_key_pepper == DEV_API_KEY_PEPPER
                || self.internal_token == DEV_INTERNAL_TOKEN
                || is_placeholder_secret(&self.session_secret)
                || is_placeholder_secret(&self.api_key_pepper)
                || is_placeholder_secret(&self.internal_token)
                || is_insecure_task_signing_master_key())
        {
            anyhow::bail!(
                "production refuses default, placeholder, or all-zero secrets \
                 (SESSION_SECRET / API_KEY_PEPPER / INTERNAL_TOKEN / HECATE_TASK_SIGNING_MASTER_KEY)"
            );
        }
        Ok(())
    }
}

fn is_placeholder_secret(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    lower.is_empty()
        || lower.contains("change-me")
        || lower.contains("changeme")
        || lower == "secret"
        || lower == "password"
        || value.len() < 16
}

fn is_insecure_task_signing_master_key() -> bool {
    let Ok(raw) = std::env::var("HECATE_TASK_SIGNING_MASTER_KEY") else {
        return true;
    };
    let material = raw
        .trim()
        .split_once(':')
        .map(|(_, rest)| rest)
        .unwrap_or(raw.trim());
    if material.is_empty() {
        return true;
    }
    if let Ok(bytes) = hex::decode(material) {
        return bytes.iter().all(|b| *b == 0);
    }
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    if let Ok(bytes) = BASE64.decode(material) {
        return bytes.iter().all(|b| *b == 0);
    }
    false
}

fn parse_hecate_env(raw: &str) -> anyhow::Result<HecateEnv> {
    match raw.trim().to_lowercase().as_str() {
        "development" | "dev" => Ok(HecateEnv::Development),
        "production" | "prod" => Ok(HecateEnv::Production),
        other => anyhow::bail!("invalid HECATE_ENV: {other}"),
    }
}

fn default_cors_origins() -> String {
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080".into()
}

pub fn parse_cors_allowed_origins(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

pub async fn build_webauthn(config: &AppConfig) -> anyhow::Result<Webauthn> {
    let rp_origin = Url::parse(&config.rp_origin)?;
    let builder = WebauthnBuilder::new(&config.rp_id, &rp_origin)?
        .rp_name("Hecate");
    Ok(builder.build()?)
}
