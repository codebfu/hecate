//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

pub mod authz;
pub mod content_policy;
pub mod pagination;
pub mod machines;
pub mod admin_auth;
pub mod admin_commands;
pub mod command_dispatch;
pub mod command_queue;
pub mod command_definitions;
pub mod command_artifacts;
pub mod helper_install;
pub mod desktop_sessions;
pub mod proxmox_sessions;
pub mod agent_auth;
pub mod audit;
pub mod backup;
pub mod backup_crypto;
pub mod task_crypto;
pub mod crypto;
pub mod enrollment;
pub mod error;
pub mod feature_repo;
pub mod internal_auth;
pub mod key_rotation;
pub mod permissions;
pub mod permission_request_workflow;
pub mod permission_requests;
pub mod proxy_auth;
pub mod reboot_watch;
pub mod session;
pub mod routes;
pub mod security_tests;
pub mod server_settings;
pub mod server_update;
pub mod state;
pub mod updates;
pub mod webauthn_store;

pub use error::{ApiError, ApiResult};
