//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Shared protocol types for Hecate platform.

pub mod agent;
pub mod agent_signing;
pub mod authz;
pub mod backup;
pub mod command;
pub mod machine_tags;
pub mod permission_request;
pub mod permissions;
pub mod policy;
pub mod proxy;
pub mod release_artifacts;
pub mod remote_download_policy;
pub mod task;
pub mod task_signing;

pub const API_VERSION: &str = "v1";
pub const HECATE_VERSION: &str = env!("CARGO_PKG_VERSION");
