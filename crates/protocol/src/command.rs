//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    PendingApproval,
    Queued,
    Dispatched,
    Running,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommandEnqueueResponse {
    pub command_id: Uuid,
    pub status: CommandStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommandResultPayload {
    pub command_id: Uuid,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommandDetail {
    pub command_id: Uuid,
    pub machine_id: Uuid,
    pub command_name: String,
    pub status: CommandStatus,
    pub result: Option<CommandResultPayload>,
}
