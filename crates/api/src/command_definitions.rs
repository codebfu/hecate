//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use sqlx::PgPool;

use crate::error::ApiResult;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CommandDefinitionSummary {
    pub name: String,
    pub description: String,
    pub risk_level: String,
}

pub async fn list_command_definitions(pool: &PgPool) -> ApiResult<Vec<CommandDefinitionSummary>> {
    let rows = sqlx::query_as::<_, CommandDefinitionSummary>(
        "SELECT name, description, risk_level FROM command_definitions ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
