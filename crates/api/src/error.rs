//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("{0}")]
    ForbiddenMessage(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("too many requests: {0}")]
    TooManyRequests(String),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
    #[error("database error")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, msg) = match &self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", self.to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", self.to_string()),
            ApiError::ForbiddenMessage(m) => (StatusCode::FORBIDDEN, "forbidden", m.clone()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, "conflict", m.clone()),
            ApiError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests", m.clone()),
            ApiError::Internal(e) => {
                tracing::error!(error = %e, "internal API error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error".into())
            }
            ApiError::Db(e) => {
                tracing::error!(error = %e, "database API error");
                (StatusCode::INTERNAL_SERVER_ERROR, "database", "database error".into())
            }
        };
        (status, Json(json!({ "error": code, "message": msg }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
