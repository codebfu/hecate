//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) mod admin;
pub(crate) mod agent;
pub(crate) mod auth;
pub(crate) mod authz;
pub(crate) mod internal;
pub(crate) mod proxy;
pub(crate) mod releases;
pub(crate) mod system;

use std::path::PathBuf;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Method};
use axum::Router;
use tower_http::cors::{AllowHeaders, AllowMethods, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

const UI_DIST_DIR: &str = "/opt/hecate/ui/dist";

/// Match permission `max_file_bytes` (50 MiB) so command-artifact uploads are not
/// rejected by axum's default 2 MiB body buffer before business limits apply.
const MAX_REQUEST_BODY_BYTES: usize = 50 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    let ui_root = PathBuf::from(UI_DIST_DIR);
    let static_files = ServeDir::new(ui_root.clone())
        .fallback(ServeFile::new(ui_root.join("index.html")));

    // Security headers primarily protect the UI SPA served by the fallback.
    let ui_security_headers = (
        SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'",
            ),
        ),
        SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ),
        SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
    );

    Router::new()
        .merge(auth::router())
        .merge(admin::router())
        .merge(agent::router())
        .merge(proxy::router())
        .merge(internal::router())
        .merge(releases::router())
        .merge(system::router())
        .fallback_service(static_files)
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(build_cors_layer(&state))
        .layer(ui_security_headers)
        .layer(TraceLayer::new_for_http())
}

fn build_cors_layer(state: &AppState) -> CorsLayer {
    let mut cors = CorsLayer::new()
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::list([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-csrf-token"),
        ]))
        .allow_credentials(true);

    for origin in &state.config.cors_allowed_origins {
        if let Ok(value) = HeaderValue::from_str(origin) {
            cors = cors.allow_origin(value);
        }
    }

    cors
}
