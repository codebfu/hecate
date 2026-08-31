//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use hecate_protocol::authz::MatchedGrant;
use hecate_protocol::permissions::CapabilityProfileRules;
use hecate_protocol::policy;
use hecate_protocol::remote_download_policy;
use sqlx::PgPool;
use uuid::Uuid;

use crate::authz::evaluator;
use crate::error::{ApiError, ApiResult};

pub async fn authorize_command(
    pool: &PgPool,
    identity_id: Uuid,
    machine_id: Uuid,
    command_name: &str,
    params: &serde_json::Value,
) -> ApiResult<MatchedGrant> {
    let grant =
        evaluator::authorize_agent_command(pool, identity_id, machine_id, command_name, params)
            .await?;
    evaluator::check_max_concurrent(
        pool,
        identity_id,
        grant.capability_profile.max_concurrent,
    )
    .await?;
    Ok(grant)
}

pub fn validate_shell_params(params: &serde_json::Value, rules: &CapabilityProfileRules) -> ApiResult<()> {
    let argv: Vec<String> = params
        .get("argv")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .ok_or_else(|| ApiError::BadRequest("argv required".into()))?;
    let elevated = params
        .get("elevated")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if elevated {
        policy::check_elevation_policy(&argv, &rules.elevation_policy)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    } else {
        policy::check_shell_policy(&argv, &rules.shell_policy.allowed_binaries)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    let cwd = params
        .get("cwd")
        .and_then(|value| value.as_str())
        .unwrap_or(".");
    policy::check_cwd_policy(cwd, &rules.shell_policy.allowed_cwd)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if let Some(env_value) = params.get("env") {
        let obj = env_value
            .as_object()
            .ok_or_else(|| ApiError::BadRequest("env must be an object".into()))?;
        let mut env_map = std::collections::HashMap::new();
        for (key, value) in obj {
            let Some(val) = value.as_str() else {
                return Err(ApiError::BadRequest("env values must be strings".into()));
            };
            env_map.insert(key.clone(), val.to_string());
        }
        policy::check_env_policy(&env_map, &rules.shell_policy.allowed_env)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(timeout_secs) = optional_u64(params, "timeout_secs")? {
        let max_timeout = u64::from(rules.timeout_secs.max(1));
        if !(1..=max_timeout).contains(&timeout_secs) {
            return Err(ApiError::BadRequest(format!(
                "timeout_secs must be 1..{max_timeout}"
            )));
        }
    }
    Ok(())
}

fn required_path(params: &serde_json::Value, key: &str) -> ApiResult<String> {
    params
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ApiError::BadRequest(format!("{key} required")))
}

fn validate_path_under_policy(path: &str, rules: &CapabilityProfileRules) -> ApiResult<()> {
    policy::reject_path_traversal(path).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    policy::check_cwd_policy(path, &rules.shell_policy.allowed_cwd)
        .map_err(|error| ApiError::BadRequest(error.to_string()))
}

fn validate_name_component(name: &str) -> ApiResult<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("new_name must not be empty".into()));
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err(ApiError::BadRequest("new_name must not contain path separators".into()));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(ApiError::BadRequest("invalid new_name".into()));
    }
    Ok(())
}

pub fn validate_path_params(params: &serde_json::Value, rules: &CapabilityProfileRules) -> ApiResult<()> {
    let path = required_path(params, "path")?;
    validate_path_under_policy(&path, rules)
}

pub fn validate_src_dest_params(
    params: &serde_json::Value,
    rules: &CapabilityProfileRules,
) -> ApiResult<()> {
    let src = required_path(params, "src")?;
    let dest = required_path(params, "dest")?;
    validate_path_under_policy(&src, rules)?;
    validate_path_under_policy(&dest, rules)
}

pub fn validate_rename_params(params: &serde_json::Value, rules: &CapabilityProfileRules) -> ApiResult<()> {
    let path = required_path(params, "path")?;
    let new_name = required_path(params, "new_name")?;
    validate_path_under_policy(&path, rules)?;
    validate_name_component(&new_name)?;
    let parent = std::path::Path::new(&path)
        .parent()
        .and_then(|value| value.to_str())
        .unwrap_or(".");
    let dest = format!(
        "{}/{}",
        parent.trim_end_matches('/'),
        new_name.trim()
    );
    validate_path_under_policy(&dest, rules)
}

pub fn validate_mkdir_params(params: &serde_json::Value, rules: &CapabilityProfileRules) -> ApiResult<()> {
    validate_path_params(params, rules)?;
    if let Some(mode) = params.get("mode").and_then(|value| value.as_str()) {
        if mode.len() != 4 || !mode.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(ApiError::BadRequest("mode must be a 4-digit octal string".into()));
        }
    }
    Ok(())
}

pub fn validate_file_pull_params(params: &serde_json::Value, rules: &CapabilityProfileRules) -> ApiResult<()> {
    validate_path_params(params, rules)
}

pub fn validate_file_push_params(params: &serde_json::Value, rules: &CapabilityProfileRules) -> ApiResult<()> {
    let dest_path = required_path(params, "dest_path")?;
    validate_path_under_policy(&dest_path, rules)?;

    let artifact_id = params
        .get("artifact_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| ApiError::BadRequest("artifact_id required".into()))?;
    Uuid::parse_str(artifact_id)
        .map_err(|_| ApiError::BadRequest("artifact_id must be a UUID".into()))?;

    let sha256 = required_path(params, "sha256")?;
    if sha256.len() != 64 || !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("sha256 must be a 64-char hex string".into()));
    }

    if let Some(mode) = params.get("mode").and_then(|value| value.as_str()) {
        if mode.len() != 4 || !mode.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(ApiError::BadRequest("mode must be a 4-digit octal string".into()));
        }
    }

    Ok(())
}

pub fn validate_remote_download_params(
    params: &serde_json::Value,
    rules: &CapabilityProfileRules,
) -> ApiResult<()> {
    let url = required_path(params, "url")?;
    remote_download_policy::check_remote_download_url(&url)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    if let Some(connect_ip) = params.get("connect_ip") {
        let raw = connect_ip.as_str().ok_or_else(|| {
            ApiError::BadRequest("connect_ip must be a string".into())
        })?;
        let ip: std::net::IpAddr = raw.parse().map_err(|_| {
            ApiError::BadRequest(format!("invalid connect_ip: {raw}"))
        })?;
        if remote_download_policy::is_blocked_ip(ip) {
            return Err(ApiError::BadRequest(format!(
                "connect_ip is a private or reserved address: {ip}"
            )));
        }
    }

    if let Some(dest_path) = params.get("dest_path").and_then(|value| value.as_str()) {
        let dest_path = dest_path.trim();
        if !dest_path.is_empty() {
            validate_path_under_policy(dest_path, rules)?;
        }
    }

    if let Some(headers) = params.get("headers") {
        let Some(obj) = headers.as_object() else {
            return Err(ApiError::BadRequest("headers must be an object".into()));
        };
        for (key, value) in obj {
            if key.trim().is_empty() {
                return Err(ApiError::BadRequest("header names must not be empty".into()));
            }
            if !value.is_string() {
                return Err(ApiError::BadRequest(format!(
                    "header {key} must be a string"
                )));
            }
        }
    }

    Ok(())
}

pub async fn validate_remote_download_resolved_host(params: &serde_json::Value) -> ApiResult<()> {
    let _ = resolve_remote_download_connect_ip(params).await?;
    Ok(())
}

/// Resolve the download host and persist the chosen public IP on params as `connect_ip`.
/// The agent must connect to this IP (with the original Host header) and must not re-resolve.
pub async fn pin_remote_download_connect_ip(params: &mut serde_json::Value) -> ApiResult<()> {
    let ip = resolve_remote_download_connect_ip(params).await?;
    let obj = params.as_object_mut().ok_or_else(|| {
        ApiError::BadRequest("params must be an object".into())
    })?;
    obj.insert("connect_ip".into(), serde_json::Value::String(ip));
    Ok(())
}

async fn resolve_remote_download_connect_ip(params: &serde_json::Value) -> ApiResult<String> {
    let url = required_path(params, "url")?;
    let parsed = url::Url::parse(&url).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("url missing host".into()))?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if remote_download_policy::is_blocked_ip(ip) {
            return Err(ApiError::BadRequest(format!(
                "download URL host is a private or reserved address: {ip}"
            )));
        }
        return Ok(ip.to_string());
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| ApiError::BadRequest(format!("cannot resolve download host: {error}")))?
        .collect();
    if addresses.is_empty() {
        return Err(ApiError::BadRequest(
            "download host resolved to no addresses".into(),
        ));
    }
    let mut chosen = None;
    for address in addresses {
        if remote_download_policy::is_blocked_ip(address.ip()) {
            return Err(ApiError::BadRequest(format!(
                "download URL resolves to a private or reserved address: {}",
                address.ip()
            )));
        }
        chosen.get_or_insert(address.ip());
    }
    Ok(chosen
        .ok_or_else(|| ApiError::BadRequest("download host resolved to no addresses".into()))?
        .to_string())
}

pub fn shell_run_is_elevated(params: &serde_json::Value) -> bool {
    params
        .get("elevated")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

pub async fn command_enqueue_requires_approval(
    pool: &PgPool,
    grant: &MatchedGrant,
    command_name: &str,
    params: &serde_json::Value,
) -> ApiResult<bool> {
    if command_name == "shell.run" && shell_run_is_elevated(params) {
        return Ok(grant.requires_approval_for_elevated);
    }

    let risk: Option<(String,)> =
        sqlx::query_as("SELECT risk_level FROM command_definitions WHERE name = $1")
            .bind(command_name)
            .fetch_optional(pool)
            .await?;
    let risk_level = match risk {
        Some((level,)) => level,
        None => return Ok(true),
    };
    if risk_level != "high" {
        return Ok(false);
    }
    Ok(grant.requires_approval_for_shell)
}

fn optional_u64(params: &serde_json::Value, key: &str) -> ApiResult<Option<u64>> {
    match params.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| ApiError::BadRequest(format!("{key} must be an unsigned integer")))
            .map(Some),
    }
}

fn optional_i64(params: &serde_json::Value, key: &str) -> ApiResult<Option<i64>> {
    match params.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .ok_or_else(|| ApiError::BadRequest(format!("{key} must be an integer")))
            .map(Some),
    }
}

fn optional_f64(params: &serde_json::Value, key: &str) -> ApiResult<Option<f64>> {
    match params.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .ok_or_else(|| ApiError::BadRequest(format!("{key} must be a number")))
            .map(Some),
    }
}

fn require_point(params: &serde_json::Value, key: &str) -> ApiResult<(f64, f64)> {
    let obj = params
        .get(key)
        .and_then(|v| v.as_object())
        .ok_or_else(|| ApiError::BadRequest(format!("{key} object required")))?;
    let x = obj
        .get("x")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ApiError::BadRequest(format!("{key}.x required")))?;
    let y = obj
        .get("y")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ApiError::BadRequest(format!("{key}.y required")))?;
    Ok((x, y))
}

fn validate_region(params: &serde_json::Value) -> ApiResult<()> {
    let Some(region) = params.get("region") else {
        return Ok(());
    };
    let obj = region
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("region must be an object".into()))?;
    for key in ["x", "y", "width", "height"] {
        let value = obj
            .get(key)
            .and_then(|v| v.as_f64())
            .ok_or_else(|| ApiError::BadRequest(format!("region.{key} required")))?;
        if matches!(key, "width" | "height") && value <= 0.0 {
            return Err(ApiError::BadRequest(format!(
                "region.{key} must be positive"
            )));
        }
    }
    Ok(())
}

pub fn validate_desktop_params(
    command_name: &str,
    params: &serde_json::Value,
    rules: &CapabilityProfileRules,
) -> ApiResult<()> {
    if !params.is_object() {
        return Err(ApiError::BadRequest("params must be an object".into()));
    }

    match command_name {
        "desktop.info" => Ok(()),
        "desktop.screenshot" => {
            let _ = optional_u64(params, "display")?;
            validate_region(params)
        }
        "desktop.move" => {
            let _ = optional_f64(params, "x")?;
            let _ = optional_f64(params, "y")?;
            if params.get("x").is_none() || params.get("y").is_none() {
                return Err(ApiError::BadRequest("x and y required".into()));
            }
            let _ = optional_u64(params, "display")?;
            Ok(())
        }
        "desktop.click" => {
            if params.get("x").and_then(|v| v.as_f64()).is_none()
                || params.get("y").and_then(|v| v.as_f64()).is_none()
            {
                return Err(ApiError::BadRequest("x and y required".into()));
            }
            if let Some(button) = params.get("button").and_then(|v| v.as_str()) {
                if !matches!(button, "left" | "right" | "middle") {
                    return Err(ApiError::BadRequest(
                        "button must be left, right, or middle".into(),
                    ));
                }
            }
            if let Some(count) = optional_u64(params, "count")? {
                if !(1..=3).contains(&count) {
                    return Err(ApiError::BadRequest("count must be 1..3".into()));
                }
            }
            let _ = optional_u64(params, "display")?;
            Ok(())
        }
        "desktop.scroll" => {
            if params.get("x").and_then(|v| v.as_f64()).is_none()
                || params.get("y").and_then(|v| v.as_f64()).is_none()
            {
                return Err(ApiError::BadRequest("x and y required".into()));
            }
            let _ = optional_i64(params, "dx")?;
            let _ = optional_i64(params, "dy")?;
            let _ = optional_i64(params, "delta")?;
            let _ = optional_u64(params, "display")?;
            Ok(())
        }
        "desktop.drag" => {
            let _ = require_point(params, "from")?;
            let _ = require_point(params, "to")?;
            if let Some(button) = params.get("button").and_then(|v| v.as_str()) {
                if !matches!(button, "left" | "right" | "middle") {
                    return Err(ApiError::BadRequest(
                        "button must be left, right, or middle".into(),
                    ));
                }
            }
            let _ = optional_u64(params, "duration_ms")?;
            let _ = optional_u64(params, "display")?;
            Ok(())
        }
        "desktop.type" => {
            let text = params
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::BadRequest("text required".into()))?;
            if text.is_empty() {
                return Err(ApiError::BadRequest("text must not be empty".into()));
            }
            if text.len() > 16_384 {
                return Err(ApiError::BadRequest("text exceeds 16384 bytes".into()));
            }
            let _ = optional_u64(params, "delay_ms")?;
            Ok(())
        }
        "desktop.key" => {
            let key = params
                .get("key")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| ApiError::BadRequest("key required".into()))?;
            let _ = key;
            if let Some(action) = params.get("action").and_then(|v| v.as_str()) {
                if !matches!(action, "press" | "release" | "tap") {
                    return Err(ApiError::BadRequest(
                        "action must be press, release, or tap".into(),
                    ));
                }
            }
            if let Some(modifiers) = params.get("modifiers") {
                let arr = modifiers
                    .as_array()
                    .ok_or_else(|| ApiError::BadRequest("modifiers must be an array".into()))?;
                for item in arr {
                    if item.as_str().is_none() {
                        return Err(ApiError::BadRequest(
                            "modifiers entries must be strings".into(),
                        ));
                    }
                }
            }
            Ok(())
        }
        "desktop.clipboard.get" => {
            if let Some(format) = params.get("format").and_then(|v| v.as_str()) {
                if !matches!(format, "text" | "image") {
                    return Err(ApiError::BadRequest("format must be text or image".into()));
                }
            }
            Ok(())
        }
        "desktop.clipboard.set" => {
            let has_text = params
                .get("text")
                .and_then(|v| v.as_str())
                .map(|v| !v.is_empty())
                .unwrap_or(false);
            let has_artifact = params.get("artifact_id").and_then(|v| v.as_str()).is_some();
            if has_text == has_artifact {
                return Err(ApiError::BadRequest(
                    "provide exactly one of text or artifact_id".into(),
                ));
            }
            if has_artifact {
                let artifact_id = params
                    .get("artifact_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ApiError::BadRequest("artifact_id required".into()))?;
                Uuid::parse_str(artifact_id)
                    .map_err(|_| ApiError::BadRequest("artifact_id must be a UUID".into()))?;
                let sha256 = params
                    .get("sha256")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ApiError::BadRequest("sha256 required".into()))?;
                if sha256.len() != 64 || !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    return Err(ApiError::BadRequest(
                        "sha256 must be a 64-char hex string".into(),
                    ));
                }
            }
            Ok(())
        }
        "desktop.session.open" => {
            if let Some(fps) = optional_u64(params, "fps")? {
                if !(1..=10).contains(&fps) {
                    return Err(ApiError::BadRequest("fps must be 1..10".into()));
                }
            }
            if let Some(max_duration) = optional_u64(params, "max_duration_secs")? {
                if !(30..=3600).contains(&max_duration) {
                    return Err(ApiError::BadRequest(
                        "max_duration_secs must be 30..3600".into(),
                    ));
                }
            }
            if let Some(format) = params.get("format").and_then(|v| v.as_str()) {
                if !matches!(format, "png" | "jpeg") {
                    return Err(ApiError::BadRequest("format must be png or jpeg".into()));
                }
            }
            let _ = optional_u64(params, "display")?;
            Ok(())
        }
        "desktop.session.frame" | "desktop.session.close" => {
            let _ = params
                .get("session_id")
                .and_then(|v| v.as_str())
                .and_then(|v| Uuid::parse_str(v).ok())
                .ok_or_else(|| ApiError::BadRequest("session_id required".into()))?;
            Ok(())
        }
        "desktop.session.input" => {
            let _ = params
                .get("session_id")
                .and_then(|v| v.as_str())
                .and_then(|v| Uuid::parse_str(v).ok())
                .ok_or_else(|| ApiError::BadRequest("session_id required".into()))?;
            let events = params
                .get("events")
                .and_then(|v| v.as_array())
                .ok_or_else(|| ApiError::BadRequest("events array required".into()))?;
            if events.is_empty() {
                return Err(ApiError::BadRequest("events must not be empty".into()));
            }
            if events.len() > 64 {
                return Err(ApiError::BadRequest("events exceeds max of 64".into()));
            }
            for event in events {
                let action = event
                    .get("action")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ApiError::BadRequest("event.action required".into()))?;
                if !matches!(
                    action,
                    "move" | "click" | "scroll" | "drag" | "type" | "key"
                ) {
                    return Err(ApiError::BadRequest(format!(
                        "unsupported event.action: {action}"
                    )));
                }
            }
            Ok(())
        }
        "desktop.app.launch" => {
            let app = params
                .get("app")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| ApiError::BadRequest("app required".into()))?;
            let _ = app;
            if let Some(args) = params.get("args") {
                let arr = args
                    .as_array()
                    .ok_or_else(|| ApiError::BadRequest("args must be an array".into()))?;
                if arr.len() > 64 {
                    return Err(ApiError::BadRequest("args exceeds max of 64".into()));
                }
                for item in arr {
                    if item.as_str().is_none() {
                        return Err(ApiError::BadRequest("args entries must be strings".into()));
                    }
                }
            }
            if let Some(cwd) = params.get("cwd").and_then(|v| v.as_str()) {
                if cwd.trim().is_empty() {
                    return Err(ApiError::BadRequest("cwd must not be empty".into()));
                }
            }
            if let Some(wait_ms) = optional_u64(params, "wait_window_ms")? {
                if wait_ms > 120_000 {
                    return Err(ApiError::BadRequest(
                        "wait_window_ms must be <= 120000".into(),
                    ));
                }
            }
            Ok(())
        }
        "desktop.window.list" => {
            if let Some(include_hidden) = params.get("include_hidden") {
                if include_hidden.as_bool().is_none() {
                    return Err(ApiError::BadRequest(
                        "include_hidden must be a boolean".into(),
                    ));
                }
            }
            Ok(())
        }
        "desktop.window.focus" | "desktop.window.wait" => {
            validate_window_match_params(params)?;
            if command_name == "desktop.window.wait" {
                if let Some(timeout_ms) = optional_u64(params, "timeout_ms")? {
                    if !(1..=300_000).contains(&timeout_ms) {
                        return Err(ApiError::BadRequest(
                            "timeout_ms must be 1..300000".into(),
                        ));
                    }
                }
                if let Some(state) = params.get("state").and_then(|v| v.as_str()) {
                    if !matches!(state, "visible" | "focused") {
                        return Err(ApiError::BadRequest(
                            "state must be visible or focused".into(),
                        ));
                    }
                }
            }
            Ok(())
        }
        "desktop.shell.run" => {
            let argv_json = params
                .get("argv")
                .and_then(|v| v.as_array())
                .ok_or_else(|| ApiError::BadRequest("argv required".into()))?;
            if argv_json.is_empty() {
                return Err(ApiError::BadRequest("argv must not be empty".into()));
            }
            if argv_json.len() > 128 {
                return Err(ApiError::BadRequest("argv exceeds max of 128".into()));
            }
            let mut argv = Vec::with_capacity(argv_json.len());
            for item in argv_json {
                let Some(arg) = item.as_str() else {
                    return Err(ApiError::BadRequest("argv entries must be strings".into()));
                };
                if arg.is_empty() {
                    return Err(ApiError::BadRequest("argv entries must not be empty".into()));
                }
                argv.push(arg.to_string());
            }
            let binary = &argv[0];
            let is_unix_abs = binary.starts_with('/');
            let is_windows_abs = binary.len() >= 3
                && binary.as_bytes()[0].is_ascii_alphabetic()
                && binary.as_bytes()[1] == b':'
                && (binary.as_bytes()[2] == b'\\' || binary.as_bytes()[2] == b'/');
            if !is_unix_abs && !is_windows_abs {
                return Err(ApiError::BadRequest(
                    "argv[0] must be an absolute path".into(),
                ));
            }
            let elevated = params
                .get("elevated")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            if elevated {
                policy::check_elevation_policy(&argv, &rules.elevation_policy)
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            } else {
                policy::check_shell_policy(&argv, &rules.shell_policy.allowed_binaries)
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            }
            let cwd = params
                .get("cwd")
                .and_then(|v| v.as_str())
                .unwrap_or(".");
            if cwd.trim().is_empty() {
                return Err(ApiError::BadRequest("cwd must not be empty".into()));
            }
            policy::check_cwd_policy(cwd, &rules.shell_policy.allowed_cwd)
                .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            if let Some(env) = params.get("env") {
                let obj = env
                    .as_object()
                    .ok_or_else(|| ApiError::BadRequest("env must be an object".into()))?;
                if obj.len() > 64 {
                    return Err(ApiError::BadRequest("env exceeds max of 64 keys".into()));
                }
                let mut env_map = std::collections::HashMap::new();
                for (key, value) in obj {
                    let Some(val) = value.as_str() else {
                        return Err(ApiError::BadRequest(
                            "env keys/values must be non-empty strings".into(),
                        ));
                    };
                    if key.is_empty() {
                        return Err(ApiError::BadRequest(
                            "env keys/values must be non-empty strings".into(),
                        ));
                    }
                    env_map.insert(key.clone(), val.to_string());
                }
                policy::check_env_policy(&env_map, &rules.shell_policy.allowed_env)
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            }
            if let Some(timeout_secs) = optional_u64(params, "timeout_secs")? {
                if !(1..=3600).contains(&timeout_secs) {
                    return Err(ApiError::BadRequest(
                        "timeout_secs must be 1..3600".into(),
                    ));
                }
            }
            Ok(())
        }
        _ => Err(ApiError::BadRequest(format!(
            "unknown desktop command: {command_name}"
        ))),
    }
}

pub fn validate_proxmox_params(
    command_name: &str,
    params: &serde_json::Value,
) -> ApiResult<()> {
    if !params.is_object() {
        return Err(ApiError::BadRequest("params must be an object".into()));
    }

    match command_name {
        "proxmox.info" | "proxmox.vm.list" => Ok(()),
        "proxmox.console.open" => {
            let vmid = params
                .get("vmid")
                .and_then(|value| value.as_u64())
                .filter(|value| *value > 0 && *value <= i32::MAX as u64)
                .ok_or_else(|| ApiError::BadRequest("vmid must be a positive integer".into()))?;
            let _ = vmid;
            if let Some(fps) = optional_u64(params, "fps")? {
                if !(1..=10).contains(&fps) {
                    return Err(ApiError::BadRequest("fps must be 1..10".into()));
                }
            }
            if let Some(max_duration) = optional_u64(params, "max_duration_secs")? {
                if !(30..=3600).contains(&max_duration) {
                    return Err(ApiError::BadRequest(
                        "max_duration_secs must be 30..3600".into(),
                    ));
                }
            }
            if let Some(format) = params.get("format").and_then(|value| value.as_str()) {
                if !matches!(format, "png" | "jpeg") {
                    return Err(ApiError::BadRequest("format must be png or jpeg".into()));
                }
            }
            Ok(())
        }
        "proxmox.console.frame" | "proxmox.console.close" => {
            validate_proxmox_session_id(params)
        }
        "proxmox.console.input" => {
            validate_proxmox_session_id(params)?;
            let events = params
                .get("events")
                .and_then(|value| value.as_array())
                .ok_or_else(|| ApiError::BadRequest("events array required".into()))?;
            if events.is_empty() {
                return Err(ApiError::BadRequest("events must not be empty".into()));
            }
            if events.len() > 64 {
                return Err(ApiError::BadRequest("events exceeds max of 64".into()));
            }
            Ok(())
        }
        _ => Err(ApiError::BadRequest(format!(
            "unknown Proxmox command: {command_name}"
        ))),
    }
}

fn validate_proxmox_session_id(params: &serde_json::Value) -> ApiResult<()> {
    params
        .get("session_id")
        .and_then(|value| value.as_str())
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| ApiError::BadRequest("session_id required".into()))?;
    Ok(())
}

fn validate_window_match_params(params: &serde_json::Value) -> ApiResult<()> {
    let id = params
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let title = params
        .get("title")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let app = params
        .get("app")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let count = [id.is_some(), title.is_some(), app.is_some()]
        .into_iter()
        .filter(|v| *v)
        .count();
    if count != 1 {
        return Err(ApiError::BadRequest(
            "provide exactly one of id, title, or app".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::permissions::{ElevationPolicy, ShellPolicy};

    fn default_rules() -> CapabilityProfileRules {
        CapabilityProfileRules {
            allowed_commands: vec!["system.info".into(), "permissions.request".into()],
            allowed_admin_commands: vec![],
            shell_policy: ShellPolicy::default(),
            elevation_policy: ElevationPolicy::default(),
            max_output_bytes: hecate_protocol::permissions::DEFAULT_MAX_OUTPUT_BYTES,
            max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
            timeout_secs: hecate_protocol::permissions::DEFAULT_TIMEOUT_SECS,
            max_concurrent: hecate_protocol::permissions::DEFAULT_MAX_CONCURRENT,
        }
    }

    #[test]
    fn rejects_shell_outside_policy() {
        let rules = CapabilityProfileRules {
            allowed_commands: vec!["shell.run".into()],
            shell_policy: ShellPolicy {
                allowed_binaries: vec!["/usr/bin/uptime".into()],
                ..Default::default()
            },
            ..default_rules()
        };
        let params = serde_json::json!({ "argv": ["/bin/sh", "-c", "ls"] });
        assert!(validate_shell_params(&params, &rules).is_err());
    }

    #[test]
    fn allows_shell_in_subdirectory_cwd() {
        let rules = CapabilityProfileRules {
            allowed_commands: vec!["shell.run".into()],
            shell_policy: ShellPolicy {
                allowed_binaries: vec!["/usr/bin/uptime".into()],
                allowed_cwd: vec!["/tmp".into()],
                ..Default::default()
            },
            ..default_rules()
        };
        let params = serde_json::json!({ "argv": ["/usr/bin/uptime"], "cwd": "/tmp/nested" });
        assert!(validate_shell_params(&params, &rules).is_ok());
    }

    #[test]
    fn command_wildcard_allows_any_command() {
        let rules = CapabilityProfileRules {
            allowed_commands: vec!["*".into()],
            ..default_rules()
        };
        assert!(hecate_protocol::permissions::command_allowed(
            &rules.allowed_commands,
            "custom.command"
        ));
    }

    #[test]
    fn rejects_sudo_in_argv() {
        let rules = CapabilityProfileRules {
            allowed_commands: vec!["shell.run".into()],
            shell_policy: ShellPolicy {
                allowed_binaries: vec!["*".into()],
                ..Default::default()
            },
            ..default_rules()
        };
        let params = serde_json::json!({ "argv": ["/usr/bin/sudo", "/usr/bin/id"] });
        assert!(validate_shell_params(&params, &rules).is_err());
    }

    #[test]
    fn elevated_requires_elevation_policy() {
        let rules = CapabilityProfileRules {
            allowed_commands: vec!["shell.run".into()],
            shell_policy: ShellPolicy {
                allowed_binaries: vec!["/usr/bin/id".into()],
                ..Default::default()
            },
            elevation_policy: hecate_protocol::permissions::ElevationPolicy {
                enabled: false,
                allowed_binaries: vec![],
            },
            ..default_rules()
        };
        let params = serde_json::json!({
            "argv": ["/usr/bin/id"],
            "elevated": true
        });
        assert!(validate_shell_params(&params, &rules).is_err());
    }

    #[test]
    fn elevated_allows_elevation_allowlist() {
        let rules = CapabilityProfileRules {
            allowed_commands: vec!["shell.run".into()],
            shell_policy: ShellPolicy {
                allowed_binaries: vec![],
                allowed_cwd: vec!["*".into()],
                allowed_env: vec![],
            },
            elevation_policy: hecate_protocol::permissions::ElevationPolicy {
                enabled: true,
                allowed_binaries: vec!["/usr/bin/id".into()],
            },
            ..default_rules()
        };
        let params = serde_json::json!({
            "argv": ["/usr/bin/id"],
            "elevated": true
        });
        assert!(validate_shell_params(&params, &rules).is_ok());
    }

    #[test]
    fn shell_run_is_elevated_detects_flag() {
        assert!(!shell_run_is_elevated(&serde_json::json!({ "argv": ["/usr/bin/id"] })));
        assert!(shell_run_is_elevated(&serde_json::json!({ "argv": ["/usr/bin/id"], "elevated": true })));
        assert!(!shell_run_is_elevated(&serde_json::json!({ "argv": ["/usr/bin/id"], "elevated": false })));
    }

    #[test]
    fn validates_file_pull_path_against_allowed_cwd() {
        let rules = CapabilityProfileRules {
            shell_policy: ShellPolicy {
                allowed_cwd: vec!["/tmp".into()],
                ..Default::default()
            },
            ..default_rules()
        };
        assert!(validate_file_pull_params(
            &serde_json::json!({ "path": "/tmp/data.txt" }),
            &rules
        )
        .is_ok());
        assert!(validate_file_pull_params(
            &serde_json::json!({ "path": "/etc/passwd" }),
            &rules
        )
        .is_err());
    }

    #[test]
    fn validates_remote_download_https_only() {
        let rules = default_rules();
        assert!(validate_remote_download_params(
            &serde_json::json!({ "url": "https://example.com/file" }),
            &rules
        )
        .is_ok());
        assert!(validate_remote_download_params(
            &serde_json::json!({ "url": "http://example.com/file" }),
            &rules
        )
        .is_err());
        assert!(validate_remote_download_params(
            &serde_json::json!({
                "url": "https://example.com/file",
                "connect_ip": "93.184.216.34"
            }),
            &rules
        )
        .is_ok());
        assert!(validate_remote_download_params(
            &serde_json::json!({
                "url": "https://example.com/file",
                "connect_ip": "127.0.0.1"
            }),
            &rules
        )
        .is_err());
    }

    #[test]
    fn validates_src_dest_under_allowed_cwd() {
        let rules = CapabilityProfileRules {
            shell_policy: ShellPolicy {
                allowed_cwd: vec!["/tmp".into()],
                ..Default::default()
            },
            ..default_rules()
        };
        assert!(validate_src_dest_params(
            &serde_json::json!({
                "src": "/tmp/a.txt",
                "dest": "/tmp/b.txt",
            }),
            &rules
        )
        .is_ok());
        assert!(validate_src_dest_params(
            &serde_json::json!({
                "src": "/etc/passwd",
                "dest": "/tmp/b.txt",
            }),
            &rules
        )
        .is_err());
    }

    #[test]
    fn validates_rename_rejects_separator_in_new_name() {
        let rules = CapabilityProfileRules {
            shell_policy: ShellPolicy {
                allowed_cwd: vec!["/tmp".into()],
                ..Default::default()
            },
            ..default_rules()
        };
        assert!(validate_rename_params(
            &serde_json::json!({
                "path": "/tmp/a.txt",
                "new_name": "../escape",
            }),
            &rules
        )
        .is_err());
    }

    #[test]
    fn validates_desktop_click_requires_xy() {
        let rules = default_rules();
        assert!(validate_desktop_params("desktop.click", &serde_json::json!({}), &rules).is_err());
        assert!(validate_desktop_params(
            "desktop.click",
            &serde_json::json!({ "x": 1, "y": 2 }),
            &rules
        )
        .is_ok());
    }

    #[test]
    fn validates_desktop_session_input_events() {
        let rules = default_rules();
        assert!(validate_desktop_params(
            "desktop.session.input",
            &serde_json::json!({
                "session_id": "00000000-0000-0000-0000-000000000001",
                "events": [{ "action": "click", "x": 1, "y": 2 }]
            }),
            &rules
        )
        .is_ok());
    }

    #[test]
    fn validates_proxmox_console_params() {
        assert!(validate_proxmox_params(
            "proxmox.console.open",
            &serde_json::json!({ "vmid": 100, "fps": 2 }),
        )
        .is_ok());
        assert!(
            validate_proxmox_params("proxmox.console.open", &serde_json::json!({ "vmid": 0 }),)
                .is_err()
        );
        assert!(validate_proxmox_params(
            "proxmox.console.input",
            &serde_json::json!({
                "session_id": "00000000-0000-0000-0000-000000000001",
                "events": [{ "action": "key", "key": "Enter" }]
            }),
        )
        .is_ok());
    }

    #[test]
    fn validates_desktop_info_empty() {
        let rules = default_rules();
        assert!(validate_desktop_params("desktop.info", &serde_json::json!({}), &rules).is_ok());
    }

    #[test]
    fn validates_desktop_app_launch() {
        let rules = default_rules();
        assert!(validate_desktop_params("desktop.app.launch", &serde_json::json!({}), &rules).is_err());
        assert!(validate_desktop_params(
            "desktop.app.launch",
            &serde_json::json!({ "app": "mousepad", "wait_window_ms": 5000 }),
            &rules
        )
        .is_ok());
    }

    #[test]
    fn validates_desktop_window_focus_exactly_one_match() {
        let rules = default_rules();
        assert!(validate_desktop_params("desktop.window.focus", &serde_json::json!({}), &rules).is_err());
        assert!(validate_desktop_params(
            "desktop.window.focus",
            &serde_json::json!({ "id": "1", "title": "x" }),
            &rules
        )
        .is_err());
        assert!(validate_desktop_params(
            "desktop.window.focus",
            &serde_json::json!({ "title": "Mousepad" }),
            &rules
        )
        .is_ok());
    }

    #[test]
    fn validates_desktop_shell_run_absolute_argv() {
        let mut rules = default_rules();
        rules.shell_policy.allowed_binaries = vec![
            "/usr/bin/xdg-user-dir".into(),
            r"C:\Windows\System32\cmd.exe".into(),
        ];
        rules.shell_policy.allowed_cwd = vec!["*".into()];
        assert!(validate_desktop_params(
            "desktop.shell.run",
            &serde_json::json!({ "argv": ["xdg-user-dir", "DESKTOP"] }),
            &rules
        )
        .is_err());
        assert!(validate_desktop_params(
            "desktop.shell.run",
            &serde_json::json!({ "argv": ["/usr/bin/xdg-user-dir", "DESKTOP"] }),
            &rules
        )
        .is_ok());
        assert!(validate_desktop_params(
            "desktop.shell.run",
            &serde_json::json!({ "argv": ["C:\\Windows\\System32\\cmd.exe", "/c", "echo"] }),
            &rules
        )
        .is_ok());
        assert!(validate_desktop_params(
            "desktop.shell.run",
            &serde_json::json!({ "argv": ["/bin/sh", "-c", "id"] }),
            &rules
        )
        .is_err());
    }
}
