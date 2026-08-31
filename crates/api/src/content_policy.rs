//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Content-policy scanner and AI lockout for illicit script/payload content.

use hecate_protocol::permissions::{CapabilityProfileRules, ALLOWLIST_WILDCARD};
use hecate_protocol::policy;
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::append_audit;
use crate::error::{ApiError, ApiResult};
use crate::server_settings;

const FIRST_VIOLATION_MESSAGE: &str = "content rejected because it does not fit granted permissions; a second attempt will lock this AI identity";
const LOCKOUT_MESSAGE: &str = "AI identity temporarily locked due to content policy violation; contact an administrator";
const MAX_SCAN_BYTES: usize = 512 * 1024;
const MAX_DECODE_PASSES: usize = 2;

#[derive(Debug, Clone, sqlx::FromRow)]
struct ContentPolicyState {
    violation_count: i32,
    locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn ensure_not_locked(pool: &PgPool, ai_identity_id: Uuid) -> ApiResult<()> {
    if let Some(state) = load_state(pool, ai_identity_id).await? {
        if let Some(until) = state.locked_until {
            if until > chrono::Utc::now() {
                return Err(ApiError::ForbiddenMessage(LOCKOUT_MESSAGE.into()));
            }
        }
    }
    Ok(())
}

pub async fn clear_lockout(pool: &PgPool, ai_identity_id: Uuid) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO ai_content_policy_state (ai_identity_id, violation_count, locked_until, last_violation_at, updated_at)
         VALUES ($1, 0, NULL, NULL, now())
         ON CONFLICT (ai_identity_id) DO UPDATE
         SET violation_count = 0, locked_until = NULL, updated_at = now()",
    )
    .bind(ai_identity_id)
    .execute(pool)
    .await?;
    append_audit(
        pool,
        "admin",
        "ai.content_policy.lockout_cleared",
        &ai_identity_id.to_string(),
        "",
        &serde_json::json!({}),
    )
    .await?;
    Ok(())
}

/// Scan command params / artifact bytes. On violation, record strike and return AI-facing error.
pub async fn enforce_content_policy(
    pool: &PgPool,
    ai_identity_id: Uuid,
    rules: &CapabilityProfileRules,
    command_name: &str,
    params: &serde_json::Value,
    artifact_bytes: Option<&[u8]>,
) -> ApiResult<()> {
    ensure_not_locked(pool, ai_identity_id).await?;

    let mut findings = Vec::new();
    if let Some(bytes) = artifact_bytes {
        if let Err(reason) = scan_bytes(bytes, rules) {
            findings.push(reason);
        }
    }
    if let Err(reason) = scan_params(command_name, params, rules) {
        findings.push(reason);
    }
    if findings.is_empty() {
        return Ok(());
    }

    record_violation(pool, ai_identity_id, command_name, &findings).await
}

fn scan_params(
    command_name: &str,
    params: &serde_json::Value,
    rules: &CapabilityProfileRules,
) -> Result<(), String> {
    if matches!(command_name, "shell.run" | "desktop.shell.run") {
        if let Some(argv) = params.get("argv").and_then(|v| v.as_array()) {
            let joined: Vec<String> = argv
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            detect_decode_pipeline(&joined)?;
            for arg in &joined {
                scan_text(arg, rules)?;
            }
        }
    }
    if let Some(text) = params.get("text").and_then(|v| v.as_str()) {
        scan_text(text, rules)?;
    }
    if let Some(content) = params.get("content").and_then(|v| v.as_str()) {
        scan_text(content, rules)?;
    }
    Ok(())
}

fn detect_decode_pipeline(argv: &[String]) -> Result<(), String> {
    let lower: Vec<String> = argv.iter().map(|s| s.to_ascii_lowercase()).collect();
    let has_decode = lower.iter().any(|a| {
        a.contains("base64") || a == "-d" || a == "--decode" || a.contains("openssl")
    });
    let has_interpreter = lower.iter().any(|a| {
        a.ends_with("/sh")
            || a.ends_with("/bash")
            || a.ends_with("/zsh")
            || a.ends_with("/python")
            || a.ends_with("/python3")
            || a.ends_with("/perl")
            || a.ends_with("/ruby")
            || a == "sh"
            || a == "bash"
            || a == "python"
            || a == "python3"
    });
    if has_decode && has_interpreter {
        return Err("decode-to-interpreter pipeline is not allowed".into());
    }
    Ok(())
}

fn scan_bytes(bytes: &[u8], rules: &CapabilityProfileRules) -> Result<(), String> {
    let capped = if bytes.len() > MAX_SCAN_BYTES {
        &bytes[..MAX_SCAN_BYTES]
    } else {
        bytes
    };
    // Skip dense binary (non-text) except for embedded printable strings.
    let text = String::from_utf8_lossy(capped);
    scan_text(&text, rules)?;
    let mut current = capped.to_vec();
    for _ in 0..MAX_DECODE_PASSES {
        if let Some(decoded) = try_decode_payload(&current) {
            let decoded_text = String::from_utf8_lossy(&decoded);
            scan_text(&decoded_text, rules)?;
            current = decoded;
        } else {
            break;
        }
    }
    Ok(())
}

fn scan_text(text: &str, rules: &CapabilityProfileRules) -> Result<(), String> {
    let allowed = &rules.shell_policy.allowed_binaries;
    if policy::allowlist_has_wildcard(allowed) {
        // Still block elevation wrappers as content.
        for wrapper in ["/usr/bin/sudo", "/bin/sudo", "sudo", "pkexec"] {
            if text.contains(wrapper) {
                return Err(format!("content references forbidden wrapper: {wrapper}"));
            }
        }
        return Ok(());
    }
    // Tokenize on whitespace and common separators.
    for raw in text.split(|c: char| {
        c.is_whitespace() || matches!(c, ';' | '|' | '&' | '`' | '$' | '(' | ')' | '"' | '\'')
    }) {
        let token = raw.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | ','));
        if token.is_empty() {
            continue;
        }
        if looks_like_binary_ref(token) && !binary_allowed(token, allowed) {
            return Err(format!("content references disallowed binary: {token}"));
        }
    }
    Ok(())
}

fn looks_like_binary_ref(token: &str) -> bool {
    token.starts_with('/')
        || (token.len() >= 3
            && token.as_bytes()[0].is_ascii_alphabetic()
            && token.as_bytes()[1] == b':'
            && (token.as_bytes()[2] == b'\\' || token.as_bytes()[2] == b'/'))
        || matches!(
            token,
            "sh" | "bash"
                | "zsh"
                | "dash"
                | "python"
                | "python3"
                | "perl"
                | "ruby"
                | "node"
                | "curl"
                | "wget"
                | "sudo"
                | "pkexec"
        )
}

fn binary_allowed(token: &str, allowed: &[String]) -> bool {
    if allowed.iter().any(|entry| entry == ALLOWLIST_WILDCARD) {
        return true;
    }
    let canon = policy::canonicalize_binary(token);
    allowed
        .iter()
        .map(|p| policy::canonicalize_binary(p))
        .any(|allowed_bin| allowed_bin == canon || allowed_bin.ends_with(&format!("/{canon}")) || canon.ends_with(&format!("/{allowed_bin}")))
}

fn try_decode_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() < 16 {
        return None;
    }
    // Prefer base64.
    if let Ok(decoded) = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        text.as_bytes(),
    ) {
        if decoded.len() > 8 {
            return Some(decoded);
        }
    }
    // Hex
    if text.len() % 2 == 0 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = Vec::with_capacity(text.len() / 2);
        let chars: Vec<char> = text.chars().collect();
        for chunk in chars.chunks(2) {
            let byte = u8::from_str_radix(&format!("{}{}", chunk[0], chunk[1]), 16).ok()?;
            out.push(byte);
        }
        if out.len() > 8 {
            return Some(out);
        }
    }
    None
}

async fn load_state(pool: &PgPool, ai_identity_id: Uuid) -> ApiResult<Option<ContentPolicyState>> {
    sqlx::query_as::<_, ContentPolicyState>(
        "SELECT violation_count, locked_until FROM ai_content_policy_state WHERE ai_identity_id = $1",
    )
    .bind(ai_identity_id)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

async fn record_violation(
    pool: &PgPool,
    ai_identity_id: Uuid,
    command_name: &str,
    findings: &[String],
) -> ApiResult<()> {
    let lockout_secs = server_settings::content_policy_lockout_seconds(pool).await?;
    let existing = load_state(pool, ai_identity_id).await?;
    let prior = existing
        .as_ref()
        .map(|s| {
            // Reset strikes if previous lockout already expired.
            if s.locked_until
                .map(|until| until <= chrono::Utc::now())
                .unwrap_or(false)
                && s.violation_count >= 2
            {
                0
            } else {
                s.violation_count
            }
        })
        .unwrap_or(0);
    let next = prior + 1;
    let locked_until = if next >= 2 {
        Some(chrono::Utc::now() + chrono::Duration::seconds(lockout_secs as i64))
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO ai_content_policy_state (ai_identity_id, violation_count, locked_until, last_violation_at, updated_at)
         VALUES ($1, $2, $3, now(), now())
         ON CONFLICT (ai_identity_id) DO UPDATE
         SET violation_count = EXCLUDED.violation_count,
             locked_until = EXCLUDED.locked_until,
             last_violation_at = now(),
             updated_at = now()",
    )
    .bind(ai_identity_id)
    .bind(next)
    .bind(locked_until)
    .execute(pool)
    .await?;

    append_audit(
        pool,
        "ai",
        if next >= 2 {
            "ai.content_policy.lockout"
        } else {
            "ai.content_policy.violation"
        },
        &ai_identity_id.to_string(),
        "",
        &serde_json::json!({
            "command": command_name,
            "findings": findings,
            "violation_count": next,
            "locked": next >= 2,
            // Admin-only detail; never returned to AI clients.
            "locked_until": locked_until,
        }),
    )
    .await?;

    if next >= 2 {
        Err(ApiError::ForbiddenMessage(LOCKOUT_MESSAGE.into()))
    } else {
        Err(ApiError::BadRequest(FIRST_VIOLATION_MESSAGE.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::permissions::{CapabilityProfileRules, ShellPolicy};

    fn rules_with_bins(bins: &[&str]) -> CapabilityProfileRules {
        CapabilityProfileRules {
            allowed_commands: vec!["shell.run".into()],
            allowed_admin_commands: vec![],
            shell_policy: ShellPolicy {
                allowed_binaries: bins.iter().map(|s| (*s).to_string()).collect(),
                allowed_cwd: vec!["/tmp".into()],
                allowed_env: vec![],
            },
            elevation_policy: Default::default(),
            max_output_bytes: hecate_protocol::permissions::DEFAULT_MAX_OUTPUT_BYTES,
            max_file_bytes: hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES,
            timeout_secs: hecate_protocol::permissions::DEFAULT_TIMEOUT_SECS,
            max_concurrent: hecate_protocol::permissions::DEFAULT_MAX_CONCURRENT,
        }
    }

    #[test]
    fn rejects_disallowed_binary_in_script() {
        let rules = rules_with_bins(&["/usr/bin/echo"]);
        assert!(scan_text("#!/bin/sh\n/bin/bash -c id\n", &rules).is_err());
    }

    #[test]
    fn accepts_allowlisted_binary_in_script() {
        let rules = rules_with_bins(&["/usr/bin/echo", "/usr/bin/uptime"]);
        assert!(scan_text("#!/usr/bin/env\n/usr/bin/uptime\n", &rules).is_ok());
    }

    #[test]
    fn rejects_decode_pipeline() {
        assert!(detect_decode_pipeline(&[
            "/usr/bin/base64".into(),
            "-d".into(),
            "|".into(),
            "/bin/sh".into()
        ])
        .is_err());
    }
}
