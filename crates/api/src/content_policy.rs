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
const DESKTOP_INPUT_BUFFER_CAP: usize = 256;
const DESKTOP_INPUT_BUFFER_TTL_SECS: i64 = 300;

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
    machine_id: Option<Uuid>,
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

    if let Some(machine_id) = machine_id {
        if command_name == "desktop.window.focus" {
            clear_desktop_input_buffer(pool, ai_identity_id, machine_id).await?;
        } else if matches!(
            command_name,
            "desktop.type" | "desktop.key" | "desktop.session.input"
        ) {
            match append_and_scan_desktop_input_buffer(
                pool,
                ai_identity_id,
                machine_id,
                command_name,
                params,
                rules,
            )
            .await
            {
                Ok(()) => {}
                Err(reason) => findings.push(reason),
            }
        }
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
    if let Some(app) = params.get("app").and_then(|v| v.as_str()) {
        scan_text(app, rules)?;
    }
    if let Some(args) = params.get("args").and_then(|v| v.as_array()) {
        let joined: Vec<String> = args
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        detect_decode_pipeline(&joined)?;
        for arg in &joined {
            scan_text(arg, rules)?;
        }
    }
    if let Some(text) = params.get("text").and_then(|v| v.as_str()) {
        scan_text(text, rules)?;
    }
    if let Some(content) = params.get("content").and_then(|v| v.as_str()) {
        scan_text(content, rules)?;
    }
    if let Some(key) = params.get("key").and_then(|v| v.as_str()) {
        scan_text(key, rules)?;
    }
    if command_name == "desktop.session.input" {
        if let Some(events) = params.get("events").and_then(|v| v.as_array()) {
            for event in events {
                if let Some(text) = event.get("text").and_then(|v| v.as_str()) {
                    scan_text(text, rules)?;
                }
                if let Some(key) = event.get("key").and_then(|v| v.as_str()) {
                    scan_text(key, rules)?;
                }
            }
        }
    }
    Ok(())
}

fn collect_desktop_input_chars(command_name: &str, params: &serde_json::Value) -> String {
    let mut out = String::new();
    match command_name {
        "desktop.type" => {
            if let Some(text) = params.get("text").and_then(|v| v.as_str()) {
                out.push_str(text);
            }
        }
        "desktop.key" => {
            if let Some(chunk) = printable_key_chunk(params.get("key").and_then(|v| v.as_str())) {
                out.push_str(&chunk);
            }
        }
        "desktop.session.input" => {
            if let Some(events) = params.get("events").and_then(|v| v.as_array()) {
                for event in events {
                    let action = event.get("action").and_then(|v| v.as_str()).unwrap_or("");
                    match action {
                        "type" => {
                            if let Some(text) = event.get("text").and_then(|v| v.as_str()) {
                                out.push_str(text);
                            }
                        }
                        "key" => {
                            if let Some(chunk) =
                                printable_key_chunk(event.get("key").and_then(|v| v.as_str()))
                            {
                                out.push_str(&chunk);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn printable_key_chunk(key: Option<&str>) -> Option<String> {
    let key = key?.trim();
    if key.is_empty() {
        return None;
    }
    // Single Unicode grapheme / character — character-by-character typing.
    if key.chars().count() == 1 {
        return Some(key.to_string());
    }
    // Named keys (Return, F1, Escape, …) do not contribute to the text buffer.
    None
}

async fn clear_desktop_input_buffer(
    pool: &PgPool,
    ai_identity_id: Uuid,
    machine_id: Uuid,
) -> ApiResult<()> {
    sqlx::query(
        "DELETE FROM ai_desktop_input_buffers
         WHERE ai_identity_id = $1 AND machine_id = $2",
    )
    .bind(ai_identity_id)
    .bind(machine_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn append_and_scan_desktop_input_buffer(
    pool: &PgPool,
    ai_identity_id: Uuid,
    machine_id: Uuid,
    command_name: &str,
    params: &serde_json::Value,
    rules: &CapabilityProfileRules,
) -> Result<(), String> {
    let chunk = collect_desktop_input_chars(command_name, params);
    if chunk.is_empty() {
        // Still scan existing buffer (e.g. Return after typing a LOLBin name).
        let existing = load_desktop_input_buffer(pool, ai_identity_id, machine_id)
            .await
            .map_err(|e| format!("desktop input buffer load failed: {e:?}"))?;
        if !existing.is_empty() {
            scan_text(&existing, rules)?;
        }
        return Ok(());
    }

    let previous = load_desktop_input_buffer(pool, ai_identity_id, machine_id)
        .await
        .map_err(|e| format!("desktop input buffer load failed: {e:?}"))?;
    let mut combined = previous;
    combined.push_str(&chunk);
    combined = truncate_desktop_input_buffer(combined, DESKTOP_INPUT_BUFFER_CAP);
    // Persist before scanning so fragmented typing remains visible across requests.
    persist_desktop_input_buffer(pool, ai_identity_id, machine_id, &combined)
        .await
        .map_err(|e| format!("desktop input buffer persist failed: {e:?}"))?;
    scan_text(&combined, rules)?;
    Ok(())
}

/// Keep at most `max_bytes` of UTF-8, dropping from the front on a char boundary.
fn truncate_desktop_input_buffer(s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let mut start = s.len() - max_bytes;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    s[start..].to_string()
}

async fn load_desktop_input_buffer(
    pool: &PgPool,
    ai_identity_id: Uuid,
    machine_id: Uuid,
) -> ApiResult<String> {
    let row: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT buffer, updated_at FROM ai_desktop_input_buffers
         WHERE ai_identity_id = $1 AND machine_id = $2",
    )
    .bind(ai_identity_id)
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;
    let Some((buffer, updated_at)) = row else {
        return Ok(String::new());
    };
    let age = chrono::Utc::now().signed_duration_since(updated_at);
    if age.num_seconds() > DESKTOP_INPUT_BUFFER_TTL_SECS {
        clear_desktop_input_buffer(pool, ai_identity_id, machine_id).await?;
        return Ok(String::new());
    }
    Ok(buffer)
}

async fn persist_desktop_input_buffer(
    pool: &PgPool,
    ai_identity_id: Uuid,
    machine_id: Uuid,
    buffer: &str,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO ai_desktop_input_buffers (ai_identity_id, machine_id, buffer, updated_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (ai_identity_id, machine_id) DO UPDATE
         SET buffer = EXCLUDED.buffer, updated_at = now()",
    )
    .bind(ai_identity_id)
    .bind(machine_id)
    .bind(buffer)
    .execute(pool)
    .await?;
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
            || a.ends_with("/osascript")
            || a.ends_with("/swift")
            || a.ends_with("/node")
            || a.ends_with("/php")
            || a.ends_with("/lua")
            || a.ends_with("/tclsh")
            || a.ends_with("\\cmd.exe")
            || a.ends_with("/cmd.exe")
            || a.ends_with("\\powershell.exe")
            || a.ends_with("/powershell.exe")
            || a.ends_with("\\pwsh.exe")
            || a.ends_with("/pwsh.exe")
            || a == "sh"
            || a == "bash"
            || a == "python"
            || a == "python3"
            || a == "perl"
            || a == "ruby"
            || a == "osascript"
            || a == "swift"
            || a == "node"
            || a == "php"
            || a == "lua"
            || a == "tclsh"
            || a == "cmd"
            || a == "cmd.exe"
            || a == "powershell"
            || a == "powershell.exe"
            || a == "pwsh"
            || a == "pwsh.exe"
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
    if token.starts_with('/')
        || (token.len() >= 3
            && token.as_bytes()[0].is_ascii_alphabetic()
            && token.as_bytes()[1] == b':'
            && (token.as_bytes()[2] == b'\\' || token.as_bytes()[2] == b'/'))
    {
        return true;
    }
    let lower = token.to_ascii_lowercase();
    matches!(
        lower.as_str(),
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
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "cmd"
            | "cmd.exe"
            | "cscript"
            | "cscript.exe"
            | "wscript"
            | "wscript.exe"
            | "mshta"
            | "mshta.exe"
            | "regsvr32"
            | "regsvr32.exe"
            | "rundll32"
            | "rundll32.exe"
            | "certutil"
            | "certutil.exe"
            | "bitsadmin"
            | "bitsadmin.exe"
            | "net"
            | "net.exe"
            | "reg"
            | "reg.exe"
            | "sc"
            | "sc.exe"
            | "schtasks"
            | "schtasks.exe"
            // macOS + missing Unix interpreters / LOLBins (content-scan deny-by-detection)
            | "osascript"
            | "osacompile"
            | "swift"
            | "jsc"
            | "xcrun"
            | "php"
            | "lua"
            | "luajit"
            | "tclsh"
            | "wish"
            | "expect"
            | "awk"
            | "gawk"
            | "nawk"
            | "ksh"
            | "tcsh"
            | "csh"
            | "fish"
            | "java"
            | "jshell"
            | "jrunscript"
            | "automator"
            | "open"
            | "launchctl"
            | "caffeinate"
            | "xargs"
            | "find"
            | "env"
            | "nohup"
            | "nice"
            | "stdbuf"
            | "script"
            | "tmux"
            | "screen"
            | "make"
            | "ssh"
            | "sshpass"
            | "at"
            | "atrun"
            | "crontab"
            | "watch"
            | "sqlite3"
            | "dtrace"
            | "dtruss"
            | "dscl"
            | "dseditgroup"
            | "sysadminctl"
            | "createhomedir"
            | "security"
            | "installer"
            | "profiles"
            | "defaults"
            | "nc"
            | "ncat"
            | "netcat"
            | "socat"
            | "ftp"
            | "tftp"
            | "ditto"
            | "hdiutil"
            | "bsdtar"
            | "unzip"
            | "gunzip"
            | "xxd"
            | "uudecode"
            | "screencapture"
            | "pbpaste"
            | "pbcopy"
            | "mdfind"
            | "xattr"
            | "spctl"
            | "codesign"
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
            desktop_policy: Default::default(),
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
    fn rejects_windows_lolbins_in_typed_text() {
        let rules = rules_with_bins(&["id", "whoami", "hostname", "echo"]);
        assert!(scan_text("powershell -Command Write-Output ok", &rules).is_err());
        assert!(scan_text("cmd.exe /c echo ok", &rules).is_err());
        assert!(scan_text("Pwsh -File run.ps1", &rules).is_err());
        assert!(scan_text("echo hello world", &rules).is_ok());
    }

    #[test]
    fn rejects_disallowed_app_in_launch_params() {
        let rules = rules_with_bins(&["id", "whoami", "hostname", "echo"]);
        assert!(scan_params(
            "desktop.app.launch",
            &serde_json::json!({ "app": "cmd.exe" }),
            &rules
        )
        .is_err());
        assert!(scan_params(
            "desktop.app.launch",
            &serde_json::json!({ "app": "echo", "args": ["hello"] }),
            &rules
        )
        .is_ok());
    }

    #[test]
    fn rejects_nested_session_input_text() {
        let rules = rules_with_bins(&["id", "whoami", "hostname", "echo"]);
        assert!(scan_params(
            "desktop.type",
            &serde_json::json!({ "text": "bash" }),
            &rules
        )
        .is_err());
        assert!(scan_params(
            "desktop.session.input",
            &serde_json::json!({
                "session_id": "00000000-0000-4000-8000-000000000001",
                "events": [{ "action": "type", "text": "bash" }]
            }),
            &rules
        )
        .is_err());
    }

    #[test]
    fn scans_desktop_key_field() {
        let rules = rules_with_bins(&["id", "whoami", "hostname", "echo"]);
        assert!(scan_params(
            "desktop.key",
            &serde_json::json!({ "key": "powershell" }),
            &rules
        )
        .is_err());
        assert!(scan_params(
            "desktop.key",
            &serde_json::json!({ "key": "Return" }),
            &rules
        )
        .is_ok());
    }

    #[test]
    fn collect_desktop_input_chars_from_key_and_type() {
        assert_eq!(
            collect_desktop_input_chars(
                "desktop.key",
                &serde_json::json!({ "key": "p" })
            ),
            "p"
        );
        assert_eq!(
            collect_desktop_input_chars(
                "desktop.key",
                &serde_json::json!({ "key": "Return" })
            ),
            ""
        );
        assert_eq!(
            collect_desktop_input_chars(
                "desktop.type",
                &serde_json::json!({ "text": "power" })
            ),
            "power"
        );
        assert_eq!(
            collect_desktop_input_chars(
                "desktop.session.input",
                &serde_json::json!({
                    "events": [
                        { "action": "type", "text": "sh" },
                        { "action": "key", "key": "e" },
                        { "action": "key", "key": "Return" }
                    ]
                })
            ),
            "she"
        );
    }

    #[test]
    fn truncate_desktop_input_buffer_respects_utf8_boundaries() {
        // € is 3 bytes in UTF-8. "aaa" (3) + 86×€ (258) = 261 bytes.
        // A naive byte slice at excess would land mid-character and panic.
        let mut s = String::from("aaa");
        for _ in 0..86 {
            s.push('€');
        }
        assert!(s.len() > DESKTOP_INPUT_BUFFER_CAP);
        let trimmed = truncate_desktop_input_buffer(s, DESKTOP_INPUT_BUFFER_CAP);
        assert!(trimmed.len() <= DESKTOP_INPUT_BUFFER_CAP);
        assert!(trimmed.is_char_boundary(0));
        assert!(trimmed.chars().all(|c| c == '€' || c == 'a'));
        // Must not start mid-€ (would be invalid UTF-8 / panic above).
        assert!(trimmed.starts_with('€') || trimmed.starts_with('a'));
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

    #[test]
    fn rejects_windows_decode_pipeline() {
        assert!(detect_decode_pipeline(&[
            "base64".into(),
            "-d".into(),
            "|".into(),
            "powershell".into(),
        ])
        .is_err());
        assert!(detect_decode_pipeline(&[
            "base64".into(),
            "-d".into(),
            "|".into(),
            "cmd.exe".into(),
        ])
        .is_err());
    }

    #[test]
    fn rejects_macos_binaries_in_desktop_input() {
        let rules = rules_with_bins(&["id", "whoami", "hostname", "echo"]);
        let rejected = [
            "osascript",
            "open",
            "open -b com.apple.Terminal",
            "swift",
            "osacompile",
            "automator",
            "launchctl",
            "dseditgroup",
            "sysadminctl",
            "security",
            "sqlite3",
            "screencapture",
            "xattr",
            "hdiutil",
            "installer",
            "OSASCRIPT",
        ];
        for text in rejected {
            assert!(
                scan_params("desktop.type", &serde_json::json!({ "text": text }), &rules).is_err(),
                "desktop.type should reject {text}"
            );
            // Single-token key field (multi-word strings are typed via desktop.type).
            if !text.contains(' ') {
                assert!(
                    scan_params("desktop.key", &serde_json::json!({ "key": text }), &rules)
                        .is_err(),
                    "desktop.key should reject {text}"
                );
            }
            assert!(
                scan_params(
                    "desktop.session.input",
                    &serde_json::json!({
                        "session_id": "00000000-0000-4000-8000-000000000001",
                        "events": [{ "action": "type", "text": text }]
                    }),
                    &rules
                )
                .is_err(),
                "desktop.session.input should reject {text}"
            );
        }
    }

    #[test]
    fn accepts_allowlisted_macos_typed_text() {
        let rules = rules_with_bins(&["id", "whoami", "hostname", "echo"]);
        for text in ["echo hello world", "id", "whoami"] {
            assert!(
                scan_params("desktop.type", &serde_json::json!({ "text": text }), &rules).is_ok(),
                "desktop.type should accept {text}"
            );
        }
    }

    #[test]
    fn rejects_osascript_reassembled_from_key_buffer() {
        let rules = rules_with_bins(&["id", "whoami", "hostname", "echo"]);
        let mut buffer = String::new();
        for ch in ["o", "s", "a", "s", "c", "r", "i", "p", "t"] {
            buffer.push_str(&collect_desktop_input_chars(
                "desktop.key",
                &serde_json::json!({ "key": ch }),
            ));
        }
        assert_eq!(buffer, "osascript");
        assert!(scan_text(&buffer, &rules).is_err());
    }

    #[test]
    fn rejects_macos_decode_pipeline() {
        assert!(detect_decode_pipeline(&[
            "/bin/sh".into(),
            "-c".into(),
            "base64 -d x | osascript".into(),
        ])
        .is_err());
        assert!(detect_decode_pipeline(&[
            "base64".into(),
            "-d".into(),
            "|".into(),
            "osascript".into(),
        ])
        .is_err());
        assert!(detect_decode_pipeline(&[
            "base64".into(),
            "-d".into(),
            "|".into(),
            "/usr/bin/swift".into(),
        ])
        .is_err());
    }
}
