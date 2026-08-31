//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! End-to-end integration tests (require PostgreSQL).
//!
//! Run: `E2E=1 DATABASE_URL=postgres://hecate:hecate@localhost:5432/hecate cargo test -p hecate-api --test e2e -- --ignored`

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::json;
use uuid::Uuid;

fn e2e_enabled() -> bool {
    std::env::var("E2E").ok().as_deref() == Some("1")
}

fn base_url() -> String {
    std::env::var("HECATE_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".into())
}

fn env_or_skip(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    if value.trim().is_empty() {
        return None;
    }
    Some(value)
}

#[tokio::test]
#[ignore = "requires running Hecate API + PostgreSQL (E2E=1)"]
async fn bootstrap_and_status() {
    if !e2e_enabled() {
        return;
    }
    let client = Client::new();
    let status: serde_json::Value = client
        .get(format!("{}/api/v1/auth/status", base_url()))
        .send()
        .await
        .expect("status")
        .json()
        .await
        .expect("json");
    assert!(status.get("bootstrap_required").is_some());
}

#[tokio::test]
#[ignore = "requires running Hecate API + PostgreSQL (E2E=1)"]
async fn bootstrap_admin_flow() {
    if !e2e_enabled() {
        return;
    }
    let client = Client::new();
    let login = format!("admin_{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{}/api/v1/auth/bootstrap", base_url()))
        .json(&json!({ "login": login, "password": "securepassword123" }))
        .send()
        .await
        .expect("bootstrap");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["role"], "admin");
}

#[tokio::test]
#[ignore = "requires MCP + API stack (E2E=1, E2E_INTERNAL_TOKEN, E2E_AI_API_KEY, E2E_MACHINE_ID)"]
async fn mcp_async_command_flow() {
    if !e2e_enabled() {
        return;
    }

    let internal_token = match env_or_skip("E2E_INTERNAL_TOKEN") {
        Some(value) => value,
        None => {
            eprintln!("skip mcp_async_command_flow: set E2E_INTERNAL_TOKEN");
            return;
        }
    };
    let api_key = match env_or_skip("E2E_AI_API_KEY") {
        Some(value) => value,
        None => {
            eprintln!("skip mcp_async_command_flow: set E2E_AI_API_KEY");
            return;
        }
    };
    let machine_id = match env_or_skip("E2E_MACHINE_ID") {
        Some(value) => value,
        None => {
            eprintln!("skip mcp_async_command_flow: set E2E_MACHINE_ID");
            return;
        }
    };

    let client = Client::new();
    let enqueue = client
        .post(format!("{}/internal/commands", base_url()))
        .header("x-internal-token", &internal_token)
        .header("x-ai-api-key", &api_key)
        .json(&json!({
            "machine_id": machine_id,
            "command_name": "system.info",
            "params": {},
            "wait": false,
        }))
        .send()
        .await
        .expect("enqueue");

    assert!(enqueue.status().is_success(), "enqueue failed: {}", enqueue.status());
    let body: serde_json::Value = enqueue.json().await.expect("enqueue json");
    let command_id = body["command_id"]
        .as_str()
        .expect("command_id in enqueue response");

    let detail = client
        .get(format!(
            "{}/internal/commands/{}?wait=1&wait_timeout_secs=30",
            base_url(),
            command_id
        ))
        .header("x-internal-token", &internal_token)
        .header("x-ai-api-key", &api_key)
        .send()
        .await
        .expect("get command");

    assert!(detail.status().is_success(), "get command failed: {}", detail.status());
    let command: serde_json::Value = detail.json().await.expect("command json");
    assert_eq!(command["command_id"], command_id);
    assert!(
        matches!(
            command["status"].as_str(),
            Some("completed") | Some("failed")
        ),
        "wait should return a terminal status, got: {:?}",
        command["status"]
    );
}

#[tokio::test]
#[ignore = "requires agent + API (E2E=1, E2E_ENROLLMENT_TOKEN)"]
async fn agent_enroll_flow() {
    if !e2e_enabled() {
        return;
    }

    let enrollment_token = match env_or_skip("E2E_ENROLLMENT_TOKEN") {
        Some(value) => value,
        None => {
            eprintln!("skip agent_enroll_flow: set E2E_ENROLLMENT_TOKEN");
            return;
        }
    };

    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = BASE64.encode(signing_key.verifying_key().to_bytes());

    let client = Client::new();
    let resp = client
        .post(format!("{}/api/v1/agent/enroll", base_url()))
        .json(&json!({
            "enrollment_token": enrollment_token,
            "public_key": public_key,
            "hostname": format!("e2e-{}", Uuid::new_v4().simple()),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "tags": [],
            "attestation": {},
        }))
        .send()
        .await
        .expect("enroll");

    assert!(resp.status().is_success(), "enroll failed: {}", resp.status());
    let body: serde_json::Value = resp.json().await.expect("enroll json");
    assert!(body.get("agent_id").is_some());
    assert!(body.get("machine_id").is_some());
    assert!(body.get("state").is_some());
    assert!(
        body.get("task_signing_pubkey_b64")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
    );
    // release_public_key_b64 may be omitted when the server has no signing key configured.
    if let Some(key) = body.get("release_public_key_b64") {
        assert!(key.as_str().is_some_and(|s| !s.is_empty()) || key.is_null());
    }
}

#[tokio::test]
#[ignore = "requires MCP + API stack (E2E=1, E2E_INTERNAL_TOKEN, E2E_AI_API_KEY)"]
async fn internal_command_artifact_upload_flow() {
    if !e2e_enabled() {
        return;
    }

    let internal_token = match env_or_skip("E2E_INTERNAL_TOKEN") {
        Some(value) => value,
        None => {
            eprintln!("skip internal_command_artifact_upload_flow: set E2E_INTERNAL_TOKEN");
            return;
        }
    };
    let api_key = match env_or_skip("E2E_AI_API_KEY") {
        Some(value) => value,
        None => {
            eprintln!("skip internal_command_artifact_upload_flow: set E2E_AI_API_KEY");
            return;
        }
    };

    let client = Client::new();
    let body = b"hello-hecate-artifact";
    let upload = client
        .post(format!("{}/internal/command-artifacts", base_url()))
        .header("x-internal-token", &internal_token)
        .header("x-ai-api-key", &api_key)
        .header("x-filename", "test.txt")
        .header("content-type", "application/octet-stream")
        .body(body.to_vec())
        .send()
        .await
        .expect("upload artifact");

    assert!(
        upload.status().is_success(),
        "artifact upload failed: {}",
        upload.status()
    );
    let payload: serde_json::Value = upload.json().await.expect("upload json");
    assert!(payload.get("artifact_id").is_some());
    assert!(payload.get("sha256").is_some());
    assert_eq!(payload["size_bytes"], body.len() as i64);
}
