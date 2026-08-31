//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::header::{HeaderMap, HeaderValue, COOKIE};
use serde_json::{json, Map, Value};

#[derive(Parser)]
#[command(name = "hecate", version, about = "Operate a Hecate server")]
struct Cli {
    #[arg(long, env = "HECATE_URL", default_value = "http://127.0.0.1:8080")]
    url: String,
    #[arg(long, env = "HECATE_TOKEN", hide_env_values = true)]
    token: Option<String>,
    #[arg(long, env = "HECATE_INTERNAL_TOKEN", hide_env_values = true)]
    internal_token: Option<String>,
    #[arg(long, env = "HECATE_SESSION_COOKIE", hide_env_values = true)]
    session_cookie: Option<String>,
    #[arg(long, env = "HECATE_CSRF_TOKEN", hide_env_values = true)]
    csrf_token: Option<String>,
    #[command(subcommand)]
    command: RootCommand,
}

#[derive(Subcommand)]
enum RootCommand {
    Repo(RepoArgs),
}

#[derive(Args)]
struct RepoArgs {
    #[command(subcommand)]
    command: RepoCommand,
}

#[derive(Subcommand)]
enum RepoCommand {
    Sources(SourcesArgs),
    List,
    Install(FeatureSelection),
    Upgrade(UpgradeArgs),
    UpgradeAll,
    Pin(PinArgs),
    Unpin(FeatureId),
    Uninstall(FeatureId),
    Status,
    Refresh,
}

#[derive(Args)]
struct SourcesArgs {
    #[command(subcommand)]
    command: SourcesCommand,
}

#[derive(Subcommand)]
enum SourcesCommand {
    List,
    Add(AddSourceArgs),
    Update(UpdateSourceArgs),
    Enable(SourceId),
    Disable(SourceId),
    Remove(RemoveSourceArgs),
}

#[derive(Args)]
struct SourceId {
    id: String,
}

#[derive(Args)]
struct RemoveSourceArgs {
    id: String,
}

#[derive(Args)]
struct AddSourceArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    url: String,
    #[arg(long)]
    public_key_b64: String,
    #[arg(long, default_value_t = 0)]
    priority: i32,
}

#[derive(Args)]
struct UpdateSourceArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    public_key_b64: Option<String>,
    #[arg(long)]
    priority: Option<i32>,
}

#[derive(Args)]
struct FeatureId {
    id: String,
}

#[derive(Args)]
struct FeatureSelection {
    id: String,
    #[arg(long)]
    version: Option<String>,
    #[arg(long)]
    source_id: Option<String>,
}

#[derive(Args)]
struct UpgradeArgs {
    id: String,
    #[arg(long)]
    version: Option<String>,
}

#[derive(Args)]
struct PinArgs {
    id: String,
    #[arg(long)]
    version: String,
}

enum Authentication {
    Internal {
        internal_token: String,
        api_key: String,
    },
    Session {
        cookie: String,
        csrf_token: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let auth = match (
        cli.internal_token,
        cli.token,
        cli.session_cookie,
        cli.csrf_token,
    ) {
        (Some(internal_token), Some(api_key), _, _) => Authentication::Internal {
            internal_token,
            api_key,
        },
        (_, _, Some(cookie), Some(csrf_token)) => Authentication::Session { cookie, csrf_token },
        _ => bail!(
            "set HECATE_INTERNAL_TOKEN and HECATE_TOKEN, or HECATE_SESSION_COOKIE and HECATE_CSRF_TOKEN"
        ),
    };

    let (command, params) = map_command(cli.command)?;
    let result = execute(&cli.url, auth, command, params).await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn map_command(command: RootCommand) -> Result<(&'static str, Value)> {
    let RootCommand::Repo(repo) = command;
    let mapped = match repo.command {
        RepoCommand::Sources(sources) => match sources.command {
            SourcesCommand::List => ("admin.repo.sources.list", json!({})),
            SourcesCommand::Add(args) => (
                "admin.repo.sources.add",
                json!({
                    "id": args.id,
                    "url": args.url,
                    "public_key_b64": args.public_key_b64,
                    "priority": args.priority,
                }),
            ),
            SourcesCommand::Update(args) => {
                if args.url.is_none() && args.public_key_b64.is_none() && args.priority.is_none() {
                    bail!("provide at least one of --url, --public-key-b64, or --priority");
                }
                let mut params = json!({ "id": args.id });
                let object = params.as_object_mut().expect("object");
                if let Some(url) = args.url {
                    object.insert("url".into(), Value::String(url));
                }
                if let Some(public_key_b64) = args.public_key_b64 {
                    object.insert("public_key_b64".into(), Value::String(public_key_b64));
                }
                if let Some(priority) = args.priority {
                    object.insert("priority".into(), json!(priority));
                }
                ("admin.repo.sources.update", params)
            }
            SourcesCommand::Enable(args) => ("admin.repo.sources.enable", json!({ "id": args.id })),
            SourcesCommand::Disable(args) => {
                ("admin.repo.sources.disable", json!({ "id": args.id }))
            }
            SourcesCommand::Remove(args) => {
                if args.id == "official" {
                    bail!("the official repository source cannot be removed");
                }
                ("admin.repo.sources.remove", json!({ "id": args.id }))
            }
        },
        RepoCommand::List => ("admin.repo.list", json!({})),
        RepoCommand::Install(args) => (
            "admin.repo.install",
            optional_params(
                args.id,
                [("version", args.version), ("source_id", args.source_id)],
            ),
        ),
        RepoCommand::Upgrade(args) => (
            "admin.repo.upgrade",
            optional_params(args.id, [("version", args.version)]),
        ),
        RepoCommand::UpgradeAll => ("admin.repo.upgrade_all", json!({})),
        RepoCommand::Pin(args) => (
            "admin.repo.pin",
            json!({ "id": args.id, "version": args.version }),
        ),
        RepoCommand::Unpin(args) => ("admin.repo.unpin", json!({ "id": args.id })),
        RepoCommand::Uninstall(args) => ("admin.repo.uninstall", json!({ "id": args.id })),
        RepoCommand::Status => ("admin.repo.status", json!({})),
        RepoCommand::Refresh => ("admin.repo.refresh", json!({})),
    };
    Ok(mapped)
}

fn optional_params<const N: usize>(id: String, values: [(&str, Option<String>); N]) -> Value {
    let mut params = Map::from_iter([("id".into(), Value::String(id))]);
    for (key, value) in values {
        if let Some(value) = value {
            params.insert(key.into(), Value::String(value));
        }
    }
    Value::Object(params)
}

async fn execute(
    base_url: &str,
    auth: Authentication,
    command_name: &str,
    params: Value,
) -> Result<Value> {
    let base_url = base_url.trim_end_matches('/').trim_end_matches("/api/v1");
    let (path, headers) = match auth {
        Authentication::Internal {
            internal_token,
            api_key,
        } => {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-internal-token",
                HeaderValue::from_str(&internal_token).context("invalid internal token")?,
            );
            headers.insert(
                "x-ai-api-key",
                HeaderValue::from_str(&api_key).context("invalid API token")?,
            );
            ("/internal/admin-commands", headers)
        }
        Authentication::Session { cookie, csrf_token } => {
            let mut headers = HeaderMap::new();
            let cookie = if cookie.contains('=') {
                cookie
            } else {
                format!("hecate_session={cookie}")
            };
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&cookie).context("invalid session cookie")?,
            );
            headers.insert(
                "x-csrf-token",
                HeaderValue::from_str(&csrf_token).context("invalid CSRF token")?,
            );
            ("/api/v1/admin/repo/commands", headers)
        }
    };

    let response = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("http client")?
        .post(format!("{base_url}{path}"))
        .headers(headers)
        .json(&json!({ "command_name": command_name, "params": params }))
        .send()
        .await
        .context("failed to contact Hecate")?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .context("server returned invalid JSON")?;
    if !status.is_success() {
        bail!("Hecate returned {status}: {body}");
    }
    Ok(body.get("result").cloned().unwrap_or(body))
}
