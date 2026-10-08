//! Sends signed `provider/v1` commands to Tadokoro, the way the HeteroCloud
//! worker does. For lab and end-to-end testing only: it needs the provider
//! signing key.

use std::{path::PathBuf, process::ExitCode, time::Duration};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tadokoro::{
    PROVIDER_DELETE_ACTION, PROVIDER_RECONCILE_ACTION, PROVIDER_STATUS_GET_ACTION,
    auth::ProviderClaims,
};
use uuid::Uuid;

#[derive(Parser)]
#[command(about = "Send signed provider/v1 commands to Tadokoro")]
struct Cli {
    #[arg(long, env = "TADOKORO_URL", default_value = "http://127.0.0.1:8080")]
    url: String,
    /// Ed25519 private key (PEM) of the HeteroCloud provider signer.
    #[arg(long, env = "TADOKORO_SIGNING_KEY")]
    key: PathBuf,
    #[arg(long, default_value = "heterocloud-provider-1")]
    kid: String,
    #[arg(long, default_value = "heterocloud")]
    issuer: String,
    #[arg(long, default_value = "heterocloud-vm")]
    audience: String,
    #[arg(long, default_value_t = Uuid::nil())]
    organization: Uuid,
    #[arg(long, default_value_t = Uuid::nil())]
    project: Uuid,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create or update a VM and wait until the provider accepts it.
    Apply {
        instance: Uuid,
        #[arg(long)]
        generation: i64,
        #[arg(long)]
        name: String,
        /// JSON file with the VM spec.
        #[arg(long)]
        spec: PathBuf,
    },
    /// Delete a VM and wait until it is gone.
    Delete {
        instance: Uuid,
        #[arg(long)]
        generation: i64,
    },
    Status {
        instance: Uuid,
        #[arg(long)]
        generation: i64,
    },
}

fn token(cli: &Cli, instance: Uuid, action: &str, generation: i64) -> Result<String> {
    let pem = std::fs::read(&cli.key).context("read the signing key")?;
    let now = Utc::now().timestamp();
    let claims = ProviderClaims {
        issuer: cli.issuer.clone(),
        audience: cli.audience.clone(),
        subject: Uuid::now_v7(),
        user_id: None,
        organization_id: cli.organization,
        project_id: cli.project,
        service_instance_id: instance,
        action: action.into(),
        generation,
        jwt_id: Uuid::now_v7(),
        issued_at: now,
        not_before: now - 5,
        expires_at: now + 60,
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(cli.kid.clone());
    Ok(encode(&header, &claims, &EncodingKey::from_ed_pem(&pem)?)?)
}

#[allow(clippy::too_many_arguments)]
async fn call(
    cli: &Cli,
    http: &reqwest::Client,
    method: reqwest::Method,
    path: &str,
    action: &str,
    instance: Uuid,
    generation: i64,
    body: Option<Value>,
) -> Result<(u16, Value)> {
    let mut request = http
        .request(method, format!("{}{}", cli.url.trim_end_matches('/'), path))
        .bearer_auth(token(cli, instance, action, generation)?);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    Ok((status, response.json().await.unwrap_or(Value::Null)))
}

async fn run(cli: Cli) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    match &cli.command {
        Command::Apply {
            instance,
            generation,
            name,
            spec,
        } => {
            let spec: Value = serde_json::from_slice(&std::fs::read(spec)?)?;
            let path = format!("/internal/v1/service-instances/{instance}");
            for attempt in 1..=240 {
                let (status, body) = call(
                    &cli,
                    &http,
                    reqwest::Method::PUT,
                    &path,
                    PROVIDER_RECONCILE_ACTION,
                    *instance,
                    *generation,
                    Some(json!({"generation": generation, "name": name, "spec": spec})),
                )
                .await?;
                match status {
                    202 => {
                        println!("{}", serde_json::to_string_pretty(&body)?);
                        return Ok(());
                    }
                    503 => eprintln!("[{attempt}] reconciling…"),
                    _ => bail!("provider answered {status}: {body}"),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            bail!("timed out waiting for the VM")
        }
        Command::Delete {
            instance,
            generation,
        } => {
            let path = format!("/internal/v1/service-instances/{instance}?generation={generation}");
            for attempt in 1..=120 {
                let (status, body) = call(
                    &cli,
                    &http,
                    reqwest::Method::DELETE,
                    &path,
                    PROVIDER_DELETE_ACTION,
                    *instance,
                    *generation,
                    None,
                )
                .await?;
                match status {
                    202 => {
                        println!("{}", serde_json::to_string_pretty(&body)?);
                        return Ok(());
                    }
                    503 => eprintln!("[{attempt}] deleting…"),
                    _ => bail!("provider answered {status}: {body}"),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            bail!("timed out waiting for deletion")
        }
        Command::Status {
            instance,
            generation,
        } => {
            let path = format!("/internal/v1/service-instances/{instance}?generation={generation}");
            let (status, body) = call(
                &cli,
                &http,
                reqwest::Method::GET,
                &path,
                PROVIDER_STATUS_GET_ACTION,
                *instance,
                *generation,
                None,
            )
            .await?;
            println!("{status} {}", serde_json::to_string_pretty(&body)?);
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
