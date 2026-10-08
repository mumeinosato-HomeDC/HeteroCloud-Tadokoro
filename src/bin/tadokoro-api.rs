use std::{process::ExitCode, sync::Arc};

use anyhow::{Context, Result};
use clap::Parser;
use tadokoro::{
    api::{AppState, router},
    auth::ProviderAuthenticator,
    config::Config,
    dns::{DnsUpdater, parse_socket},
    flash::FlashDirectory,
    pve::PveClient,
    reconcile::{Reconciler, Settings},
};
use tokio::{net::TcpListener, signal};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = ?error, "tadokoro-api stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let config = Config::parse();
    config.validate()?;
    let secret = std::fs::read_to_string(&config.pve_token_secret_file)
        .context("read the Proxmox API token secret file")?;
    let ca = config
        .pve_ca_file
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("read the Proxmox CA file")?;
    let pve = PveClient::new(
        &config.pve_url,
        &config.pve_token_id,
        secret.trim(),
        &config.node,
        ca.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let flash = config
        .flash_namespace
        .as_deref()
        .map(FlashDirectory::in_cluster)
        .transpose()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let dns = match (&config.dns_server, &config.dns_key_file) {
        (Some(server), Some(key_file)) => {
            let key = std::fs::read_to_string(key_file).context("read the DNS TSIG key file")?;
            let server = parse_socket(server).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            Some(
                DnsUpdater::new(server, &config.dns_zone, &key, config.dns_ttl)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            )
        }
        (None, None) => None,
        _ => anyhow::bail!("TADOKORO_DNS_SERVER and TADOKORO_DNS_KEY_FILE must be set together"),
    };
    let reconciler = Reconciler::new(
        pve,
        Settings {
            images: config.images()?,
            storage: config.storage.clone(),
            ip_pool: config.ip_pool,
            network_prefix: config.network_prefix,
            gateway: config.gateway,
            nameserver: config.nameserver,
            search_domain: config.search_domain.clone(),
            max_vms: config.max_vms,
            flash_snat: config.flash_snat_addresses.clone(),
        },
        flash,
        dns,
    );
    let authenticator = ProviderAuthenticator::from_public_keys_json(
        config.issuer.clone(),
        config.audience.clone(),
        &config.public_keys_json,
    )
    .context("configure provider authentication")?;
    {
        let reconciler = Arc::clone(&reconciler);
        let every = std::time::Duration::from_secs(config.vpc_sync_seconds.max(5));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                if let Err(error) = reconciler.sync_all().await {
                    tracing::warn!(%error, "periodic VPC synchronisation failed");
                }
            }
        });
    }
    let state = Arc::new(AppState {
        authenticator,
        reconciler,
        region: config.region.clone(),
        shell_sessions: Arc::new(tokio::sync::Semaphore::new(16)),
    });
    let listener = TcpListener::bind(&config.bind_addr)
        .await
        .with_context(|| format!("bind to {}", config.bind_addr))?;
    tracing::info!(bind_addr = %config.bind_addr, node = %config.node, "HeteroCloud Tadokoro provider ready");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = signal::ctrl_c().await;
        })
        .await
        .context("serve provider API")
}
