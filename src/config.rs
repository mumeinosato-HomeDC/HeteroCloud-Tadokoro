use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ipnet::Ipv4Net;

/// Runtime configuration, read from flags or environment variables.
#[derive(Debug, Clone, Parser)]
#[command(version, about)]
pub struct Config {
    #[arg(long, env = "TADOKORO_BIND_ADDR", default_value = "0.0.0.0:8080")]
    pub bind_addr: String,

    #[arg(
        long,
        env = "HETEROCLOUD_PROVIDER_ISSUER",
        default_value = "heterocloud"
    )]
    pub issuer: String,
    #[arg(
        long,
        env = "HETEROCLOUD_PROVIDER_AUDIENCE",
        default_value = "heterocloud-vm"
    )]
    pub audience: String,
    /// JSON object `{kid: ed25519 public key PEM}`.
    #[arg(long, env = "HETEROCLOUD_PROVIDER_PUBLIC_KEYS_JSON")]
    pub public_keys_json: String,

    /// Base URL of a Proxmox VE node API, e.g. https://10.1.128.139:8006
    #[arg(long, env = "TADOKORO_PVE_URL")]
    pub pve_url: String,
    /// API token id, `user@realm!name`.
    #[arg(long, env = "TADOKORO_PVE_TOKEN_ID")]
    pub pve_token_id: String,
    /// File that contains only the API token secret.
    #[arg(long, env = "TADOKORO_PVE_TOKEN_SECRET_FILE")]
    pub pve_token_secret_file: PathBuf,
    /// PEM CA (or self-signed certificate) used to verify the Proxmox API.
    #[arg(long, env = "TADOKORO_PVE_CA_FILE")]
    pub pve_ca_file: Option<PathBuf>,
    /// Node that receives every VM created by this provider.
    #[arg(long, env = "TADOKORO_PVE_NODE", default_value = "pve02")]
    pub node: String,

    #[arg(long, env = "TADOKORO_REGION", default_value = "heteronet-global")]
    pub region: String,
    /// JSON object `{image name: template VMID}`; templates must live on `--node`.
    #[arg(
        long,
        env = "TADOKORO_IMAGES_JSON",
        default_value = r#"{"ubuntu-26.04":9000}"#
    )]
    pub images_json: String,
    /// Storage that holds VM disks (full clones land here).
    #[arg(long, env = "TADOKORO_PVE_STORAGE", default_value = "local-lvm")]
    pub storage: String,
    /// VM network bridge (the SDN VNet).
    #[arg(long, env = "TADOKORO_BRIDGE", default_value = "hcnet")]
    pub bridge: String,
    /// Addresses handed to VMs. Network and broadcast addresses are skipped.
    #[arg(long, env = "TADOKORO_IP_POOL", default_value = "10.100.16.0/20")]
    pub ip_pool: Ipv4Net,
    /// Prefix length of the VNet the VMs sit in (the pool is a slice of it).
    #[arg(long, env = "TADOKORO_NETWORK_PREFIX", default_value_t = 16)]
    pub network_prefix: u8,
    #[arg(long, env = "TADOKORO_GATEWAY", default_value = "10.100.0.1")]
    pub gateway: Ipv4Addr,
    #[arg(long, env = "TADOKORO_NAMESERVER", default_value = "10.100.0.2")]
    pub nameserver: Ipv4Addr,
    #[arg(
        long,
        env = "TADOKORO_SEARCH_DOMAIN",
        default_value = "hetero.internal"
    )]
    pub search_domain: String,
    /// Namespace with the Flash workloads. When set, Tadokoro reads the VM-facing
    /// virtual IPs that the VPC provider publishes there (needs a read-only Role).
    #[arg(long, env = "TADOKORO_FLASH_NAMESPACE")]
    pub flash_namespace: Option<String>,
    /// Source addresses Flash traffic to VMs arrives from (the node address that
    /// pod traffic is translated to). Comma separated.
    #[arg(long, env = "TADOKORO_FLASH_SNAT_ADDRESSES", value_delimiter = ',')]
    pub flash_snat_addresses: Vec<Ipv4Addr>,
    /// How often VPC membership and Flash addresses are re-synchronised.
    #[arg(long, env = "TADOKORO_VPC_SYNC_SECONDS", default_value_t = 30)]
    pub vpc_sync_seconds: u64,
    /// Upper bound of VMs this provider keeps at once.
    #[arg(long, env = "TADOKORO_MAX_VMS", default_value_t = 32)]
    pub max_vms: usize,
}

impl Config {
    pub fn images(&self) -> Result<BTreeMap<String, u32>> {
        let images: BTreeMap<String, u32> = serde_json::from_str(&self.images_json)
            .context("TADOKORO_IMAGES_JSON must be a JSON object of name to VMID")?;
        if images.is_empty() {
            bail!("at least one image template is required");
        }
        Ok(images)
    }

    pub fn validate(&self) -> Result<()> {
        self.images()?;
        if !(8..=30).contains(&self.network_prefix) {
            bail!("network prefix must be between 8 and 30");
        }
        if self.ip_pool.prefix_len() < self.network_prefix {
            bail!("the IP pool must be inside the VM network");
        }
        if self.ip_pool.prefix_len() > 29 {
            bail!("the IP pool is too small");
        }
        if self.max_vms == 0 {
            bail!("max VMs must be positive");
        }
        Ok(())
    }
}
