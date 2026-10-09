//! The reconciler. `advance` is called on every `PUT` and moves one VM a single
//! step closer to the requested generation; it returns the VM status only when
//! the VM matches the spec and runs (or is deliberately stopped).
//!
//! All state lives on the Proxmox VM: the name ends in the service instance id,
//! the tags carry the marker and the address, and the description holds the
//! accepted generation and spec as JSON.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    auth::ProviderClaims,
    dns::{self, DnsUpdater, Records},
    firewall::{self, FLASH_SRC_IPSET, FLASH_VIP_IPSET, IPFILTER_IPSET, VPC_IPSET},
    flash::FlashDirectory,
    ipam::{self, parse_ip_tag},
    pve::{PveClient, PveError, PveVm, VmConfig, percent_encode},
    spec::{VmSpec, slug},
};

pub const TAG_MARKER: &str = "hc-vm";
const ROOT_DISK: &str = "scsi0";
const SHUTDOWN_TIMEOUT_SECONDS: u32 = 60;

#[derive(Debug, Error)]
pub enum ReconcileError {
    #[error("provider is still reconciling the resource")]
    NotReady,
    #[error("service instance was not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("provider command is forbidden")]
    Forbidden,
    #[error("provider capacity is exhausted: {0}")]
    Capacity(String),
    #[error(transparent)]
    Pve(#[from] PveError),
}

/// What the provider writes into the VM `description`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VmMeta {
    pub v: u8,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub service_instance_id: Uuid,
    pub name: String,
    pub generation: i64,
    pub applied_generation: i64,
    pub spec: VmSpec,
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub images: BTreeMap<String, u32>,
    pub storage: String,
    pub ip_pool: Ipv4Net,
    pub network_prefix: u8,
    pub gateway: Ipv4Addr,
    pub nameserver: Ipv4Addr,
    pub search_domain: String,
    pub max_vms: usize,
    /// Source addresses Flash traffic reaches VMs from.
    pub flash_snat: Vec<Ipv4Addr>,
    /// Second NIC towards the outside world, if configured.
    pub external: Option<External>,
}

#[derive(Clone, Debug)]
pub struct External {
    pub bridge: String,
    /// Addresses the external router hands out; anything else a guest reports is ignored.
    pub network: Ipv4Net,
}

pub struct Reconciler {
    pve: PveClient,
    settings: Settings,
    flash: Option<FlashDirectory>,
    dns: Option<DnsUpdater>,
    /// Serialises VMID and address allocation (the provider runs one replica).
    allocation: Mutex<()>,
    /// VMs cloned moments ago. `cluster/resources` lags by several seconds, so
    /// without this a quick retry could clone the same instance twice.
    recent: std::sync::Mutex<HashMap<Uuid, (PveVm, Instant)>>,
}

const RECENT_TTL: Duration = Duration::from_secs(180);

/// Names of provider-managed VMs end in `-<32 hex>`, the instance id.
fn managed_name(name: &str) -> bool {
    name.len() > 33
        && name.as_bytes()[name.len() - 33] == b'-'
        && name[name.len() - 32..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Reconciler {
    pub fn new(
        pve: PveClient,
        settings: Settings,
        flash: Option<FlashDirectory>,
        dns: Option<DnsUpdater>,
    ) -> Arc<Self> {
        Arc::new(Self {
            pve,
            settings,
            flash,
            dns,
            allocation: Mutex::new(()),
            recent: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Cheap readiness probe for the Proxmox dependency.
    pub async fn ping(&self) -> Result<(), PveError> {
        self.pve.next_id().await.map(|_| ())
    }

    pub fn vm_name(display: &str, instance: Uuid) -> String {
        format!("{}-{}", slug(display), instance.simple())
    }

    fn recent_vm(&self, instance: Uuid) -> Option<PveVm> {
        let mut recent = self.recent.lock().ok()?;
        recent.retain(|_, (_, at)| at.elapsed() < RECENT_TTL);
        recent.get(&instance).map(|(vm, _)| vm.clone())
    }

    fn forget_recent(&self, instance: Uuid) {
        if let Ok(mut recent) = self.recent.lock() {
            recent.remove(&instance);
        }
    }

    /// Provider-managed VMs, including ones too new to appear in the resource list.
    async fn managed(&self) -> Result<Vec<PveVm>, PveError> {
        let mut vms: Vec<PveVm> = self
            .pve
            .list_vms()
            .await?
            .into_iter()
            .filter(|vm| vm.name.as_deref().is_some_and(managed_name))
            .collect();
        if let Ok(recent) = self.recent.lock() {
            for (vm, at) in recent.values() {
                if at.elapsed() < RECENT_TTL && !vms.iter().any(|v| v.vmid == vm.vmid) {
                    vms.push(vm.clone());
                }
            }
        }
        Ok(vms)
    }

    async fn find(&self, instance: Uuid) -> Result<Option<PveVm>, PveError> {
        let suffix = format!("-{}", instance.simple());
        if let Some(vm) = self.recent_vm(instance) {
            match self.pve.config(vm.vmid).await {
                Ok(_) | Err(PveError::Locked) => return Ok(Some(vm)),
                Err(PveError::NotFound) => self.forget_recent(instance),
                Err(error) => return Err(error),
            }
        }
        let found = self.pve.list_vms().await?.into_iter().find(|vm| {
            vm.name
                .as_deref()
                .is_some_and(|n| managed_name(n) && n.ends_with(&suffix))
        });
        if found.is_some() {
            self.forget_recent(instance);
        }
        Ok(found)
    }

    fn meta_of(config: &VmConfig) -> Option<VmMeta> {
        serde_json::from_str(config.str("description")?.trim()).ok()
    }

    fn check_identity(meta: &VmMeta, claims: &ProviderClaims) -> Result<(), ReconcileError> {
        if meta.organization_id != claims.organization_id
            || meta.project_id != claims.project_id
            || meta.service_instance_id != claims.service_instance_id
        {
            return Err(ReconcileError::Forbidden);
        }
        Ok(())
    }

    async fn locked_config(&self, vmid: u32) -> Result<VmConfig, ReconcileError> {
        match self.pve.config(vmid).await {
            Ok(config) if config.lock().is_none() => Ok(config),
            Ok(_) | Err(PveError::Locked) => Err(ReconcileError::NotReady),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn advance(
        &self,
        claims: &ProviderClaims,
        name: &str,
        spec: &VmSpec,
        generation: i64,
    ) -> Result<Value, ReconcileError> {
        let instance = claims.service_instance_id;
        let Some(vm) = self.find(instance).await? else {
            self.create(instance, name, spec).await?;
            return Err(ReconcileError::NotReady);
        };
        let config = self.locked_config(vm.vmid).await?;

        let mut meta = match Self::meta_of(&config) {
            Some(meta) => {
                Self::check_identity(&meta, claims)?;
                if generation < meta.generation {
                    return Err(ReconcileError::Conflict("generation is stale".into()));
                }
                if generation == meta.generation && (meta.name != name || &meta.spec != spec) {
                    return Err(ReconcileError::Conflict(
                        "generation was already used for different desired state".into(),
                    ));
                }
                meta
            }
            // A fresh clone that this provider has not configured yet.
            None => VmMeta {
                v: 1,
                organization_id: claims.organization_id,
                project_id: claims.project_id,
                service_instance_id: instance,
                name: name.to_owned(),
                generation: 0,
                applied_generation: 0,
                spec: spec.clone(),
            },
        };
        let previous_vpc = meta.spec.network.vpc_id;
        if generation > meta.generation {
            Self::check_update_allowed(&config, &meta, spec)?;
            meta.generation = generation;
            meta.name = name.to_owned();
            meta.spec = spec.clone();
            // Record the accepted generation before acting on it.
            self.pve
                .set_config(vm.vmid, &[("description", Self::describe(&meta)?)])
                .await?;
        }

        let power = self.pve.power_state(vm.vmid).await?;
        // VMs created before the firewall existed are brought under it as well.
        if meta.applied_generation < meta.generation || !has_firewall_flag(&config) {
            self.apply(&vm, &config, meta, &power, previous_vpc).await?;
            return Err(ReconcileError::NotReady);
        }
        self.settle(&vm, &config, &meta, &power).await
    }

    fn describe(meta: &VmMeta) -> Result<String, ReconcileError> {
        serde_json::to_string(meta)
            .map_err(|_| ReconcileError::BadRequest("spec is not serializable".into()))
    }

    /// Disks only grow and the image is fixed for the life of the VM.
    fn check_update_allowed(
        config: &VmConfig,
        old: &VmMeta,
        new: &VmSpec,
    ) -> Result<(), ReconcileError> {
        if old.applied_generation > 0 && old.spec.image != new.image {
            return Err(ReconcileError::BadRequest(
                "image cannot change after creation".into(),
            ));
        }
        if let Some(current) = config.disk_mib(ROOT_DISK)
            && old.applied_generation > 0
            && u64::from(new.disk_gib) * 1024 < current
        {
            return Err(ReconcileError::BadRequest("disk_gib cannot shrink".into()));
        }
        Ok(())
    }

    async fn create(
        &self,
        instance: Uuid,
        name: &str,
        spec: &VmSpec,
    ) -> Result<(), ReconcileError> {
        let _guard = self.allocation.lock().await;
        // Re-check under the lock: a concurrent request may have just cloned it.
        if self.find(instance).await?.is_some() {
            return Ok(());
        }
        if self.managed().await?.len() >= self.settings.max_vms {
            return Err(ReconcileError::Capacity(format!(
                "at most {} VMs",
                self.settings.max_vms
            )));
        }
        let template =
            *self.settings.images.get(&spec.image).ok_or_else(|| {
                ReconcileError::BadRequest(format!("unknown image {}", spec.image))
            })?;
        let vmid = self.pve.next_id().await?;
        let vm_name = Self::vm_name(name, instance);
        self.pve
            .clone_template(template, vmid, &vm_name, &self.settings.storage)
            .await?;
        if let Ok(mut recent) = self.recent.lock() {
            let vm = PveVm {
                vmid,
                name: Some(vm_name),
                node: self.pve.node().to_owned(),
                status: "stopped".into(),
                template: 0,
                tags: None,
            };
            recent.insert(instance, (vm, Instant::now()));
        }
        Ok(())
    }

    fn desired_sshkeys(spec: &VmSpec) -> String {
        spec.ssh_authorized_keys
            .iter()
            .map(|k| k.trim())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn restart_needed(&self, config: &VmConfig, spec: &VmSpec) -> bool {
        let keys_now = config
            .str("sshkeys")
            .map(|v| percent_decode(&v))
            .unwrap_or_default();
        config.u64("cores") != Some(u64::from(spec.cpu_cores))
            || config.u64("memory") != Some(u64::from(spec.memory_mib))
            || config.str("ciuser").as_deref() != Some(spec.username.as_str())
            || keys_now.trim() != Self::desired_sshkeys(spec).trim()
            || !has_firewall_flag(config)
            // The external NIC is added (or its bridge changed) at the next boot.
            || self
                .settings
                .external
                .as_ref()
                .is_some_and(|external| nic_bridge(config, "net1").as_deref() != Some(&external.bridge))
    }

    fn tags_for(ip: Ipv4Addr, vpc: Option<Uuid>) -> String {
        let mut tags = format!("{TAG_MARKER};{}", ipam::ip_tag(ip));
        if let Some(vpc) = vpc {
            tags.push(';');
            tags.push_str(&vpc_tag(vpc));
        }
        tags
    }

    fn tag_values(config: &VmConfig) -> Vec<String> {
        config
            .str("tags")
            .map(|t| {
                t.split([';', ',', ' '])
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn ip_of(config: &VmConfig) -> Option<Ipv4Addr> {
        Self::tag_values(config)
            .iter()
            .find_map(|t| parse_ip_tag(t))
    }

    async fn address_for(&self, config: &VmConfig, vmid: u32) -> Result<Ipv4Addr, ReconcileError> {
        if let Some(ip) = Self::ip_of(config) {
            return Ok(ip);
        }
        let _guard = self.allocation.lock().await;
        // Read tags from the VM configs, not the (lagging) resource list.
        let mut used = BTreeSet::new();
        for other in self.managed().await?.iter().filter(|vm| vm.vmid != vmid) {
            match self.pve.config(other.vmid).await {
                Ok(other_config) => used.extend(Self::ip_of(&other_config)),
                Err(PveError::NotFound | PveError::Locked) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let ip = ipam::allocate(self.settings.ip_pool, &used).ok_or_else(|| {
            ReconcileError::Capacity("no free address left in the IP pool".into())
        })?;
        // Commit the address immediately so a concurrent allocation sees it.
        self.pve
            .set_config(vmid, &[("tags", Self::tags_for(ip, None))])
            .await?;
        Ok(ip)
    }

    async fn apply(
        &self,
        vm: &PveVm,
        config: &VmConfig,
        mut meta: VmMeta,
        power: &str,
        previous_vpc: Option<Uuid>,
    ) -> Result<(), ReconcileError> {
        let vmid = vm.vmid;
        let spec = meta.spec.clone();
        if power != "stopped" && self.restart_needed(config, &spec) {
            // CPU, memory, cloud-init and NIC changes apply on the next boot.
            self.pve.shutdown(vmid, SHUTDOWN_TIMEOUT_SECONDS).await?;
            return Ok(());
        }
        let ip = self.address_for(config, vmid).await?;
        if let Some(current) = config.disk_mib(ROOT_DISK)
            && u64::from(spec.disk_gib) * 1024 > current
        {
            self.pve.resize(vmid, ROOT_DISK, spec.disk_gib).await?;
        }
        meta.applied_generation = meta.generation;
        let mut params = vec![
            ("cores", spec.cpu_cores.to_string()),
            ("sockets", "1".into()),
            ("memory", spec.memory_mib.to_string()),
            ("balloon", "0".into()),
            ("onboot", "1".into()),
            ("ciuser", spec.username.clone()),
            (
                "sshkeys",
                percent_encode(&format!("{}\n", Self::desired_sshkeys(&spec))),
            ),
            (
                "ipconfig0",
                // With an external NIC the default route comes from its DHCP lease.
                match self.settings.external {
                    Some(_) => format!("ip={ip}/{}", self.settings.network_prefix),
                    None => format!(
                        "ip={ip}/{},gw={}",
                        self.settings.network_prefix, self.settings.gateway
                    ),
                },
            ),
            ("nameserver", self.settings.nameserver.to_string()),
            ("searchdomain", self.settings.search_domain.clone()),
            ("tags", Self::tags_for(ip, spec.network.vpc_id)),
            ("description", Self::describe(&meta)?),
        ];
        if let Some(net0) = net0_with_firewall(config) {
            params.push(("net0", net0));
        }
        if let Some(external) = &self.settings.external {
            params.push(("ipconfig1", "ip=dhcp".into()));
            if nic_bridge(config, "net1").as_deref() != Some(&external.bridge) {
                params.push((
                    "net1",
                    format!("virtio,bridge={},firewall=1", external.bridge),
                ));
            }
        }
        // Firewall objects first, config last: a VM never boots unfiltered.
        self.ensure_firewall(vmid, &spec, ip).await?;
        self.pve.set_config(vmid, &params).await?;
        if let Some(vpc) = spec.network.vpc_id {
            self.sync_vpc(vpc, None).await?;
        }
        if let Some(old) = previous_vpc.filter(|old| Some(*old) != spec.network.vpc_id) {
            self.sync_vpc(old, None).await?;
        }
        self.sync_dns_best_effort().await;
        Ok(())
    }

    /// The A records every settled VM and VPC-attached Flash service should have.
    async fn desired_dns(&self, zone: &str) -> Result<Records, ReconcileError> {
        let mut records = Records::new();
        let mut vpcs = BTreeSet::new();
        for vm in self.managed().await? {
            let config = match self.pve.config(vm.vmid).await {
                // A locked VM cannot be read right now; deleting its names because of that
                // would make them flap, so the round is skipped instead.
                Ok(config) if config.lock().is_some() => return Err(ReconcileError::NotReady),
                Ok(config) => config,
                Err(PveError::Locked) => return Err(ReconcileError::NotReady),
                Err(PveError::NotFound) => continue,
                Err(error) => return Err(error.into()),
            };
            // A clone that is not configured yet has no name to publish.
            let (Some(meta), Some(ip)) = (Self::meta_of(&config), Self::ip_of(&config)) else {
                continue;
            };
            let id = meta.service_instance_id;
            records
                .entry(dns::vm_canonical_name(zone, &meta.name, id))
                .or_default()
                .insert(ip);
            if let Some(vpc) = meta.spec.network.vpc_id {
                vpcs.insert(vpc);
                records
                    .entry(dns::vm_vpc_alias(zone, &meta.name, vpc))
                    .or_default()
                    .insert(ip);
            }
        }
        if let Some(directory) = &self.flash {
            for vpc in vpcs {
                // A failed lookup aborts the round: absent names would be deleted.
                let services = directory
                    .vm_services(vpc)
                    .await
                    .map_err(|e| ReconcileError::BadRequest(e.to_string()))?;
                for (name, ip) in services {
                    if let Some(name) = name {
                        records
                            .entry(dns::service_name(zone, &name, vpc))
                            .or_default()
                            .insert(ip);
                    }
                }
            }
        }
        Ok(records)
    }

    /// Declarative DNS sync: owned subtrees of the zone end up exactly as desired.
    pub async fn sync_dns(&self) -> Result<(), ReconcileError> {
        let Some(updater) = &self.dns else {
            return Ok(());
        };
        let desired = self.desired_dns(updater.zone()).await?;
        match updater.reconcile(&desired).await {
            Ok((changed, removed)) if changed + removed > 0 => {
                tracing::info!(changed, removed, "DNS records synchronised");
                Ok(())
            }
            Ok(_) => Ok(()),
            Err(error) => Err(ReconcileError::BadRequest(error.to_string())),
        }
    }

    async fn sync_dns_best_effort(&self) {
        match self.sync_dns().await {
            Ok(()) | Err(ReconcileError::NotReady) => {}
            Err(error) => {
                tracing::warn!(%error, "DNS synchronisation failed; the periodic sync retries");
            }
        }
    }

    /// Make the VM's firewall options, IP sets and rules match the spec.
    async fn ensure_firewall(
        &self,
        vmid: u32,
        spec: &VmSpec,
        ip: Ipv4Addr,
    ) -> Result<(), ReconcileError> {
        self.set_ipset(vmid, IPFILTER_IPSET, &BTreeSet::from([ip.to_string()]))
            .await?;
        if self.settings.external.is_some() {
            self.ensure_external_ipfilter(vmid).await?;
        }
        if spec.network.vpc_id.is_none() {
            self.set_ipset(vmid, VPC_IPSET, &BTreeSet::new()).await?;
        } else {
            self.ensure_ipset(vmid, VPC_IPSET).await?;
        }

        let in_vpc = spec.network.vpc_id;
        let flash_src: BTreeSet<String> = if in_vpc.is_some() {
            self.settings
                .flash_snat
                .iter()
                .map(ToString::to_string)
                .collect()
        } else {
            BTreeSet::new()
        };
        self.set_ipset(vmid, FLASH_SRC_IPSET, &flash_src).await?;
        match (in_vpc, &self.flash) {
            (Some(vpc), Some(directory)) => match directory.vm_addresses(vpc).await {
                Ok(vips) => {
                    let vips: BTreeSet<String> = vips.iter().map(ToString::to_string).collect();
                    self.set_ipset(vmid, FLASH_VIP_IPSET, &vips).await?;
                }
                Err(error) => {
                    // Keep what the VM has; the periodic sync retries.
                    tracing::warn!(%error, %vpc, "could not read the Flash addresses of the VPC");
                    self.ensure_ipset(vmid, FLASH_VIP_IPSET).await?;
                }
            },
            (None, _) => {
                self.set_ipset(vmid, FLASH_VIP_IPSET, &BTreeSet::new())
                    .await?
            }
            (Some(_), None) => self.ensure_ipset(vmid, FLASH_VIP_IPSET).await?,
        }

        let desired = firewall::rules(spec, self.settings.nameserver);
        let current = self.pve.fw_rules(vmid).await?;
        let in_sync = current.len() == desired.len()
            && desired
                .iter()
                .zip(&current)
                .all(|(want, have)| want.matches(have));
        if !in_sync {
            let mut positions: Vec<u64> = current
                .iter()
                .filter_map(|r| r.get("pos").and_then(Value::as_u64))
                .collect();
            positions.sort_unstable_by(|a, b| b.cmp(a));
            for pos in positions {
                self.pve.delete_fw_rule(vmid, pos).await?;
            }
            // Proxmox inserts every new rule at the top, so add them last to first.
            for rule in desired.iter().rev() {
                self.pve.add_fw_rule(vmid, &rule.params()).await?;
            }
        }

        let options = self.pve.fw_options(vmid).await?;
        let changed: Vec<(&str, String)> = firewall::options(self.settings.external.is_some())
            .iter()
            .filter(|(key, want)| options.str(key).as_deref() != Some(*want))
            .map(|(key, want)| (*key, (*want).to_owned()))
            .collect();
        if !changed.is_empty() {
            self.pve.set_fw_options(vmid, &changed).await?;
        }
        Ok(())
    }

    /// The address the external router leased to the VM's second NIC, as the guest agent reports
    /// it. Only addresses inside the external network count; the guest controls what it says.
    async fn external_ip(
        &self,
        vmid: u32,
        config: &VmConfig,
    ) -> Result<Option<Ipv4Addr>, ReconcileError> {
        let Some(external) = &self.settings.external else {
            return Ok(None);
        };
        let Some(mac) = nic_mac(config, "net1") else {
            return Ok(None);
        };
        let interfaces = self.pve.agent_interfaces(vmid).await?;
        Ok(interfaces
            .iter()
            .filter(|nic| {
                nic.get("hardware-address")
                    .and_then(Value::as_str)
                    .is_some_and(|m| m.eq_ignore_ascii_case(&mac))
            })
            .flat_map(|nic| {
                nic.get("ip-addresses")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter(|a| a.get("ip-address-type").and_then(Value::as_str) == Some("ipv4"))
            .filter_map(|a| {
                a.get("ip-address")
                    .and_then(Value::as_str)?
                    .parse::<Ipv4Addr>()
                    .ok()
            })
            .find(|ip| external.network.contains(ip)))
    }

    /// Lets the leased external address through `ipfilter` (the lease is unknown until the guest has
    /// booted, so the set starts empty and is filled from the next sync). Without information the
    /// current set is left alone.
    async fn ensure_external_ipfilter(&self, vmid: u32) -> Result<(), ReconcileError> {
        let config = match self.pve.config(vmid).await {
            Ok(config) => config,
            Err(PveError::NotFound | PveError::Locked) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        match self.external_ip(vmid, &config).await? {
            Some(ip) => {
                self.set_ipset(
                    vmid,
                    firewall::EXTERNAL_IPFILTER_IPSET,
                    &BTreeSet::from([ip.to_string()]),
                )
                .await
            }
            None => {
                self.ensure_ipset(vmid, firewall::EXTERNAL_IPFILTER_IPSET)
                    .await
            }
        }
    }

    async fn ensure_ipset(&self, vmid: u32, name: &str) -> Result<(), ReconcileError> {
        if !self.pve.fw_ipsets(vmid).await?.iter().any(|n| n == name) {
            self.pve.create_fw_ipset(vmid, name).await?;
        }
        Ok(())
    }

    /// Replace the entries of a VM-scoped IP set.
    async fn set_ipset(
        &self,
        vmid: u32,
        name: &str,
        desired: &BTreeSet<String>,
    ) -> Result<(), ReconcileError> {
        self.ensure_ipset(vmid, name).await?;
        let current: BTreeSet<String> = self
            .pve
            .fw_ipset_entries(vmid, name)
            .await?
            .into_iter()
            .map(|c| c.strip_suffix("/32").unwrap_or(&c).to_owned())
            .collect();
        for stale in current.difference(desired) {
            self.pve.delete_fw_ipset_entry(vmid, name, stale).await?;
        }
        for missing in desired.difference(&current) {
            self.pve.add_fw_ipset_entry(vmid, name, missing).await?;
        }
        Ok(())
    }

    /// Give every VM of a VPC the addresses of all the others. `exclude` is a VM
    /// that is leaving (being deleted).
    async fn sync_vpc(&self, vpc: Uuid, exclude: Option<u32>) -> Result<(), ReconcileError> {
        let tag = vpc_tag(vpc);
        let mut members: Vec<(u32, Ipv4Addr)> = Vec::new();
        for vm in self
            .managed()
            .await?
            .iter()
            .filter(|vm| Some(vm.vmid) != exclude)
        {
            let config = match self.pve.config(vm.vmid).await {
                Ok(config) => config,
                Err(PveError::NotFound | PveError::Locked) => continue,
                Err(error) => return Err(error.into()),
            };
            if Self::tag_values(&config).contains(&tag)
                && let Some(ip) = Self::ip_of(&config)
            {
                members.push((vm.vmid, ip));
            }
        }
        let vips: Option<BTreeSet<String>> = match &self.flash {
            Some(directory) => match directory.vm_addresses(vpc).await {
                Ok(vips) => Some(vips.iter().map(ToString::to_string).collect()),
                Err(error) => {
                    tracing::warn!(%error, %vpc, "could not read the Flash addresses of the VPC");
                    None
                }
            },
            None => None,
        };
        for (vmid, own) in &members {
            let peers: BTreeSet<String> = members
                .iter()
                .filter(|(_, ip)| ip != own)
                .map(|(_, ip)| ip.to_string())
                .collect();
            self.set_ipset(*vmid, VPC_IPSET, &peers).await?;
            if let Some(vips) = &vips {
                self.set_ipset(*vmid, FLASH_VIP_IPSET, vips).await?;
            }
        }
        Ok(())
    }

    /// Re-synchronises every VPC that has VMs: peers come and go with their VMs, and
    /// Flash services (with their virtual IPs) change without any VM command.
    pub async fn sync_all(&self) -> Result<(), ReconcileError> {
        let mut vpcs = BTreeSet::new();
        for vm in self.managed().await? {
            let config = match self.pve.config(vm.vmid).await {
                Ok(config) if config.lock().is_none() => config,
                Ok(_) | Err(PveError::NotFound | PveError::Locked) => continue,
                Err(error) => return Err(error.into()),
            };
            // Settled VMs only: heal drift and roll out rule changes made since they were created.
            if let (Some(meta), Some(ip)) = (Self::meta_of(&config), Self::ip_of(&config))
                && meta.applied_generation >= meta.generation
                && has_firewall_flag(&config)
            {
                self.ensure_firewall(vm.vmid, &meta.spec, ip).await?;
            }
            for tag in Self::tag_values(&config) {
                if let Some(id) = tag
                    .strip_prefix("hc-vpc-")
                    .and_then(|s| Uuid::parse_str(s).ok())
                {
                    vpcs.insert(id);
                }
            }
        }
        for vpc in vpcs {
            self.sync_vpc(vpc, None).await?;
        }
        self.sync_dns_best_effort().await;
        Ok(())
    }

    /// Bring the power state in line with the spec once the config is applied.
    async fn settle(
        &self,
        vm: &PveVm,
        config: &VmConfig,
        meta: &VmMeta,
        power: &str,
    ) -> Result<Value, ReconcileError> {
        if let Some(ip) = Self::ip_of(config) {
            // Cheap, idempotent, and heals manual edits of the firewall.
            self.ensure_firewall(vm.vmid, &meta.spec, ip).await?;
        }
        match (power, meta.spec.stopped) {
            ("running", false) | ("stopped", true) => {
                Ok(self.status_json(vm, config, meta, power).await)
            }
            ("stopped", false) => {
                self.pve.start(vm.vmid).await?;
                Err(ReconcileError::NotReady)
            }
            ("running", true) => {
                self.pve.shutdown(vm.vmid, SHUTDOWN_TIMEOUT_SECONDS).await?;
                Err(ReconcileError::NotReady)
            }
            _ => Err(ReconcileError::NotReady),
        }
    }

    /// DNS names the VM is registered under (empty when DNS registration is off).
    fn dns_names(&self, meta: &VmMeta) -> Vec<String> {
        let Some(updater) = &self.dns else {
            return Vec::new();
        };
        let zone = updater.zone();
        let mut names = vec![dns::vm_canonical_name(
            zone,
            &meta.name,
            meta.service_instance_id,
        )];
        if let Some(vpc) = meta.spec.network.vpc_id {
            names.push(dns::vm_vpc_alias(zone, &meta.name, vpc));
        }
        names
            .into_iter()
            .map(|n| n.trim_end_matches('.').to_owned())
            .collect()
    }

    async fn status_json(
        &self,
        vm: &PveVm,
        config: &VmConfig,
        meta: &VmMeta,
        power: &str,
    ) -> Value {
        let external_ip = if power == "running" {
            self.external_ip(vm.vmid, config).await.ok().flatten()
        } else {
            None
        };
        json!({
            "phase": "ready",
            "observed_generation": meta.applied_generation,
            "vmid": vm.vmid,
            "node": vm.node,
            "hostname": vm.name,
            "ip_address": Self::ip_of(config).map(|ip| ip.to_string()),
            "external_ip_address": external_ip.map(|ip| ip.to_string()),
            "power_state": power,
            "image": meta.spec.image,
            "cpu_cores": meta.spec.cpu_cores,
            "memory_mib": meta.spec.memory_mib,
            "disk_gib": meta.spec.disk_gib,
            "username": meta.spec.username,
            "vpc_id": meta.spec.network.vpc_id,
            "firewall": "enforced",
            "dns_names": self.dns_names(meta),
        })
    }

    pub fn deleted_status(generation: i64) -> Value {
        json!({"phase": "deleted", "observed_generation": generation})
    }

    /// Idempotent delete; returns the status once the VM is gone.
    pub async fn remove(
        &self,
        claims: &ProviderClaims,
        generation: i64,
    ) -> Result<Value, ReconcileError> {
        let Some(vm) = self.find(claims.service_instance_id).await? else {
            self.sync_dns_best_effort().await;
            return Ok(Self::deleted_status(generation));
        };
        let config = self.locked_config(vm.vmid).await?;
        if let Some(meta) = Self::meta_of(&config) {
            Self::check_identity(&meta, claims)?;
            if generation < meta.generation {
                return Err(ReconcileError::Conflict("generation is stale".into()));
            }
            if let Some(updater) = &self.dns {
                let name =
                    dns::vm_canonical_name(updater.zone(), &meta.name, meta.service_instance_id);
                if let Err(error) = updater.delete(&name).await {
                    tracing::warn!(%error, %name, "could not remove the VM's DNS name");
                }
            }
            if let Some(vpc) = meta.spec.network.vpc_id {
                // Peers stop allowing this address before the VM goes away.
                self.sync_vpc(vpc, Some(vm.vmid)).await?;
            }
        }
        if self.pve.power_state(vm.vmid).await? != "stopped" {
            self.pve.stop(vm.vmid).await?;
        } else {
            self.pve.destroy(vm.vmid).await?;
        }
        Err(ReconcileError::NotReady)
    }

    /// Verifies the caller may open a shell on this VM and returns its VMID: same tenant,
    /// current generation, configured and running.
    pub async fn shell_target(
        &self,
        claims: &ProviderClaims,
        generation: i64,
    ) -> Result<u32, ReconcileError> {
        let vm = self
            .find(claims.service_instance_id)
            .await?
            .ok_or(ReconcileError::NotFound)?;
        let config = self.locked_config(vm.vmid).await?;
        let meta = Self::meta_of(&config).ok_or(ReconcileError::NotReady)?;
        Self::check_identity(&meta, claims)?;
        if meta.generation != generation {
            return Err(ReconcileError::Conflict(
                "generation does not match current desired state".into(),
            ));
        }
        if meta.applied_generation < generation || self.pve.power_state(vm.vmid).await? != "running"
        {
            return Err(ReconcileError::NotReady);
        }
        Ok(vm.vmid)
    }

    pub async fn open_terminal(
        &self,
        vmid: u32,
    ) -> Result<(crate::pve::TerminalSocket, crate::pve::TermProxy), ReconcileError> {
        let proxy = self.pve.termproxy(vmid).await?;
        let socket = self.pve.connect_terminal(vmid, &proxy).await?;
        Ok((socket, proxy))
    }

    pub async fn status(
        &self,
        claims: &ProviderClaims,
        generation: i64,
    ) -> Result<Value, ReconcileError> {
        let vm = self
            .find(claims.service_instance_id)
            .await?
            .ok_or(ReconcileError::NotFound)?;
        let config = self.locked_config(vm.vmid).await?;
        let meta = Self::meta_of(&config).ok_or(ReconcileError::NotReady)?;
        Self::check_identity(&meta, claims)?;
        if meta.generation != generation {
            return Err(ReconcileError::Conflict(
                "generation does not match current desired state".into(),
            ));
        }
        if meta.applied_generation < generation {
            return Err(ReconcileError::NotReady);
        }
        let power = self.pve.power_state(vm.vmid).await?;
        Ok(self.status_json(&vm, &config, &meta, &power).await)
    }
}

fn vpc_tag(vpc: Uuid) -> String {
    format!("hc-vpc-{}", vpc.simple())
}

/// `bridge=` of a NIC, e.g. `net1`.
fn nic_bridge(config: &VmConfig, nic: &str) -> Option<String> {
    config
        .str(nic)?
        .split(',')
        .find_map(|part| part.strip_prefix("bridge=").map(str::to_owned))
}

/// MAC address of a NIC (`virtio=BC:24:...`).
fn nic_mac(config: &VmConfig, nic: &str) -> Option<String> {
    config.str(nic)?.split(',').find_map(|part| {
        part.split_once('=')
            .filter(|(model, _)| *model == "virtio")
            .map(|(_, mac)| mac.to_owned())
    })
}

fn has_firewall_flag(config: &VmConfig) -> bool {
    config
        .str("net0")
        .is_some_and(|n| n.split(',').any(|part| part == "firewall=1"))
}

/// `net0` with `firewall=1`, or `None` if it is already set.
fn net0_with_firewall(config: &VmConfig) -> Option<String> {
    let net0 = config.str("net0")?;
    if has_firewall_flag(config) {
        return None;
    }
    let parts: Vec<&str> = net0.split(',').filter(|p| *p != "firewall=0").collect();
    Some(format!("{},firewall=1", parts.join(",")))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn managed_names_end_in_an_instance_id() {
        let id = Uuid::nil();
        assert!(managed_name(&Reconciler::vm_name("web", id)));
        assert!(!managed_name("ubuntu-26.04-template"));
        assert!(!managed_name("dns"));
    }

    #[test]
    fn percent_decode_round_trips() {
        let original = "ssh-ed25519 AAA/+=\nx";
        assert_eq!(percent_decode(&percent_encode(original)), original);
    }
}
