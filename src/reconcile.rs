//! The reconciler. `advance` is called on every `PUT` and moves one VM a single
//! step closer to the requested generation; it returns the VM status only when
//! the VM matches the spec and runs (or is deliberately stopped).
//!
//! All state lives on the Proxmox VM: the name ends in the service instance id,
//! the tags carry the marker and the address, and the description holds the
//! accepted generation and spec as JSON.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::Arc,
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    auth::ProviderClaims,
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
}

pub struct Reconciler {
    pve: PveClient,
    settings: Settings,
    /// Serialises VMID and address allocation (the provider runs one replica).
    allocation: Mutex<()>,
}

/// Names of provider-managed VMs end in `-<32 hex>`, the instance id.
fn managed_name(name: &str) -> bool {
    name.len() > 33
        && name.as_bytes()[name.len() - 33] == b'-'
        && name[name.len() - 32..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Reconciler {
    pub fn new(pve: PveClient, settings: Settings) -> Arc<Self> {
        Arc::new(Self {
            pve,
            settings,
            allocation: Mutex::new(()),
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

    async fn find(&self, instance: Uuid) -> Result<Option<PveVm>, PveError> {
        let suffix = format!("-{}", instance.simple());
        Ok(self.pve.list_vms().await?.into_iter().find(|vm| {
            vm.name
                .as_deref()
                .is_some_and(|n| managed_name(n) && n.ends_with(&suffix))
        }))
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
        if meta.applied_generation < meta.generation {
            self.apply(&vm, &config, meta, &power).await?;
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
        let vms = self.pve.list_vms().await?;
        let managed = vms
            .iter()
            .filter(|vm| vm.name.as_deref().is_some_and(managed_name))
            .count();
        if managed >= self.settings.max_vms {
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
        self.pve
            .clone_template(
                template,
                vmid,
                &Self::vm_name(name, instance),
                &self.settings.storage,
            )
            .await?;
        Ok(())
    }

    fn desired_sshkeys(spec: &VmSpec) -> String {
        spec.ssh_authorized_keys
            .iter()
            .map(|k| k.trim())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn restart_needed(config: &VmConfig, spec: &VmSpec) -> bool {
        let keys_now = config
            .str("sshkeys")
            .map(|v| percent_decode(&v))
            .unwrap_or_default();
        config.u64("cores") != Some(u64::from(spec.cpu_cores))
            || config.u64("memory") != Some(u64::from(spec.memory_mib))
            || config.str("ciuser").as_deref() != Some(spec.username.as_str())
            || keys_now.trim() != Self::desired_sshkeys(spec).trim()
    }

    async fn address_for(&self, config: &VmConfig, vmid: u32) -> Result<Ipv4Addr, ReconcileError> {
        let own = config
            .str("tags")
            .and_then(|t| t.split([';', ',', ' ']).find_map(parse_ip_tag));
        if let Some(ip) = own {
            return Ok(ip);
        }
        let _guard = self.allocation.lock().await;
        let used: BTreeSet<Ipv4Addr> = self
            .pve
            .list_vms()
            .await?
            .iter()
            .filter(|vm| vm.vmid != vmid)
            .flat_map(|vm| {
                vm.tag_list()
                    .into_iter()
                    .filter_map(parse_ip_tag)
                    .collect::<Vec<_>>()
            })
            .collect();
        let ip = ipam::allocate(self.settings.ip_pool, &used).ok_or_else(|| {
            ReconcileError::Capacity("no free address left in the IP pool".into())
        })?;
        // Commit the address immediately so a concurrent allocation sees it.
        self.pve
            .set_config(
                vmid,
                &[("tags", format!("{TAG_MARKER};{}", ipam::ip_tag(ip)))],
            )
            .await?;
        Ok(ip)
    }

    async fn apply(
        &self,
        vm: &PveVm,
        config: &VmConfig,
        mut meta: VmMeta,
        power: &str,
    ) -> Result<(), ReconcileError> {
        let vmid = vm.vmid;
        let spec = meta.spec.clone();
        if power != "stopped" && Self::restart_needed(config, &spec) {
            // CPU, memory and cloud-init changes apply on the next boot.
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
        self.pve
            .set_config(
                vmid,
                &[
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
                        format!(
                            "ip={ip}/{},gw={}",
                            self.settings.network_prefix, self.settings.gateway
                        ),
                    ),
                    ("nameserver", self.settings.nameserver.to_string()),
                    ("searchdomain", self.settings.search_domain.clone()),
                    ("tags", format!("{TAG_MARKER};{}", ipam::ip_tag(ip))),
                    ("description", Self::describe(&meta)?),
                ],
            )
            .await?;
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
        match (power, meta.spec.stopped) {
            ("running", false) | ("stopped", true) => {
                Ok(Self::status_json(vm, config, meta, power))
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

    fn status_json(vm: &PveVm, config: &VmConfig, meta: &VmMeta, power: &str) -> Value {
        let ip = config
            .str("tags")
            .and_then(|t| t.split([';', ',', ' ']).find_map(parse_ip_tag));
        json!({
            "phase": "ready",
            "observed_generation": meta.applied_generation,
            "vmid": vm.vmid,
            "node": vm.node,
            "hostname": vm.name,
            "ip_address": ip.map(|ip| ip.to_string()),
            "power_state": power,
            "image": meta.spec.image,
            "cpu_cores": meta.spec.cpu_cores,
            "memory_mib": meta.spec.memory_mib,
            "disk_gib": meta.spec.disk_gib,
            "username": meta.spec.username,
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
            return Ok(Self::deleted_status(generation));
        };
        let config = self.locked_config(vm.vmid).await?;
        if let Some(meta) = Self::meta_of(&config) {
            Self::check_identity(&meta, claims)?;
            if generation < meta.generation {
                return Err(ReconcileError::Conflict("generation is stale".into()));
            }
        }
        if self.pve.power_state(vm.vmid).await? != "stopped" {
            self.pve.stop(vm.vmid).await?;
        } else {
            self.pve.destroy(vm.vmid).await?;
        }
        Err(ReconcileError::NotReady)
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
        Ok(Self::status_json(&vm, &config, &meta, &power))
    }
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
