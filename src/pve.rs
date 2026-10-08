//! A small Proxmox VE API client. It only covers what the provider needs and
//! authenticates exclusively with an API token.

use std::{collections::BTreeMap, time::Duration};

use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PveError {
    /// The Proxmox API could not be reached or answered with a server fault.
    #[error("Proxmox VE is unavailable: {0}")]
    Unavailable(String),
    #[error("the VM does not exist")]
    NotFound,
    #[error("the VM is locked")]
    Locked,
    #[error("Proxmox VE rejected the request ({status}): {message}")]
    Rejected { status: u16, message: String },
}

#[derive(Clone)]
pub struct PveClient {
    http: reqwest::Client,
    base: String,
    authorization: String,
    node: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PveVm {
    pub vmid: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub template: u8,
    #[serde(default)]
    pub tags: Option<String>,
}

impl PveVm {
    pub fn tag_list(&self) -> Vec<&str> {
        self.tags
            .as_deref()
            .map(|t| t.split([';', ',', ' ']).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }
}

/// `GET /nodes/{node}/qemu/{vmid}/config`
#[derive(Clone, Debug, Default)]
pub struct VmConfig(pub BTreeMap<String, Value>);

impl VmConfig {
    pub fn str(&self, key: &str) -> Option<String> {
        match self.0.get(key)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }
    pub fn u64(&self, key: &str) -> Option<u64> {
        self.str(key)?.parse().ok()
    }
    pub fn lock(&self) -> Option<String> {
        self.str("lock")
    }
    /// Size of `scsi0` in MiB, from the `size=` option of the disk string.
    pub fn disk_mib(&self, key: &str) -> Option<u64> {
        let disk = self.str(key)?;
        let size = disk
            .split(',')
            .find_map(|part| part.strip_prefix("size="))?;
        let (number, unit) = size.split_at(size.find(|c: char| !c.is_ascii_digit() && c != '.')?);
        let value: f64 = number.parse().ok()?;
        let mib = match unit {
            "K" => value / 1024.0,
            "M" => value,
            "G" => value * 1024.0,
            "T" => value * 1024.0 * 1024.0,
            _ => return None,
        };
        Some(mib.round() as u64)
    }
}

impl PveClient {
    pub fn new(
        base_url: &str,
        token_id: &str,
        token_secret: &str,
        node: &str,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, PveError> {
        // reqwest is built with `rustls-no-provider`; installing ring is idempotent.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .user_agent("tadokoro/0.1");
        if let Some(pem) = ca_pem {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| PveError::Unavailable(e.to_string()))?;
            builder = builder.tls_certs_merge([cert]);
        }
        let http = builder
            .build()
            .map_err(|e| PveError::Unavailable(e.to_string()))?;
        Ok(Self {
            http,
            base: format!("{}/api2/json", base_url.trim_end_matches('/')),
            authorization: format!("PVEAPIToken={token_id}={token_secret}"),
            node: node.to_owned(),
        })
    }

    pub fn node(&self) -> &str {
        &self.node
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        form: &[(&str, String)],
    ) -> Result<Value, PveError> {
        let url = format!("{}{}", self.base, path);
        let mut request = self
            .http
            .request(method, &url)
            .header("Authorization", &self.authorization);
        if !form.is_empty() {
            request = request.form(form);
        }
        let response = request
            .send()
            .await
            .map_err(|e| PveError::Unavailable(e.without_url().to_string()))?;
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(body.get("data").cloned().unwrap_or(Value::Null));
        }
        let message = body
            .get("message")
            .and_then(Value::as_str)
            .map(|m| m.trim().to_owned())
            .unwrap_or_else(|| status.to_string());
        if message.contains("does not exist") || status == StatusCode::NOT_FOUND {
            return Err(PveError::NotFound);
        }
        if message.contains("is locked") || message.contains("got timeout") {
            return Err(PveError::Locked);
        }
        if status.is_server_error() && !message.contains("Permission") {
            // PVE reports most operational failures as 500 with a message.
            return Err(PveError::Rejected {
                status: status.as_u16(),
                message,
            });
        }
        Err(PveError::Rejected {
            status: status.as_u16(),
            message,
        })
    }

    fn qemu(&self, vmid: u32, suffix: &str) -> String {
        format!("/nodes/{}/qemu/{}{}", self.node, vmid, suffix)
    }

    pub async fn list_vms(&self) -> Result<Vec<PveVm>, PveError> {
        let data = self
            .call(Method::GET, "/cluster/resources?type=vm", &[])
            .await?;
        let all: Vec<PveVm> =
            serde_json::from_value(data).map_err(|e| PveError::Unavailable(e.to_string()))?;
        Ok(all
            .into_iter()
            .filter(|vm| vm.node == self.node && vm.template == 0)
            .collect())
    }

    pub async fn next_id(&self) -> Result<u32, PveError> {
        let data = self.call(Method::GET, "/cluster/nextid", &[]).await?;
        data.as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| data.as_u64().and_then(|n| u32::try_from(n).ok()))
            .ok_or_else(|| PveError::Unavailable("unexpected nextid response".into()))
    }

    pub async fn clone_template(
        &self,
        template: u32,
        new_id: u32,
        name: &str,
        storage: &str,
    ) -> Result<(), PveError> {
        self.call(
            Method::POST,
            &self.qemu(template, "/clone"),
            &[
                ("newid", new_id.to_string()),
                ("name", name.to_owned()),
                ("full", "1".into()),
                ("storage", storage.to_owned()),
            ],
        )
        .await
        .map(|_| ())
    }

    pub async fn config(&self, vmid: u32) -> Result<VmConfig, PveError> {
        let data = self
            .call(Method::GET, &self.qemu(vmid, "/config"), &[])
            .await?;
        let map: BTreeMap<String, Value> =
            serde_json::from_value(data).map_err(|e| PveError::Unavailable(e.to_string()))?;
        Ok(VmConfig(map))
    }

    pub async fn set_config(&self, vmid: u32, params: &[(&str, String)]) -> Result<(), PveError> {
        self.call(Method::PUT, &self.qemu(vmid, "/config"), params)
            .await
            .map(|_| ())
    }

    pub async fn resize(&self, vmid: u32, disk: &str, size_gib: u32) -> Result<(), PveError> {
        self.call(
            Method::PUT,
            &self.qemu(vmid, "/resize"),
            &[("disk", disk.to_owned()), ("size", format!("{size_gib}G"))],
        )
        .await
        .map(|_| ())
    }

    pub async fn power_state(&self, vmid: u32) -> Result<String, PveError> {
        let data = self
            .call(Method::GET, &self.qemu(vmid, "/status/current"), &[])
            .await?;
        Ok(data
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned())
    }

    pub async fn start(&self, vmid: u32) -> Result<(), PveError> {
        self.call(Method::POST, &self.qemu(vmid, "/status/start"), &[])
            .await
            .map(|_| ())
    }

    /// ACPI shutdown that falls back to a hard stop after `timeout` seconds.
    pub async fn shutdown(&self, vmid: u32, timeout: u32) -> Result<(), PveError> {
        self.call(
            Method::POST,
            &self.qemu(vmid, "/status/shutdown"),
            &[("timeout", timeout.to_string()), ("forceStop", "1".into())],
        )
        .await
        .map(|_| ())
    }

    pub async fn stop(&self, vmid: u32) -> Result<(), PveError> {
        self.call(Method::POST, &self.qemu(vmid, "/status/stop"), &[])
            .await
            .map(|_| ())
    }

    pub async fn destroy(&self, vmid: u32) -> Result<(), PveError> {
        self.call(
            Method::DELETE,
            &format!(
                "{}?purge=1&destroy-unreferenced-disks=1",
                self.qemu(vmid, "")
            ),
            &[],
        )
        .await
        .map(|_| ())
    }
}

/// Percent-encodes every byte outside the RFC 3986 unreserved set. Proxmox
/// expects `sshkeys` in this form on top of the normal form encoding.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn disk_size_parses_units() {
        let cfg = |s: &str| VmConfig(BTreeMap::from([("scsi0".into(), Value::String(s.into()))]));
        assert_eq!(
            cfg("local-lvm:vm-1-disk-0,discard=on,size=3584M").disk_mib("scsi0"),
            Some(3584)
        );
        assert_eq!(
            cfg("local-lvm:vm-1-disk-0,size=20G").disk_mib("scsi0"),
            Some(20480)
        );
        assert_eq!(
            cfg("local-lvm:vm-1-disk-0,size=1T").disk_mib("scsi0"),
            Some(1_048_576)
        );
        assert_eq!(cfg("local-lvm:vm-1-disk-0").disk_mib("scsi0"), None);
    }

    #[test]
    fn percent_encoding_keeps_unreserved_only() {
        assert_eq!(
            percent_encode("ssh-ed25519 AAA/+=\nx"),
            "ssh-ed25519%20AAA%2F%2B%3D%0Ax"
        );
    }

    #[test]
    fn tags_split_on_any_separator() {
        let vm = PveVm {
            vmid: 1,
            name: None,
            node: "n".into(),
            status: "running".into(),
            template: 0,
            tags: Some("hc-vm;hc-ip-10-0-0-1 x".into()),
        };
        assert_eq!(vm.tag_list(), vec!["hc-vm", "hc-ip-10-0-0-1", "x"]);
    }
}
