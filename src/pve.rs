//! A small Proxmox VE API client. It only covers what the provider needs and
//! authenticates exclusively with an API token.

use std::{collections::BTreeMap, time::Duration};

use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

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
    base_url: String,
    ca_pem: Option<Vec<u8>>,
}

/// A WebSocket to the Proxmox serial terminal proxy.
pub type TerminalSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// What `termproxy` hands out: the one-time credentials for the terminal socket.
#[derive(Clone, Debug)]
pub struct TermProxy {
    pub port: u16,
    pub ticket: String,
    pub user: String,
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
            base_url: base_url.trim_end_matches('/').to_owned(),
            ca_pem: ca_pem.map(<[u8]>::to_vec),
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

    fn firewall(&self, vmid: u32, suffix: &str) -> String {
        format!("/nodes/{}/qemu/{}/firewall{}", self.node, vmid, suffix)
    }

    pub async fn fw_options(&self, vmid: u32) -> Result<VmConfig, PveError> {
        let data = self
            .call(Method::GET, &self.firewall(vmid, "/options"), &[])
            .await?;
        let map: BTreeMap<String, Value> =
            serde_json::from_value(data).map_err(|e| PveError::Unavailable(e.to_string()))?;
        Ok(VmConfig(map))
    }

    pub async fn set_fw_options(
        &self,
        vmid: u32,
        params: &[(&str, String)],
    ) -> Result<(), PveError> {
        self.call(Method::PUT, &self.firewall(vmid, "/options"), params)
            .await
            .map(|_| ())
    }

    pub async fn fw_rules(&self, vmid: u32) -> Result<Vec<Value>, PveError> {
        let data = self
            .call(Method::GET, &self.firewall(vmid, "/rules"), &[])
            .await?;
        serde_json::from_value(data).map_err(|e| PveError::Unavailable(e.to_string()))
    }

    pub async fn add_fw_rule(&self, vmid: u32, params: &[(&str, String)]) -> Result<(), PveError> {
        self.call(Method::POST, &self.firewall(vmid, "/rules"), params)
            .await
            .map(|_| ())
    }

    pub async fn delete_fw_rule(&self, vmid: u32, pos: u64) -> Result<(), PveError> {
        self.call(
            Method::DELETE,
            &self.firewall(vmid, &format!("/rules/{pos}")),
            &[],
        )
        .await
        .map(|_| ())
    }

    pub async fn fw_ipsets(&self, vmid: u32) -> Result<Vec<String>, PveError> {
        let data = self
            .call(Method::GET, &self.firewall(vmid, "/ipset"), &[])
            .await?;
        let items: Vec<Value> =
            serde_json::from_value(data).map_err(|e| PveError::Unavailable(e.to_string()))?;
        Ok(items
            .iter()
            .filter_map(|i| i.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect())
    }

    pub async fn create_fw_ipset(&self, vmid: u32, name: &str) -> Result<(), PveError> {
        self.call(
            Method::POST,
            &self.firewall(vmid, "/ipset"),
            &[("name", name.to_owned())],
        )
        .await
        .map(|_| ())
    }

    pub async fn fw_ipset_entries(&self, vmid: u32, name: &str) -> Result<Vec<String>, PveError> {
        let data = self
            .call(
                Method::GET,
                &self.firewall(vmid, &format!("/ipset/{name}")),
                &[],
            )
            .await?;
        let items: Vec<Value> =
            serde_json::from_value(data).map_err(|e| PveError::Unavailable(e.to_string()))?;
        Ok(items
            .iter()
            .filter_map(|i| i.get("cidr").and_then(Value::as_str).map(str::to_owned))
            .collect())
    }

    pub async fn add_fw_ipset_entry(
        &self,
        vmid: u32,
        name: &str,
        cidr: &str,
    ) -> Result<(), PveError> {
        self.call(
            Method::POST,
            &self.firewall(vmid, &format!("/ipset/{name}")),
            &[("cidr", cidr.to_owned())],
        )
        .await
        .map(|_| ())
    }

    pub async fn delete_fw_ipset_entry(
        &self,
        vmid: u32,
        name: &str,
        cidr: &str,
    ) -> Result<(), PveError> {
        self.call(
            Method::DELETE,
            &self.firewall(vmid, &format!("/ipset/{name}/{cidr}")),
            &[],
        )
        .await
        .map(|_| ())
    }

    /// Network interfaces as the guest agent sees them; empty while the agent is not running.
    pub async fn agent_interfaces(&self, vmid: u32) -> Result<Vec<Value>, PveError> {
        match self
            .call(
                Method::GET,
                &self.qemu(vmid, "/agent/network-get-interfaces"),
                &[],
            )
            .await
        {
            Ok(data) => Ok(data
                .get("result")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()),
            Err(PveError::Rejected { .. } | PveError::Unavailable(_)) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    /// Starts a serial terminal proxy for the VM and returns its one-time credentials.
    pub async fn termproxy(&self, vmid: u32) -> Result<TermProxy, PveError> {
        let data = self
            .call(Method::POST, &self.qemu(vmid, "/termproxy"), &[])
            .await?;
        let field = |name: &str| data.get(name).cloned().unwrap_or(Value::Null);
        let port = field("port")
            .as_u64()
            .or_else(|| field("port").as_str().and_then(|p| p.parse().ok()))
            .and_then(|p| u16::try_from(p).ok());
        match (port, field("ticket").as_str(), field("user").as_str()) {
            (Some(port), Some(ticket), Some(user)) => Ok(TermProxy {
                port,
                ticket: ticket.to_owned(),
                user: user.to_owned(),
            }),
            _ => Err(PveError::Unavailable(
                "unexpected termproxy response".into(),
            )),
        }
    }

    /// Starts a VNC proxy (the graphical console) for the VM; the ticket is also the VNC password.
    pub async fn vncproxy(&self, vmid: u32) -> Result<TermProxy, PveError> {
        let data = self
            .call(
                Method::POST,
                &self.qemu(vmid, "/vncproxy"),
                &[("websocket", "1".to_owned())],
            )
            .await?;
        let field = |name: &str| data.get(name).cloned().unwrap_or(Value::Null);
        let port = field("port")
            .as_u64()
            .or_else(|| field("port").as_str().and_then(|p| p.parse().ok()))
            .and_then(|p| u16::try_from(p).ok());
        match (port, field("ticket").as_str()) {
            (Some(port), Some(ticket)) => Ok(TermProxy {
                port,
                ticket: ticket.to_owned(),
                user: String::new(),
            }),
            _ => Err(PveError::Unavailable("unexpected vncproxy response".into())),
        }
    }

    /// Connects to the terminal proxy started by [`Self::termproxy`].
    pub async fn connect_terminal(
        &self,
        vmid: u32,
        proxy: &TermProxy,
    ) -> Result<TerminalSocket, PveError> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let ws_base = self
            .base_url
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        let url = format!(
            "{ws_base}/api2/json/nodes/{}/qemu/{vmid}/vncwebsocket?port={}&vncticket={}",
            self.node,
            proxy.port,
            percent_encode(&proxy.ticket)
        );
        let mut request = url
            .into_client_request()
            .map_err(|e| PveError::Unavailable(e.to_string()))?;
        let header = self
            .authorization
            .parse()
            .map_err(|_| PveError::Unavailable("invalid token header".into()))?;
        request.headers_mut().insert("Authorization", header);
        let connector = match &self.ca_pem {
            Some(pem) => {
                use rustls::pki_types::{CertificateDer, pem::PemObject};
                let mut roots = rustls::RootCertStore::empty();
                for cert in CertificateDer::pem_slice_iter(pem).flatten() {
                    roots
                        .add(cert)
                        .map_err(|e| PveError::Unavailable(e.to_string()))?;
                }
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                Some(Connector::Rustls(std::sync::Arc::new(config)))
            }
            None => None,
        };
        let (socket, _) = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector),
        )
        .await
        .map_err(|_| PveError::Unavailable("terminal connection timed out".into()))?
        .map_err(|e| PveError::Unavailable(e.to_string()))?;
        Ok(socket)
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
