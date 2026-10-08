//! Looks up the VM-facing virtual IPs of the Flash services in a VPC.
//!
//! The VPC provider publishes one `LoadBalancer` Service per member that has
//! `vm_access`, labelled with the VPC id. Tadokoro reads those Services (read-only)
//! so the VMs of the VPC may send to exactly those addresses.

use std::{collections::BTreeSet, net::Ipv4Addr, path::Path, time::Duration};

use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub const VPC_LABEL: &str = "vpc.heterocloud.io/network";
pub const VM_ACCESS_LABEL: &str = "vpc.heterocloud.io/vm-access";

#[derive(Debug, Error)]
pub enum FlashError {
    #[error("Kubernetes API request failed: {0}")]
    Request(String),
    #[error("Kubernetes API answered {0}")]
    Status(u16),
}

#[derive(Clone)]
pub struct FlashDirectory {
    http: reqwest::Client,
    base: String,
    namespace: String,
    token: String,
}

impl FlashDirectory {
    /// Uses the pod's service account (`/var/run/secrets/kubernetes.io/serviceaccount`).
    pub fn in_cluster(namespace: &str) -> Result<Self, FlashError> {
        let dir = Path::new("/var/run/secrets/kubernetes.io/serviceaccount");
        let token = std::fs::read_to_string(dir.join("token"))
            .map_err(|e| FlashError::Request(e.to_string()))?;
        let ca =
            std::fs::read(dir.join("ca.crt")).map_err(|e| FlashError::Request(e.to_string()))?;
        Self::new(
            "https://kubernetes.default.svc",
            namespace,
            token.trim(),
            Some(&ca),
        )
    }

    pub fn new(
        base: &str,
        namespace: &str,
        token: &str,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, FlashError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10));
        if let Some(pem) = ca_pem {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| FlashError::Request(e.to_string()))?;
            builder = builder.tls_certs_merge([cert]);
        }
        Ok(Self {
            http: builder
                .build()
                .map_err(|e| FlashError::Request(e.to_string()))?,
            base: base.trim_end_matches('/').to_owned(),
            namespace: namespace.to_owned(),
            token: token.to_owned(),
        })
    }

    /// Virtual IPs of the VPC's members that the VMs may reach.
    pub async fn vm_addresses(&self, vpc: Uuid) -> Result<BTreeSet<Ipv4Addr>, FlashError> {
        let url = format!(
            "{}/api/v1/namespaces/{}/services",
            self.base, self.namespace
        );
        let response = self
            .http
            .get(url)
            .query(&[(
                "labelSelector",
                format!("{VPC_LABEL}={vpc},{VM_ACCESS_LABEL}=true"),
            )])
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| FlashError::Request(e.without_url().to_string()))?;
        if !response.status().is_success() {
            return Err(FlashError::Status(response.status().as_u16()));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|e| FlashError::Request(e.to_string()))?;
        Ok(parse_addresses(&body))
    }
}

fn parse_addresses(list: &Value) -> BTreeSet<Ipv4Addr> {
    list["items"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|item| {
            item["status"]["loadBalancer"]["ingress"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter_map(|ingress| ingress["ip"].as_str()?.parse().ok())
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn collects_only_ipv4_load_balancer_addresses() {
        let list = json!({"items": [
            {"status": {"loadBalancer": {"ingress": [{"ip": "10.100.3.1"}]}}},
            {"status": {"loadBalancer": {"ingress": [{"hostname": "x"}, {"ip": "fd00::1"}]}}},
            {"status": {"loadBalancer": {}}},
            {"status": {"loadBalancer": {"ingress": [{"ip": "10.100.3.2"}, {"ip": "10.100.3.1"}]}}}
        ]});
        let ips: Vec<String> = parse_addresses(&list)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(ips, vec!["10.100.3.1", "10.100.3.2"]);
        assert!(parse_addresses(&json!({})).is_empty());
    }
}
