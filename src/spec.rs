//! The strict VM specification HeteroCloud forwards unchanged to this provider.

use std::{collections::BTreeMap, net::Ipv4Addr};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub const MAX_NAME_BYTES: usize = 120;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmSpec {
    pub region: String,
    /// Image name that maps to a template on the configured node.
    pub image: String,
    pub cpu_cores: u32,
    pub memory_mib: u32,
    pub disk_gib: u32,
    /// OpenSSH public keys installed for `username` through cloud-init.
    pub ssh_authorized_keys: Vec<String>,
    #[serde(default = "default_username")]
    pub username: String,
    /// Keep the VM defined but powered off.
    #[serde(default)]
    pub stopped: bool,
    #[serde(default)]
    pub network: VmNetwork,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

pub const MAX_INGRESS_RULES: usize = 32;
pub const MAX_SOURCE_CIDRS: usize = 16;
pub const MAX_DESTINATION_CIDRS: usize = 32;

/// Every VM runs behind a default-deny Proxmox firewall; this opens it up.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmNetwork {
    /// VMs with the same VPC id may talk to each other in both directions.
    #[serde(default)]
    pub vpc_id: Option<Uuid>,
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
    #[serde(default)]
    pub egress: Egress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngressRule {
    pub protocol: Protocol,
    /// `22` or `8000-8100`; required for tcp/udp and not allowed for icmp.
    #[serde(default)]
    pub ports: Option<String>,
    pub source_cidrs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    Disabled,
    Restricted,
    #[default]
    Internet,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    #[serde(default)]
    pub mode: EgressMode,
    /// Only with `restricted`; may not overlap the private ranges below.
    #[serde(default)]
    pub allowed_destination_cidrs: Vec<String>,
    #[serde(default)]
    pub denied_destination_cidrs: Vec<String>,
}

/// Always blocked towards the internet; infrastructure and other tenants live here.
pub const PROTECTED_NETWORKS: [&str; 8] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/3",
];

/// Parses an IPv4 address or CIDR (a bare address is a /32).
pub fn parse_cidr(value: &str) -> Option<Ipv4Net> {
    if value.is_empty() || value.trim() != value {
        return None;
    }
    value
        .parse::<Ipv4Net>()
        .ok()
        .or_else(|| value.parse::<Ipv4Addr>().ok().map(Ipv4Net::from))
}

fn default_username() -> String {
    "ubuntu".into()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SpecError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(message: impl Into<String>) -> Result<T, SpecError> {
    Err(SpecError::Invalid(message.into()))
}

impl VmSpec {
    pub fn validate(&self, region: &str, images: &BTreeMap<String, u32>) -> Result<(), SpecError> {
        if self.region != region {
            return invalid(format!("region must be {region}"));
        }
        if !images.contains_key(&self.image) {
            return invalid(format!("unknown image {}", self.image));
        }
        if !(1..=16).contains(&self.cpu_cores) {
            return invalid("cpu_cores must be between 1 and 16");
        }
        if !(512..=131_072).contains(&self.memory_mib) {
            return invalid("memory_mib must be between 512 and 131072");
        }
        if !(8..=2048).contains(&self.disk_gib) {
            return invalid("disk_gib must be between 8 and 2048");
        }
        if self.ssh_authorized_keys.is_empty() || self.ssh_authorized_keys.len() > 8 {
            return invalid("between 1 and 8 ssh_authorized_keys are required");
        }
        for key in &self.ssh_authorized_keys {
            validate_ssh_key(key)?;
        }
        validate_username(&self.username)?;
        self.network.validate()?;
        let metadata = serde_json::to_vec(&self.metadata)
            .map_err(|_| SpecError::Invalid("metadata is not serializable".into()))?;
        if metadata.len() > 64 * 1024 {
            return invalid("metadata must not exceed 64 KiB");
        }
        Ok(())
    }
}

impl VmNetwork {
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.ingress.len() > MAX_INGRESS_RULES {
            return invalid(format!(
                "at most {MAX_INGRESS_RULES} ingress rules are allowed"
            ));
        }
        for rule in &self.ingress {
            rule.validate()?;
        }
        let egress = &self.egress;
        let allowed = parse_cidrs(
            "allowed_destination_cidrs",
            &egress.allowed_destination_cidrs,
            MAX_DESTINATION_CIDRS,
        )?;
        parse_cidrs(
            "denied_destination_cidrs",
            &egress.denied_destination_cidrs,
            MAX_DESTINATION_CIDRS,
        )?;
        if egress.mode != EgressMode::Restricted && !allowed.is_empty() {
            return invalid("allowed_destination_cidrs requires restricted egress mode");
        }
        for network in &allowed {
            let overlaps = PROTECTED_NETWORKS
                .iter()
                .filter_map(|p| p.parse::<Ipv4Net>().ok())
                .any(|p| p.contains(network) || network.contains(&p));
            if overlaps {
                return invalid(format!(
                    "allowed destination {network} overlaps a protected private or infrastructure network"
                ));
            }
        }
        Ok(())
    }
}

impl IngressRule {
    fn validate(&self) -> Result<(), SpecError> {
        match (self.protocol, &self.ports) {
            (Protocol::Icmp, None) => {}
            (Protocol::Icmp, Some(_)) => return invalid("icmp ingress rules cannot have ports"),
            (_, None) => return invalid("tcp and udp ingress rules require ports"),
            (_, Some(ports)) => {
                port_range(ports).ok_or_else(|| {
                    SpecError::Invalid("ports must be a port or a range such as 8000-8100".into())
                })?;
            }
        }
        if self.source_cidrs.is_empty() {
            return invalid("ingress rules require at least one source CIDR");
        }
        parse_cidrs("source_cidrs", &self.source_cidrs, MAX_SOURCE_CIDRS).map(|_| ())
    }
}

/// `22` -> (22, 22); `8000-8100` -> (8000, 8100).
pub fn port_range(value: &str) -> Option<(u16, u16)> {
    let (start, end) = match value.split_once('-') {
        Some((a, b)) => (a, b),
        None => (value, value),
    };
    let (start, end): (u16, u16) = (start.parse().ok()?, end.parse().ok()?);
    (start >= 1 && start <= end).then_some((start, end))
}

fn parse_cidrs(field: &str, values: &[String], maximum: usize) -> Result<Vec<Ipv4Net>, SpecError> {
    if values.len() > maximum {
        return invalid(format!("{field} must contain at most {maximum} entries"));
    }
    values
        .iter()
        .map(|v| {
            parse_cidr(v).ok_or_else(|| {
                SpecError::Invalid(format!("{field} entries must be IPv4 addresses or CIDRs"))
            })
        })
        .collect()
}

fn validate_username(value: &str) -> Result<(), SpecError> {
    let mut chars = value.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    let rest_ok =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'));
    if first_ok && rest_ok && value.len() <= 32 && value != "root" {
        Ok(())
    } else {
        invalid("username must be a lowercase Linux user name other than root")
    }
}

fn validate_ssh_key(value: &str) -> Result<(), SpecError> {
    const TYPES: [&str; 5] = [
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ];
    let mut parts = value.split_whitespace();
    let (Some(kind), Some(blob)) = (parts.next(), parts.next()) else {
        return invalid("ssh_authorized_keys entries must be OpenSSH public keys");
    };
    let blob_ok = blob.len() >= 16
        && blob.len() <= 4096
        && blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    // The comment may contain spaces but never control characters or newlines.
    let clean = value.len() <= 8192 && !value.chars().any(char::is_control);
    if TYPES.contains(&kind) && blob_ok && clean && key_blob_matches(kind, blob) {
        Ok(())
    } else {
        invalid("ssh_authorized_keys entries must be OpenSSH public keys")
    }
}

/// Whether `blob` is a well-formed OpenSSH public key body of type `kind`: Proxmox rejects
/// keys it cannot parse, which would otherwise leave the VM retrying forever.
fn key_blob_matches(kind: &str, blob: &str) -> bool {
    use base64::Engine as _;
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(blob) else {
        return false;
    };
    let mut rest = bytes.as_slice();
    let mut fields: Vec<&[u8]> = Vec::new();
    while !rest.is_empty() {
        let Some((len, tail)) = rest.split_first_chunk::<4>() else {
            return false;
        };
        let len = u32::from_be_bytes(*len) as usize;
        if len > tail.len() {
            return false;
        }
        let (field, tail) = tail.split_at(len);
        fields.push(field);
        rest = tail;
    }
    let Some((name, body)) = fields.split_first() else {
        return false;
    };
    if *name != kind.as_bytes() {
        return false;
    }
    match kind {
        "ssh-ed25519" => body.len() == 1 && body[0].len() == 32,
        "ssh-rsa" => body.len() == 2 && !body[0].is_empty() && body[1].len() >= 128,
        _ => body.len() == 2 && !body[1].is_empty(),
    }
}

/// Lower-case DNS label made from a display name; never empty, at most 25 bytes.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
        if out.len() >= 25 {
            break;
        }
    }
    let trimmed = out.trim_end_matches('-').to_owned();
    if trimmed.is_empty() {
        "vm".into()
    } else {
        trimmed
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn images() -> BTreeMap<String, u32> {
        BTreeMap::from([("ubuntu-26.04".to_owned(), 9000)])
    }

    fn spec() -> VmSpec {
        serde_json::from_value(serde_json::json!({
            "region": "heteronet-global",
            "image": "ubuntu-26.04",
            "cpu_cores": 2,
            "memory_mib": 2048,
            "disk_gib": 20,
            "ssh_authorized_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAERHnScWeyI8R9LNgXVEJGjb/Cg8sopnWQJlfqkOv02 me@host"]
        }))
        .expect("valid spec")
    }

    #[test]
    fn accepts_a_valid_spec() {
        assert_eq!(spec().validate("heteronet-global", &images()), Ok(()));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        let bad = serde_json::from_value::<VmSpec>(serde_json::json!({"region": "r", "extra": 1}));
        assert!(bad.is_err());
        let mut s = spec();
        s.cpu_cores = 0;
        assert!(s.validate("heteronet-global", &images()).is_err());
        let mut s = spec();
        s.image = "nope".into();
        assert!(s.validate("heteronet-global", &images()).is_err());
        let mut s = spec();
        s.username = "root".into();
        assert!(s.validate("heteronet-global", &images()).is_err());
        let mut s = spec();
        s.ssh_authorized_keys = vec!["ssh-ed25519 AAAAAjiosdjgdsgsdg0964tlsjgsdjgsodjgsdg".into()];
        assert!(
            s.validate("heteronet-global", &images()).is_err(),
            "well-shaped but not a key"
        );
        s.ssh_authorized_keys = vec!["not a key".into()];
        assert!(s.validate("heteronet-global", &images()).is_err());
        let mut s = spec();
        s.ssh_authorized_keys =
            vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAERHnScWeyI8R9\nssh-rsa AAAA".into()];
        assert!(s.validate("heteronet-global", &images()).is_err());
        assert!(spec().validate("other-region", &images()).is_err());
    }

    #[test]
    fn slug_is_a_dns_label() {
        assert_eq!(slug("My Web Server!!"), "my-web-server");
        assert_eq!(slug("!!!"), "vm");
        assert!(slug(&"a".repeat(80)).len() <= 25);
    }
}
