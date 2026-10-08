//! Dynamic DNS registration (RFC 2136 with TSIG) of VM and Flash service names.
//!
//! Names live in two subtrees of the zone: `vm.<zone>` and `vpc.<zone>`.
//!
//! ```text
//! <slug>-<id8>.vm.<zone>              a VM, globally unique
//! <slug>.vm.<vpc8>.vpc.<zone>         the same VM inside its VPC
//! <name>.svc.<vpc8>.vpc.<zone>        a Flash service of the VPC (its VM-facing virtual IP)
//! ```
//!
//! The desired set is computed from the Proxmox and Kubernetes state and compared with
//! a zone transfer, so records of VMs or services that disappeared are removed too.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use hickory_proto::{
    op::{Message, ResponseCode, update_message, update_message::UpdateMessage},
    rr::{
        DNSClass, Name, RData, Record, RecordType, TSigner,
        rdata::{A, tsig::TsigAlgorithm},
    },
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use uuid::Uuid;

use crate::spec::slug;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AXFR_MESSAGES: usize = 4096;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("invalid DNS configuration: {0}")]
    Config(String),
    #[error("DNS request failed: {0}")]
    Io(String),
    #[error("DNS server answered {0}")]
    Rcode(String),
}

fn io(error: impl std::fmt::Display) -> DnsError {
    DnsError::Io(error.to_string())
}

pub type Records = BTreeMap<String, BTreeSet<Ipv4Addr>>;

#[derive(Clone)]
pub struct DnsUpdater {
    server: SocketAddr,
    zone: Name,
    zone_text: String,
    signer: TSigner,
    ttl: u32,
}

impl DnsUpdater {
    /// `key_text` is a BIND `key "name" { algorithm hmac-sha256; secret "…"; };` block.
    pub fn new(server: SocketAddr, zone: &str, key_text: &str, ttl: u32) -> Result<Self, DnsError> {
        let (name, algorithm, secret) = parse_bind_key(key_text)?;
        let signer = TSigner::new(secret, algorithm, Name::from_ascii(&name).map_err(io)?, 300)
            .map_err(|e| DnsError::Config(e.to_string()))?;
        let zone_text = zone.trim_end_matches('.').to_ascii_lowercase();
        Ok(Self {
            server,
            zone: Name::from_ascii(format!("{zone_text}.")).map_err(io)?,
            zone_text,
            signer,
            ttl,
        })
    }

    pub fn zone(&self) -> &str {
        &self.zone_text
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    async fn update(&self, name: &str, ips: &BTreeSet<Ipv4Addr>) -> Result<(), DnsError> {
        let owner = Name::from_ascii(name).map_err(io)?;
        let mut message = update_message::delete_rrset(
            Record::update0(owner.clone(), 0, RecordType::A),
            self.zone.clone(),
            false,
        );
        for ip in ips {
            message.add_update(Record::from_rdata(
                owner.clone(),
                self.ttl,
                RData::A(A(*ip)),
            ));
        }
        let verifier = message.finalize(&self.signer, Self::now()).map_err(io)?;
        let bytes = message.to_vec().map_err(io)?;
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(io)?;
        socket.connect(self.server).await.map_err(io)?;
        socket.send(&bytes).await.map_err(io)?;
        let mut buffer = vec![0u8; 4096];
        let length = timeout(IO_TIMEOUT, socket.recv(&mut buffer))
            .await
            .map_err(io)?
            .map_err(io)?;
        let response = match verifier {
            Some(mut verifier) => verifier
                .verify(&buffer[..length])
                .map_err(io)?
                .into_message(),
            None => Message::from_vec(&buffer[..length]).map_err(io)?,
        };
        if response.metadata.response_code != ResponseCode::NoError {
            return Err(DnsError::Rcode(response.metadata.response_code.to_string()));
        }
        Ok(())
    }

    /// Sets the A records of `name` to exactly `ips` (an empty set removes the name's A records).
    pub async fn replace(&self, name: &str, ips: &BTreeSet<Ipv4Addr>) -> Result<(), DnsError> {
        self.update(name, ips).await
    }

    pub async fn delete(&self, name: &str) -> Result<(), DnsError> {
        self.update(name, &BTreeSet::new()).await
    }

    /// The A records currently below the given subtrees (`vm.<zone>`, `vpc.<zone>`), by zone transfer.
    pub async fn snapshot(&self, roots: &[String]) -> Result<Records, DnsError> {
        let mut query = update_message::zone_transfer(self.zone.clone(), None);
        let _ = query.finalize(&self.signer, Self::now()).map_err(io)?;
        let bytes = query.to_vec().map_err(io)?;
        let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(self.server))
            .await
            .map_err(io)?
            .map_err(io)?;
        let length = u16::try_from(bytes.len()).map_err(io)?;
        stream.write_all(&length.to_be_bytes()).await.map_err(io)?;
        stream.write_all(&bytes).await.map_err(io)?;

        let mut found = Records::new();
        let mut soa_seen = 0;
        for _ in 0..MAX_AXFR_MESSAGES {
            let mut prefix = [0u8; 2];
            timeout(IO_TIMEOUT, stream.read_exact(&mut prefix))
                .await
                .map_err(io)?
                .map_err(io)?;
            let mut buffer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            timeout(IO_TIMEOUT, stream.read_exact(&mut buffer))
                .await
                .map_err(io)?
                .map_err(io)?;
            // The transfer is read-only input: a forged one could at worst make us rewrite our own subtrees.
            let message = Message::from_vec(&buffer).map_err(io)?;
            if message.metadata.response_code != ResponseCode::NoError {
                return Err(DnsError::Rcode(message.metadata.response_code.to_string()));
            }
            for record in &message.answers {
                match &record.data {
                    RData::SOA(_) => soa_seen += 1,
                    RData::A(A(ip)) if record.dns_class == DNSClass::IN => {
                        let name = record.name.to_ascii().to_ascii_lowercase();
                        if roots.iter().any(|root| name.ends_with(&format!(".{root}"))) {
                            found.entry(name).or_default().insert(*ip);
                        }
                    }
                    _ => {}
                }
            }
            if soa_seen >= 2 {
                return Ok(found);
            }
        }
        Err(DnsError::Io("zone transfer did not finish".into()))
    }

    /// Roots of the subtrees this provider owns.
    pub fn roots(&self) -> Vec<String> {
        vec![
            format!("vm.{}.", self.zone_text),
            format!("vpc.{}.", self.zone_text),
        ]
    }

    /// Brings the owned subtrees in line with `desired`. Returns (changed, removed).
    pub async fn reconcile(&self, desired: &Records) -> Result<(usize, usize), DnsError> {
        let current = self.snapshot(&self.roots()).await?;
        let plan = diff(&current, desired);
        for (name, ips) in &plan.replace {
            self.replace(name, ips).await?;
        }
        for name in &plan.delete {
            self.delete(name).await?;
        }
        Ok((plan.replace.len(), plan.delete.len()))
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Plan {
    pub replace: Vec<(String, BTreeSet<Ipv4Addr>)>,
    pub delete: Vec<String>,
}

/// What to change so that `current` becomes `desired`.
pub fn diff(current: &Records, desired: &Records) -> Plan {
    Plan {
        replace: desired
            .iter()
            .filter(|(name, ips)| current.get(*name) != Some(*ips))
            .map(|(name, ips)| (name.clone(), ips.clone()))
            .collect(),
        delete: current
            .keys()
            .filter(|name| !desired.contains_key(*name))
            .cloned()
            .collect(),
    }
}

fn parse_bind_key(text: &str) -> Result<(String, TsigAlgorithm, Vec<u8>), DnsError> {
    let quoted = |after: &str| -> Option<String> {
        let rest = &text[text.find(after)? + after.len()..];
        let start = rest.find('"')? + 1;
        let end = start + rest[start..].find('"')?;
        Some(rest[start..end].to_owned())
    };
    let name = quoted("key").ok_or_else(|| DnsError::Config("key name not found".into()))?;
    let secret = quoted("secret").ok_or_else(|| DnsError::Config("key secret not found".into()))?;
    let algorithm = text
        .split("algorithm")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .map(str::trim)
        .ok_or_else(|| DnsError::Config("key algorithm not found".into()))?;
    let algorithm = TsigAlgorithm::from_name(Name::from_ascii(algorithm).map_err(io)?);
    let secret = base64::engine::general_purpose::STANDARD
        .decode(secret.trim())
        .map_err(|e| DnsError::Config(format!("key secret is not base64: {e}")))?;
    Ok((name, algorithm, secret))
}

/// Eight hex digits that identify an id inside a DNS name. UUIDv7 starts with a
/// millisecond timestamp (equal for everything created within about a minute), so the
/// random tail is used instead.
fn short(id: Uuid) -> String {
    let simple = id.simple().to_string();
    simple[simple.len() - 8..].to_owned()
}

pub fn vm_canonical_name(zone: &str, display: &str, instance: Uuid) -> String {
    format!("{}-{}.vm.{zone}.", slug(display), short(instance))
}

pub fn vm_vpc_alias(zone: &str, display: &str, vpc: Uuid) -> String {
    format!("{}.vm.{}.vpc.{zone}.", slug(display), short(vpc))
}

pub fn service_name(zone: &str, private_name: &str, vpc: Uuid) -> String {
    format!("{private_name}.svc.{}.vpc.{zone}.", short(vpc))
}

pub fn parse_socket(value: &str) -> Result<SocketAddr, DnsError> {
    SocketAddr::from_str(value)
        .map_err(|e| DnsError::Config(format!("DNS server must be host:port: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const KEY: &str = "key \"tadokoro-update\" {\n\talgorithm hmac-sha256;\n\tsecret \"c2VjcmV0LXNlY3JldC1zZWNyZXQtMTIzNDU2Nzg5MA==\";\n};\n";

    #[test]
    fn parses_a_bind_key_file() {
        let (name, algorithm, secret) = parse_bind_key(KEY).unwrap();
        assert_eq!(name, "tadokoro-update");
        assert_eq!(algorithm, TsigAlgorithm::HmacSha256);
        assert_eq!(secret, b"secret-secret-secret-1234567890");
        assert!(parse_bind_key("nothing here").is_err());
        assert!(parse_bind_key("key \"k\" { algorithm hmac-sha256; secret \"!!\"; };").is_err());
    }

    #[test]
    fn diff_replaces_changed_names_and_deletes_stale_ones() {
        let set = |ips: &[&str]| -> BTreeSet<Ipv4Addr> {
            ips.iter().map(|i| i.parse().unwrap()).collect()
        };
        let current = Records::from([
            ("same.vm.z.".to_owned(), set(&["10.0.0.1"])),
            ("moved.vm.z.".to_owned(), set(&["10.0.0.2"])),
            ("gone.vm.z.".to_owned(), set(&["10.0.0.3"])),
        ]);
        let desired = Records::from([
            ("same.vm.z.".to_owned(), set(&["10.0.0.1"])),
            ("moved.vm.z.".to_owned(), set(&["10.0.0.9"])),
            ("new.vm.z.".to_owned(), set(&["10.0.0.4", "10.0.0.5"])),
        ]);
        let plan = diff(&current, &desired);
        assert_eq!(
            plan.replace,
            vec![
                ("moved.vm.z.".to_owned(), set(&["10.0.0.9"])),
                ("new.vm.z.".to_owned(), set(&["10.0.0.4", "10.0.0.5"])),
            ]
        );
        assert_eq!(plan.delete, vec!["gone.vm.z.".to_owned()]);
        assert_eq!(diff(&desired, &desired), Plan::default());
    }

    #[test]
    fn ids_created_in_the_same_minute_still_get_distinct_names() {
        // UUIDv7 values created together share their first 32 bits.
        let a = Uuid::parse_str("01a11c42-96d9-7e32-ac11-59bf7c029ac5").unwrap();
        let b = Uuid::parse_str("01a11c42-96da-7a10-8d4e-2bb41f0c13e8").unwrap();
        assert_ne!(
            vm_canonical_name("z", "web", a),
            vm_canonical_name("z", "web", b)
        );
        assert_ne!(vm_vpc_alias("z", "web", a), vm_vpc_alias("z", "web", b));
    }

    #[test]
    fn names_are_scoped_and_dns_safe() {
        let instance = Uuid::parse_str("01a11b4d-4e81-7941-81fa-2bb4e3eaef7a").unwrap();
        let vpc = Uuid::parse_str("01a11bb6-97ba-75a2-b448-2869e704e24f").unwrap();
        assert_eq!(
            vm_canonical_name("hetero.internal", "Web Server", instance),
            "web-server-e3eaef7a.vm.hetero.internal."
        );
        assert_eq!(
            vm_vpc_alias("hetero.internal", "Web Server", vpc),
            "web-server.vm.e704e24f.vpc.hetero.internal."
        );
        assert_eq!(
            service_name("hetero.internal", "web", vpc),
            "web.svc.e704e24f.vpc.hetero.internal."
        );
        for name in [
            vm_canonical_name("hetero.internal", "!!!", instance),
            vm_vpc_alias("hetero.internal", "A_b", vpc),
        ] {
            assert!(Name::from_ascii(&name).is_ok(), "{name}");
        }
    }
}
