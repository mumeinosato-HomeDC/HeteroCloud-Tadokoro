//! The per-VM Proxmox firewall policy.
//!
//! Every VM gets a default-deny firewall (`policy_in = policy_out = DROP`) plus
//! `ipfilter` and `macfilter` against address and MAC spoofing. The rules below
//! are derived from the VM spec and rewritten whole, so they never drift.
//! Replies need no rule: established and related connections always pass.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde_json::Value;

use crate::spec::{EgressMode, PROTECTED_NETWORKS, Protocol, VmSpec, parse_cidr};

pub const COMMENT: &str = "tadokoro";
/// VM-scoped IP set with the addresses of the other VMs in the same VPC.
pub const VPC_IPSET: &str = "vpc";
/// Addresses Flash traffic into the VPC arrives from (pod traffic is translated to a node address).
pub const FLASH_SRC_IPSET: &str = "flash-src";
/// Virtual IPs of the VPC's Flash services, which the VM may send to.
pub const FLASH_VIP_IPSET: &str = "flash-vip";

/// VM-scoped IP set Proxmox uses for `ipfilter` on `net0`.
pub const IPFILTER_IPSET: &str = "ipfilter-net0";

/// VM-scoped IP set Proxmox uses for `ipfilter` on `net1` (the external NIC).
pub const EXTERNAL_IPFILTER_IPSET: &str = "ipfilter-net1";

/// Desired firewall options of the VM. DHCP is only let through when there is an
/// external NIC that needs it.
pub fn options(external: bool) -> [(&'static str, &'static str); 8] {
    [
        ("enable", "1"),
        ("policy_in", "DROP"),
        ("policy_out", "DROP"),
        ("ipfilter", "1"),
        ("macfilter", "1"),
        ("dhcp", if external { "1" } else { "0" }),
        ("ndp", "0"),
        ("radv", "0"),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FwRule {
    /// `in` or `out`.
    pub direction: &'static str,
    pub action: &'static str,
    pub proto: Option<&'static str>,
    pub dport: Option<String>,
    pub sport: Option<String>,
    pub source: Option<String>,
    pub dest: Option<String>,
}

impl FwRule {
    fn out(
        action: &'static str,
        proto: Option<&'static str>,
        dport: Option<&str>,
        dest: Option<String>,
    ) -> Self {
        Self {
            direction: "out",
            action,
            proto,
            dport: dport.map(str::to_owned),
            sport: None,
            source: None,
            dest,
        }
    }

    /// Form parameters for `POST .../firewall/rules`.
    pub fn params(&self) -> Vec<(&'static str, String)> {
        let mut params = vec![
            ("type", self.direction.to_owned()),
            ("action", self.action.to_owned()),
            ("enable", "1".to_owned()),
            ("comment", COMMENT.to_owned()),
        ];
        for (key, value) in [
            ("proto", self.proto.map(str::to_owned)),
            ("dport", self.dport.clone()),
            ("sport", self.sport.clone()),
            ("source", self.source.clone()),
            ("dest", self.dest.clone()),
        ] {
            if let Some(value) = value {
                params.push((key, value));
            }
        }
        params
    }

    /// Whether a rule returned by `GET .../firewall/rules` is this rule.
    pub fn matches(&self, current: &Value) -> bool {
        let field = |name: &str| {
            current.get(name).and_then(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .or_else(|| v.as_u64().map(|n| n.to_string()))
            })
        };
        field("type").as_deref() == Some(self.direction)
            && field("action").as_deref() == Some(self.action)
            && field("proto").as_deref() == self.proto
            && field("dport") == self.dport
            && field("sport") == self.sport
            && field("source") == self.source
            && field("dest") == self.dest
            && field("comment").as_deref() == Some(COMMENT)
            && field("enable").as_deref() != Some("0")
    }
}

fn cidr_text(network: Ipv4Net) -> String {
    if network.prefix_len() == 32 {
        network.addr().to_string()
    } else {
        network.to_string()
    }
}

fn join_cidrs(values: &[String]) -> String {
    values
        .iter()
        .filter_map(|v| parse_cidr(v))
        .map(cidr_text)
        .collect::<Vec<_>>()
        .join(",")
}

/// Proxmox writes port ranges as `8000:8100`.
fn proxmox_ports(ports: &str) -> String {
    ports.replace('-', ":")
}

/// The complete, ordered rule list. First match wins, the policy is DROP.
pub fn rules(spec: &VmSpec, nameserver: Ipv4Addr) -> Vec<FwRule> {
    let network = &spec.network;
    let mut rules = Vec::new();

    // Inbound.
    if network.vpc_id.is_some() {
        for set in [VPC_IPSET, FLASH_SRC_IPSET] {
            rules.push(FwRule {
                direction: "in",
                action: "ACCEPT",
                proto: None,
                dport: None,
                sport: None,
                source: Some(format!("+{set}")),
                dest: None,
            });
        }
    }
    for rule in &network.ingress {
        let proto = match rule.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
        };
        rules.push(FwRule {
            direction: "in",
            action: "ACCEPT",
            proto: Some(proto),
            dport: rule.ports.as_deref().map(proxmox_ports),
            sport: None,
            source: Some(join_cidrs(&rule.source_cidrs)),
            dest: None,
        });
    }

    // Outbound: name resolution always works, even with egress disabled.
    for proto in ["udp", "tcp"] {
        rules.push(FwRule::out(
            "ACCEPT",
            Some(proto),
            Some("53"),
            Some(nameserver.to_string()),
        ));
    }
    // Answers to allowed inbound connections. Connection tracking normally lets them out, but not
    // for traffic that is routed to the VM (the external NIC): a source in a private range would
    // otherwise run into the protected-network drop below.
    for rule in &network.ingress {
        let proto = match rule.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
        };
        let mut reply = FwRule::out(
            "ACCEPT",
            Some(proto),
            None,
            Some(join_cidrs(&rule.source_cidrs)),
        );
        reply.sport = rule.ports.as_deref().map(proxmox_ports);
        rules.push(reply);
    }
    if network.vpc_id.is_some() {
        for set in [VPC_IPSET, FLASH_VIP_IPSET] {
            rules.push(FwRule::out("ACCEPT", None, None, Some(format!("+{set}"))));
        }
    }
    let egress = &network.egress;
    if !egress.denied_destination_cidrs.is_empty() {
        rules.push(FwRule::out(
            "DROP",
            None,
            None,
            Some(join_cidrs(&egress.denied_destination_cidrs)),
        ));
    }
    match egress.mode {
        EgressMode::Disabled => {}
        EgressMode::Restricted => {
            if !egress.allowed_destination_cidrs.is_empty() {
                rules.push(FwRule::out(
                    "ACCEPT",
                    None,
                    None,
                    Some(join_cidrs(&egress.allowed_destination_cidrs)),
                ));
            }
        }
        EgressMode::Internet => {
            rules.push(FwRule::out(
                "DROP",
                None,
                None,
                Some(PROTECTED_NETWORKS.join(",")),
            ));
            rules.push(FwRule::out("ACCEPT", None, None, None));
        }
    }
    rules
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec(network: Value) -> VmSpec {
        serde_json::from_value(json!({
            "region": "heteronet-global", "image": "ubuntu-26.04", "cpu_cores": 1, "memory_mib": 1024, "disk_gib": 10,
            "ssh_authorized_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAERHnScWeyI8R9LNgXVEJGjb/Cg8sopnWQJlfqkOv02 me@host"],
            "network": network
        }))
        .unwrap()
    }

    fn ns() -> Ipv4Addr {
        Ipv4Addr::new(10, 100, 0, 2)
    }

    fn summary(rules: &[FwRule]) -> Vec<String> {
        rules
            .iter()
            .map(|r| {
                format!(
                    "{} {} {} {} {} {}",
                    r.direction,
                    r.action,
                    r.proto.unwrap_or("-"),
                    r.dport.as_deref().unwrap_or("-"),
                    r.source.as_deref().unwrap_or("-"),
                    r.dest.as_deref().unwrap_or("-")
                )
            })
            .collect()
    }

    #[test]
    fn default_is_isolated_internet_client() {
        let rules = rules(&spec(json!({})), ns());
        assert_eq!(
            summary(&rules),
            vec![
                "out ACCEPT udp 53 - 10.100.0.2",
                "out ACCEPT tcp 53 - 10.100.0.2",
                "out DROP - - - 0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,224.0.0.0/3",
                "out ACCEPT - - - -",
            ]
        );
    }

    #[test]
    fn vpc_ingress_and_restricted_egress() {
        let id = uuid::Uuid::nil();
        let rules = rules(
            &spec(json!({
                "vpc_id": id,
                "ingress": [
                    {"protocol": "tcp", "ports": "22", "source_cidrs": ["10.0.128.0/24", "192.0.2.7"]},
                    {"protocol": "udp", "ports": "8000-8100", "source_cidrs": ["0.0.0.0/0"]},
                    {"protocol": "icmp", "source_cidrs": ["10.0.128.0/24"]}
                ],
                "egress": {"mode": "restricted", "allowed_destination_cidrs": ["198.51.100.0/24", "203.0.113.9"], "denied_destination_cidrs": ["198.51.100.128/25"]}
            })),
            ns(),
        );
        assert_eq!(
            summary(&rules),
            vec![
                "in ACCEPT - - +vpc -",
                "in ACCEPT - - +flash-src -",
                "in ACCEPT tcp 22 10.0.128.0/24,192.0.2.7 -",
                "in ACCEPT udp 8000:8100 0.0.0.0/0 -",
                "in ACCEPT icmp - 10.0.128.0/24 -",
                "out ACCEPT udp 53 - 10.100.0.2",
                "out ACCEPT tcp 53 - 10.100.0.2",
                "out ACCEPT tcp - - 10.0.128.0/24,192.0.2.7",
                "out ACCEPT udp - - 0.0.0.0/0",
                "out ACCEPT icmp - - 10.0.128.0/24",
                "out ACCEPT - - - +vpc",
                "out ACCEPT - - - +flash-vip",
                "out DROP - - - 198.51.100.128/25",
                "out ACCEPT - - - 198.51.100.0/24,203.0.113.9",
            ]
        );
    }

    #[test]
    fn disabled_egress_keeps_only_dns() {
        let rules = rules(&spec(json!({"egress": {"mode": "disabled"}})), ns());
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn rule_matching_ignores_pos_and_digest() {
        let rule = FwRule::out("ACCEPT", Some("udp"), Some("53"), Some("10.100.0.2".into()));
        let current = json!({"pos": 3, "type": "out", "action": "ACCEPT", "proto": "udp", "dport": "53", "dest": "10.100.0.2", "comment": "tadokoro", "enable": 1, "digest": "x"});
        assert!(rule.matches(&current));
        let other = json!({"type": "out", "action": "ACCEPT", "proto": "udp", "dport": "5353", "dest": "10.100.0.2", "comment": "tadokoro", "enable": 1});
        assert!(!rule.matches(&other));
        let unmanaged = json!({"type": "out", "action": "ACCEPT", "proto": "udp", "dport": "53", "dest": "10.100.0.2", "comment": "someone", "enable": 1});
        assert!(!rule.matches(&unmanaged));
    }
}
