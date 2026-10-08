//! Address allocation. Assigned addresses are recorded as `hc-ip-a-b-c-d` tags on
//! the VMs, so the Proxmox cluster itself is the source of truth.

use std::{collections::BTreeSet, net::Ipv4Addr};

use ipnet::Ipv4Net;

pub const IP_TAG_PREFIX: &str = "hc-ip-";

pub fn ip_tag(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{IP_TAG_PREFIX}{a}-{b}-{c}-{d}")
}

pub fn parse_ip_tag(tag: &str) -> Option<Ipv4Addr> {
    let rest = tag.strip_prefix(IP_TAG_PREFIX)?;
    let mut octets = rest.split('-').map(|p| p.parse::<u8>().ok());
    let ip = Ipv4Addr::new(
        octets.next()??,
        octets.next()??,
        octets.next()??,
        octets.next()??,
    );
    octets.next().is_none().then_some(ip)
}

/// Lowest free host address of `pool`, skipping the network and broadcast
/// addresses. `used` may contain addresses outside the pool.
pub fn allocate(pool: Ipv4Net, used: &BTreeSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    pool.hosts().find(|ip| !used.contains(ip))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn tag_round_trips() {
        let ip = Ipv4Addr::new(10, 100, 16, 7);
        assert_eq!(ip_tag(ip), "hc-ip-10-100-16-7");
        assert_eq!(parse_ip_tag("hc-ip-10-100-16-7"), Some(ip));
        assert_eq!(parse_ip_tag("hc-ip-10-100-16"), None);
        assert_eq!(parse_ip_tag("hc-ip-10-100-16-7-1"), None);
        assert_eq!(parse_ip_tag("hc-ip-300-1-1-1"), None);
        assert_eq!(parse_ip_tag("other"), None);
    }

    #[test]
    fn allocates_lowest_free_host() {
        let pool: Ipv4Net = "10.100.16.0/29".parse().expect("net");
        let mut used = BTreeSet::new();
        assert_eq!(allocate(pool, &used), Some(Ipv4Addr::new(10, 100, 16, 1)));
        used.insert(Ipv4Addr::new(10, 100, 16, 1));
        used.insert(Ipv4Addr::new(10, 100, 16, 3));
        assert_eq!(allocate(pool, &used), Some(Ipv4Addr::new(10, 100, 16, 2)));
        for n in 1..=6 {
            used.insert(Ipv4Addr::new(10, 100, 16, n));
        }
        assert_eq!(allocate(pool, &used), None);
    }
}
