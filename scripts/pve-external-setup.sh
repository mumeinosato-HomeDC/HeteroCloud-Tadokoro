#!/usr/bin/env bash
# Lab stand-in for the external router that hands out addresses in production.
#
# Creates a node-local SDN "simple" zone on the VM node with SNAT and a DHCP server (dnsmasq),
# so every VM's second NIC gets an address and a default gateway and reaches the outside through
# the node's own uplink (vmbr0 -> its gateway). Only the subnet below is masqueraded; the hosts'
# own networks are not touched. In production, skip this and point `external.bridge`
# at the bridge or VLAN that the real router serves.
#
# usage: pve-external-setup.sh [NODE] [ZONE] [SUBNET] [GATEWAY] [DHCP_START] [DHCP_END]
set -euo pipefail

node=${1:-pve02}
zone=${2:-hcext}
subnet=${3:-10.101.0.0/24}
gateway=${4:-10.101.0.1}
start=${5:-10.101.0.50}
end=${6:-10.101.0.250}

if ! dpkg -s dnsmasq >/dev/null 2>&1; then
  apt-get install -y dnsmasq
  # SDN runs its own dnsmasq instances; the stock service must stay off.
  systemctl disable --now dnsmasq
fi

pvesh get /cluster/sdn/zones/"$zone" >/dev/null 2>&1 || \
  pvesh create /cluster/sdn/zones --zone "$zone" --type simple --nodes "$node" \
    --ipam pve --dhcp dnsmasq --mtu 1500
pvesh get /cluster/sdn/vnets/"$zone" >/dev/null 2>&1 || \
  pvesh create /cluster/sdn/vnets --vnet "$zone" --zone "$zone"
if ! pvesh get /cluster/sdn/vnets/"$zone"/subnets --output-format json | grep -q "\"cidr\":\"$subnet\""; then
  pvesh create /cluster/sdn/vnets/"$zone"/subnets --subnet "$subnet" --type subnet \
    --gateway "$gateway" --snat 1 --dhcp-range "start-address=$start,end-address=$end"
fi
# SNAT needs the node to forward packets.
echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/90-hcext-forward.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
pvesh set /cluster/sdn
echo "external zone $zone ready on $node ($subnet via $gateway)"
