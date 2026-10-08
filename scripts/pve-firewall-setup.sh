#!/usr/bin/env bash
# Turn on the Proxmox VE firewall for the VMs Tadokoro creates. Run as root on
# any cluster node, once.
#
# Proxmox only filters guests when the datacenter firewall is enabled. The host
# policies stay ACCEPT so enabling it cannot lock out SSH, the web UI or the
# corosync link between sites; the default-deny policy is set per VM by
# Tadokoro (policy_in = policy_out = DROP), so only those VMs are restricted.
#
# Roll back with:  pvesh set /cluster/firewall/options --enable 0
set -euo pipefail

pvesh set /cluster/firewall/options --enable 1 --policy_in ACCEPT --policy_out ACCEPT
pvesh get /cluster/firewall/options

# Routed traffic through this node (LAN <-> VM network) must keep flowing.
for node in $(pvesh get /nodes --output-format json | python3 -c 'import sys,json; print(" ".join(n["node"] for n in json.load(sys.stdin)))'); do
  echo "== $node"
  pvesh get "/nodes/$node/firewall/options" --output-format json
done
