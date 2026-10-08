#!/usr/bin/env bash
# One-time Proxmox VE setup for Tadokoro. Run as root on any cluster node.
# Creates a least-privilege role, a dedicated user and an API token, and scopes
# them to the VM node, its storage and the VM network. The token secret is
# printed once; store it in the Kubernetes Secret the Helm chart references.
set -euo pipefail

node=${NODE:-pve02}
storage=${STORAGE:-local-lvm}
zone=${SDN_ZONE:-hcz}
user=tadokoro@pve
token=provider
role=HCTadokoro

pveum role add "$role" --privs "VM.Allocate VM.Clone VM.Audit VM.Console VM.Console VM.PowerMgmt VM.Config.CPU VM.Config.Memory VM.Config.Disk VM.Config.Network VM.Config.Cloudinit VM.Config.Options VM.Config.HWType VM.GuestAgent.Audit Datastore.AllocateSpace Datastore.Audit SDN.Use Sys.Audit" 2>/dev/null \
  || echo "role $role already exists"
pveum user add "$user" --comment "HeteroCloud Tadokoro VM provider" 2>/dev/null || echo "user $user already exists"
pveum acl modify /vms --users "$user" --roles "$role"
pveum acl modify "/storage/$storage" --users "$user" --roles "$role"
pveum acl modify "/sdn/zones/$zone" --users "$user" --roles "$role"
pveum acl modify "/nodes/$node" --users "$user" --roles "$role"
# privsep=0: the token carries the user's permissions, which are limited above.
pveum user token add "$user" "$token" --privsep 0 --output-format json
