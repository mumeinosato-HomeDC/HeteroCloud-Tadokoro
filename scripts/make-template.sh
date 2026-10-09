#!/usr/bin/env bash
# Build the cloud-init VM template Tadokoro clones from. Run as root on the
# Proxmox node that will host the VMs (the template must live on that node).
#
# The template is a stock Ubuntu cloud image with qemu-guest-agent installed and
# all per-instance state (SSH host keys, machine-id, cloud-init state) removed,
# so every clone boots like a first boot and gets unique host keys.
#
# usage: make-template.sh VMID IMAGE.img SSH_PUBKEY_FILE PREP_IP/PREFIX GATEWAY NAMESERVER
set -euo pipefail

vmid=${1:?template VMID}
image=${2:?cloud image path}
pubkey=${3:?ssh public key file used while preparing}
prep_ip=${4:?temporary address with prefix, e.g. 10.100.15.250/16}
gateway=${5:?gateway}
nameserver=${6:?nameserver}
bridge=${BRIDGE:-hcnet}
storage=${STORAGE:-local-lvm}
name=${NAME:-ubuntu-26.04-template}
snippets=${SNIPPETS:-/var/lib/vz/snippets}

if qm status "$vmid" >/dev/null 2>&1; then
  echo "VM $vmid already exists; destroy it first" >&2
  exit 1
fi

mkdir -p "$snippets"
cat >"$snippets/tadokoro-vendor.yaml" <<'YAML'
#cloud-config
package_update: true
packages: [qemu-guest-agent]
write_files:
  # The web shell attaches to the serial console; access is already gated by HeteroCloud IAM,
  # so the console logs in as the default user instead of asking for a password nobody has.
  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin ubuntu --noclear --keep-baud 115200,57600,38400,9600 %I $TERM
runcmd:
  - systemctl enable --now qemu-guest-agent
  - systemctl restart serial-getty@ttyS0.service
YAML

# mtu=1 follows the bridge MTU; the VXLAN underlay is smaller than 1500.
qm create "$vmid" --name "$name" --memory 2048 --cores 2 --cpu host --ostype l26 --agent 1 \
  --scsihw virtio-scsi-single --net0 "virtio,bridge=$bridge,mtu=1" --serial0 socket --vga std \
  --scsi0 "$storage:0,import-from=$image,discard=on,iothread=1" --ide2 "$storage:cloudinit" \
  --boot order=scsi0
qm set "$vmid" --ciuser ubuntu --sshkeys "$pubkey" --ipconfig0 "ip=$prep_ip,gw=$gateway" \
  --nameserver "$nameserver" --cicustom "vendor=local:snippets/tadokoro-vendor.yaml"
qm start "$vmid"

echo "waiting for the guest agent..."
for _ in $(seq 1 120); do
  qm agent "$vmid" ping >/dev/null 2>&1 && break
  sleep 5
done
qm agent "$vmid" ping >/dev/null

qm guest exec "$vmid" --timeout 300 -- cloud-init status --wait >/dev/null
qm guest exec "$vmid" --timeout 60 -- bash -c '
  cloud-init clean --logs --seed
  rm -f /etc/ssh/ssh_host_*
  truncate -s 0 /etc/machine-id
  rm -f /var/lib/dbus/machine-id
  apt-get clean
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
  history -c || true
' >/dev/null
qm shutdown "$vmid" --timeout 120 || qm stop "$vmid"
for _ in $(seq 1 60); do
  [ "$(qm status "$vmid")" = "status: stopped" ] && break
  sleep 2
done

qm set "$vmid" --delete cicustom,ipconfig0,sshkeys,ciuser,nameserver
qm template "$vmid"
echo "template $vmid ready"
