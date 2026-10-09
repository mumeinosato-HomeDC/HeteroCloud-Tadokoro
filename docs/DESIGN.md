# Tadokoro design

Tadokoro is the HeteroCloud `provider/v1` service for virtual machines. It
turns a strict VM spec into a Proxmox VE VM on one chosen node (`pve02`). It is
modelled on the Flash provider: HeteroCloud signs a short-lived Ed25519 command,
the provider authenticates it, and a repeated, idempotent `PUT` drives the
resource towards the requested generation.

```
HeteroCloud worker ──PUT/DELETE/GET (JWT aud=heterocloud-vm)──▶ Tadokoro ──API token──▶ Proxmox VE (pve02)
                                                                         └─ VM on the hcnet VNet (10.100.0.0/16)
```

## Contract

| Route | Action claim | Result |
| --- | --- | --- |
| `PUT /internal/v1/service-instances/{id}` | `service-instance.reconcile` | `202` + `{operation_id, status}` when converged, `503` + `Retry-After` while working |
| `DELETE /internal/v1/service-instances/{id}?generation=N` | `service-instance.delete` | `202` with `phase: deleted` once the VM is gone |
| `GET /internal/v1/service-instances/{id}?generation=N` | `vm.status.get` | current status |
| `GET /health/live`, `/health/ready` | – | readiness checks Proxmox reachability |

Authentication matches Flash: EdDSA, exact issuer/audience/action, 60 s lifetime,
`nbf = iat - 5`, and `claims.generation` must equal the request generation.
Audience `heterocloud-vm` keeps these tokens unusable at other providers.
Status codes: `409` for a stale generation or a generation reused with different
state, `403` for tenant or instance mismatch, `507` when the address pool or VM
limit is exhausted, `400` for an invalid spec.

## Spec

```json
{
  "region": "heteronet-global",
  "image": "ubuntu-26.04",
  "cpu_cores": 2,
  "memory_mib": 2048,
  "disk_gib": 20,
  "ssh_authorized_keys": ["ssh-ed25519 AAAA… me@host"],
  "username": "ubuntu",
  "stopped": false,
  "metadata": {}
}
```

Unknown fields are rejected. The image name maps to a template VMID on the node.
Disks only grow and the image cannot change after creation.

## State lives on the VM

The provider has no database. Everything it needs is on the Proxmox VM:

* **name** – `<slug>-<instance id, 32 hex>`; the suffix is the lookup key.
* **tags** – `hc-vm;hc-ip-a-b-c-d`; the address tag is also the IPAM record.
* **description** – JSON `{organization_id, project_id, service_instance_id, name, generation, applied_generation, spec}`.

Each `PUT` is a small state machine:

1. No VM → allocate a VMID, full-clone the template (VM is `lock: clone`) → `503`.
2. Locked → `503`.
3. Unconfigured clone, or a newer generation → write the accepted generation to
   the description, then apply: cores, memory, balloon off, cloud-init user and
   keys, static address, DNS, tags, `onboot`, and grow the disk. CPU/memory/user/key
   changes on a running VM first request a graceful shutdown (hard stop after 60 s).
4. Config applied → bring the power state in line with `spec.stopped` → `202` when
   it matches.

Because every step reads Proxmox again, a restart or a retried command never loses
or duplicates work. Allocation of VMIDs and addresses is serialised in-process, so
**run exactly one replica**.

## Network

VMs attach to the SDN VNet `hcnet` (VXLAN zone `hcz`, `10.100.0.0/16`). Addresses
come from `10.100.16.0/20`, leaving `10.100.0.0/20` for infrastructure and the
MetalLB pools (`10.100.1.x`, `10.100.2.0/24`, `10.100.3.0/24`) untouched.
The gateway `10.100.0.1` (NAT to the LAN) and DNS `10.100.0.2` are pushed into
cloud-init. Two lessons from the lab:

* The path between the two PVE sites has an MTU of 1420, so the VXLAN zone MTU is
  1370 and every VM NIC uses `mtu=1` (inherit the bridge MTU). Without it TLS and
  SSH stall while ping works.
* `cicustom` can only be set by `root@pam`, so the provider never uses it; the
  guest agent is baked into the template instead (`scripts/make-template.sh`).

## Firewall

Every VM runs behind its own Proxmox firewall (`net0` has `firewall=1`) with
`policy_in = policy_out = DROP`, `ipfilter` (the VM may only use its assigned
address) and `macfilter`. Nothing is shared at datacenter level, so the provider
needs only `VM.Config.Network` on the VM. The firewall objects exist before the
VM first boots.

The spec's `network` section opens it up:

```json
"network": {
  "vpc_id": "…uuid…",
  "ingress": [{"protocol": "tcp", "ports": "22", "source_cidrs": ["10.0.128.0/24"]}],
  "egress": {"mode": "internet", "denied_destination_cidrs": [], "allowed_destination_cidrs": []}
}
```

| Part | Meaning |
| --- | --- |
| `vpc_id` | VMs with the same id reach each other in both directions. Tadokoro keeps a VM-scoped IP set `vpc` on every member (the other members' addresses) and tags VMs `hc-vpc-<id>`. |
| `ingress[]` | Allow `tcp`/`udp` (`ports` = `22` or `8000-8100`) or `icmp` from the listed IPv4 CIDRs. Default: none. |
| `egress.mode` | `internet` (default) drops the private ranges (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, …) and allows the rest; `restricted` allows only `allowed_destination_cidrs`; `disabled` allows nothing. `denied_destination_cidrs` always wins. |

Name resolution to the provider's nameserver (UDP/TCP 53) is always allowed.
`allowed_destination_cidrs` may not overlap the private ranges, the same rule Flash
uses, so a tenant cannot open a path to infrastructure or to other tenants; they
only meet inside a shared VPC. Replies need no rule (conntrack).

Rules are derived from the spec (`src/firewall.rs`) and rewritten as a whole when
they differ, with the comment `tadokoro` on each. They are checked on every
`PUT`, so manual edits are healed, and a VM that predates the firewall is moved
under it (one restart to attach the filtered NIC). On delete the VM is removed from
its peers' IP sets before it is stopped.

One-time host setup: `scripts/pve-firewall-setup.sh` enables the datacenter
firewall with host policies left at `ACCEPT`, so SSH, the web UI and the corosync
link are never cut off.

## Flash services in the same VPC

VMs and Flash containers that share a `vpc_id` can talk to each other once the VPC has
`vm_access: true` (set on the VPC in HeteroCloud; the VPC provider does the Flash side).

```
VM  ──▶  virtual IP (MetalLB pool "vpc", 10.100.3.0/24, ARP on ens19)  ──▶  Flash pod
VM  ◀──  Flash pod (source NATed to the node address 10.100.0.10)
```

* **VM → Flash.** The VPC provider publishes a `LoadBalancer` Service per member
  (`externalTrafficPolicy: Local`, so the VM's address survives). Tadokoro reads those Services
  with a read-only Role in the Flash namespace and keeps their addresses in the VM-scoped IP set
  `flash-vip`; the VM may send to exactly those. The addresses come and go with Flash services, so
  a periodic sync (`TADOKORO_VPC_SYNC_SECONDS`) follows them and also rolls rule changes out to settled VMs.
* **Flash → VM.** Pod traffic leaves the node translated to its address on the VM network
  (`TADOKORO_FLASH_SNAT_ADDRESSES`, an IP set `flash-src`); VMs of the VPC accept it.
* A VM outside the VPC has neither set and no rule that refers to them; Flash pods of the VPC
  cannot reach it, and it cannot reach the VPC's virtual IPs (verified).

**Limitation.** Because all pods share one translated source address, two VPCs that both enable
`vm_access` are not isolated from each other on the Flash → VM direction: a pod of VPC A could reach a
VM of VPC B. The VM → Flash direction is exact (one virtual IP per service, one firewall per VM). Closing the
gap needs a per-VPC egress address (the VPC provider's EgressGateway with a dedicated EIP per VPC).

## DNS

With `dns.enabled`, Tadokoro keeps names in the platform zone (`hetero.internal`) through
RFC 2136 dynamic updates signed with a TSIG key:

| Name | Points to |
| --- | --- |
| `<slug>-<id8>.vm.<zone>` | the VM (globally unique) |
| `<slug>.vm.<vpc8>.vpc.<zone>` | the same VM, inside its VPC |
| `<name>.svc.<vpc8>.vpc.<zone>` | a Flash service of the VPC (its VM-facing virtual IP) |

`id8`/`vpc8` are the last eight hex digits of the id: UUIDv7 begins with a timestamp, so the first
digits are shared by everything created within about a minute. A VM registers when its
configuration is applied and its canonical name is removed when deletion starts.

The state is declarative: every sync (`TADOKORO_VPC_SYNC_SECONDS`, and after every VM change)
computes the wanted records from Proxmox and Kubernetes, reads the owned subtrees with a zone
transfer and replaces, adds or removes records until they match. Stale names of vanished VMs or Flash
services therefore disappear on their own. If Proxmox or the Kubernetes lookup fails, the round is
skipped instead of deleting names that could not be verified.

The zone transfer is read-only input and is parsed without verifying its TSIG chain (BIND signs only
some messages of a transfer); the updates and their answers are fully signed and verified.

BIND is configured so the provider's key cannot touch anything else:

```
zone "hetero.internal" {
  type primary;
  file "/var/bind/dyn/hetero.internal.zone";
  update-policy {
    grant hetero-update zonesub ANY;                                   # admin key
    grant tadokoro-update subdomain vm.hetero.internal. ANY;
    grant tadokoro-update subdomain vpc.hetero.internal. ANY;
  };
  allow-transfer { key tadokoro-update; key hetero-update; };
};
```

Records of other tenants are visible to any VM that can query the resolver, but the addresses stay
unreachable without the firewall rules of a shared VPC.

## Proxmox permissions

`scripts/pve-setup.sh` creates the role `HCTadokoro`, user `tadokoro@pve` and an
API token. The ACLs cover `/vms`, `/storage/local-lvm`, `/sdn/zones/hcz` and
`/nodes/pve02`; the provider cannot touch other nodes or datacenter settings. The
token secret is mounted from a Kubernetes Secret and never logged.

## Not yet implemented

* HeteroCloud core support for a `vm` service kind (domain spec, store, worker
  dispatch, IAM actions `vm:*`, CLI and console). Until then the provider is driven
  by signed `provider/v1` requests directly.
* Per-VPC source addresses for Flash → VM traffic (see the limitation above).
* Snapshots, and extra disks.

## External NIC

With `TADOKORO_EXTERNAL_BRIDGE` / `TADOKORO_EXTERNAL_NETWORK` set, every VM gets a second NIC (`net1`) on that
bridge, configured by DHCP. The router that serves the bridge decides the address and the default route; the VPC
NIC (`net0`) keeps its Tadokoro-assigned address but no gateway, so internet traffic leaves via `net1`. Changing the
NIC takes effect at the next boot, like other NIC changes.

- Ingress/egress rules are per VM and apply to both NICs. The firewall option `dhcp` is on only when an external
  NIC exists.
- `ipfilter` needs the leased address: the guest agent reports it and the periodic sync writes it into
  `ipfilter-net1`. Only addresses inside `TADOKORO_EXTERNAL_NETWORK` are accepted (the guest controls what it
  reports), and until a lease is known nothing is allowed out of `net1`. A guest could still claim a neighbour's
  address inside that range; the external router should do its own anti-spoofing.
- The lease is exposed as `external_ip_address` in the status.
- Lab: `scripts/pve-external-setup.sh` creates a node-local SDN simple zone with SNAT and dnsmasq DHCP that stands
  in for the router (uplink: the node's own gateway).

## Graphical console

`GET /internal/v1/service-instances/{id}/console` (action `vm.console`, WebSocket) relays the Proxmox VNC proxy
(`vncproxy` + `vncwebsocket`). Proxmox protects it with the proxy ticket as the VNC password. The relay answers the
RFB "VNC authentication" challenge itself (DES with the ticket) and offers the browser security type "None", so the
ticket never leaves the provider; afterwards the RFB stream is relayed unchanged. VMs get `vga: std` (applied at the
next boot). Open consoles are capped (16). There is deliberately no serial console: it is one shared stream with one shared login.
