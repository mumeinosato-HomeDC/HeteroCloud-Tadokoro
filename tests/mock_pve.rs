//! A tiny in-memory Proxmox VE API, just big enough for the provider.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde_json::{Value, json};

pub const TOKEN: &str = "PVEAPIToken=tadokoro@pve!provider=secret";
pub const NODE: &str = "pve02";

#[derive(Clone, Debug, Default)]
pub struct MockVm {
    pub node: String,
    pub status: String,
    pub template: bool,
    pub config: BTreeMap<String, String>,
    /// Number of config reads before a `clone` lock disappears.
    pub lock_reads: u32,
    /// `cluster/resources` calls that still hide this (new) VM, like pvestatd lag.
    pub hidden_reads: u32,
    pub fw_options: BTreeMap<String, String>,
    pub fw_rules: Vec<BTreeMap<String, String>>,
    pub ipsets: BTreeMap<String, Vec<String>>,
}

#[derive(Default)]
pub struct MockState {
    pub vms: BTreeMap<u32, MockVm>,
    pub calls: Vec<String>,
}

pub type Shared = Arc<Mutex<MockState>>;

pub fn new_state() -> Shared {
    let mut state = MockState::default();
    state.vms.insert(
        9000,
        MockVm {
            node: NODE.into(),
            status: "stopped".into(),
            template: true,
            config: BTreeMap::from([
                ("name".into(), "ubuntu-26.04-template".into()),
                (
                    "scsi0".into(),
                    "local-lvm:base-9000-disk-0,discard=on,size=3584M".into(),
                ),
                ("cores".into(), "2".into()),
                ("memory".into(), "2048".into()),
                (
                    "net0".into(),
                    "virtio=BC:24:11:00:00:01,bridge=hcnet,mtu=1".into(),
                ),
            ]),
            ..MockVm::default()
        },
    );
    Arc::new(Mutex::new(state))
}

fn err(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"data": null, "message": message}))).into_response()
}

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(TOKEN)
}

fn missing(vmid: u32) -> Response {
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!("Configuration file 'nodes/{NODE}/qemu-server/{vmid}.conf' does not exist"),
    )
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/api2/json/cluster/resources", get(resources))
        .route("/api2/json/cluster/nextid", get(nextid))
        .route("/api2/json/nodes/{node}/qemu/{vmid}/clone", post(clone))
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/config",
            get(config).put(set_config),
        )
        .route("/api2/json/nodes/{node}/qemu/{vmid}/resize", put(resize))
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/status/current",
            get(current),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/status/start",
            post(start),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/status/shutdown",
            post(stop),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/status/stop",
            post(stop),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}",
            axum::routing::delete(destroy),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/firewall/options",
            get(fw_options).put(set_fw_options),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/firewall/rules",
            get(fw_rules).post(add_fw_rule),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}",
            axum::routing::delete(delete_fw_rule),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset",
            get(ipsets).post(create_ipset),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}",
            get(ipset_entries).post(add_ipset_entry),
        )
        .route(
            "/api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}",
            axum::routing::delete(delete_ipset_entry),
        )
        .with_state(state)
}

async fn resources(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let items: Vec<Value> = s
        .vms
        .iter()
        .filter(|(_, vm)| vm.hidden_reads == 0)
        .map(|(id, vm)| {
            json!({
                "vmid": id, "node": vm.node, "status": vm.status, "template": u8::from(vm.template),
                "name": vm.config.get("name"), "tags": vm.config.get("tags"), "type": "qemu",
            })
        })
        .collect();
    for vm in s.vms.values_mut() {
        vm.hidden_reads = vm.hidden_reads.saturating_sub(1);
    }
    Json(json!({"data": items})).into_response()
}

async fn nextid(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let s = s.lock().unwrap();
    let id = (100..).find(|id| !s.vms.contains_key(id)).unwrap();
    Json(json!({"data": id.to_string()})).into_response()
}

async fn clone(
    State(s): State<Shared>,
    Path((_node, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let Some(template) = s.vms.get(&vmid).cloned() else {
        return missing(vmid);
    };
    let newid: u32 = form["newid"].parse().unwrap();
    if s.vms.contains_key(&newid) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "VM already exists");
    }
    let mut config = template.config.clone();
    config.insert("name".into(), form["name"].clone());
    config.insert("lock".into(), "clone".into());
    s.vms.insert(
        newid,
        MockVm {
            node: NODE.into(),
            status: "stopped".into(),
            template: false,
            config,
            lock_reads: 1,
            hidden_reads: 3,
            ..MockVm::default()
        },
    );
    s.calls.push(format!("clone {vmid}->{newid}"));
    Json(json!({"data": "UPID:pve02:clone"})).into_response()
}

async fn config(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let Some(vm) = s.vms.get_mut(&vmid) else {
        return missing(vmid);
    };
    let snapshot = vm.config.clone();
    if vm.lock_reads > 0 {
        vm.lock_reads -= 1;
        if vm.lock_reads == 0 {
            vm.config.remove("lock");
        }
    }
    Json(json!({"data": snapshot})).into_response()
}

async fn set_config(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let Some(vm) = s.vms.get_mut(&vmid) else {
        return missing(vmid);
    };
    if vm.config.contains_key("lock") {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "VM is locked (clone)");
    }
    for (k, v) in form {
        vm.config.insert(k, v);
    }
    s.calls.push(format!("set {vmid}"));
    Json(json!({"data": null})).into_response()
}

async fn resize(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let Some(vm) = s.vms.get_mut(&vmid) else {
        return missing(vmid);
    };
    let disk = form["disk"].clone();
    let old = vm.config.get(&disk).cloned().unwrap_or_default();
    let head = old.split(",size=").next().unwrap_or("").to_owned();
    vm.config
        .insert(disk, format!("{head},size={}", form["size"]));
    s.calls.push(format!("resize {vmid} {}", form["size"]));
    Json(json!({"data": null})).into_response()
}

async fn current(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let s = s.lock().unwrap();
    match s.vms.get(&vmid) {
        Some(vm) => Json(json!({"data": {"status": vm.status}})).into_response(),
        None => missing(vmid),
    }
}

async fn start(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let Some(vm) = s.vms.get_mut(&vmid) else {
        return missing(vmid);
    };
    vm.status = "running".into();
    s.calls.push(format!("start {vmid}"));
    Json(json!({"data": "UPID:start"})).into_response()
}

async fn stop(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let Some(vm) = s.vms.get_mut(&vmid) else {
        return missing(vmid);
    };
    vm.status = "stopped".into();
    s.calls.push(format!("stop {vmid}"));
    Json(json!({"data": "UPID:stop"})).into_response()
}

async fn destroy(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    Query(_q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    if s.vms.remove(&vmid).is_none() {
        return missing(vmid);
    }
    s.calls.push(format!("destroy {vmid}"));
    Json(json!({"data": "UPID:destroy"})).into_response()
}

pub async fn serve(state: Shared) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    format!("http://{addr}")
}

macro_rules! vm_or_missing {
    ($s:expr, $vmid:expr) => {
        match $s.vms.get_mut(&$vmid) {
            Some(vm) => vm,
            None => return missing($vmid),
        }
    };
}

async fn fw_options(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    Json(json!({"data": vm.fw_options})).into_response()
}

async fn set_fw_options(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    vm.fw_options.extend(form);
    s.calls.push(format!("fw-options {vmid}"));
    Json(json!({"data": null})).into_response()
}

async fn fw_rules(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    let rules: Vec<Value> = vm
        .fw_rules
        .iter()
        .enumerate()
        .map(|(pos, rule)| {
            let mut value = json!({"pos": pos, "digest": "d"});
            for (k, v) in rule {
                value[k] = if k == "enable" { json!(1) } else { json!(v) };
            }
            value
        })
        .collect();
    Json(json!({"data": rules})).into_response()
}

async fn add_fw_rule(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    vm.fw_rules.push(form.into_iter().collect());
    s.calls.push(format!("fw-rule-add {vmid}"));
    Json(json!({"data": null})).into_response()
}

async fn delete_fw_rule(
    State(s): State<Shared>,
    Path((_n, vmid, pos)): Path<(String, u32, usize)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    if pos >= vm.fw_rules.len() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "no such rule");
    }
    vm.fw_rules.remove(pos);
    s.calls.push(format!("fw-rule-del {vmid}"));
    Json(json!({"data": null})).into_response()
}

async fn ipsets(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    let names: Vec<Value> = vm.ipsets.keys().map(|n| json!({"name": n})).collect();
    Json(json!({"data": names})).into_response()
}

async fn create_ipset(
    State(s): State<Shared>,
    Path((_n, vmid)): Path<(String, u32)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    vm.ipsets.entry(form["name"].clone()).or_default();
    Json(json!({"data": null})).into_response()
}

async fn ipset_entries(
    State(s): State<Shared>,
    Path((_n, vmid, name)): Path<(String, u32, String)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    let Some(entries) = vm.ipsets.get(&name) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "no such ipset");
    };
    let items: Vec<Value> = entries.iter().map(|c| json!({"cidr": c})).collect();
    Json(json!({"data": items})).into_response()
}

async fn add_ipset_entry(
    State(s): State<Shared>,
    Path((_n, vmid, name)): Path<(String, u32, String)>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    vm.ipsets
        .entry(name)
        .or_default()
        .push(form["cidr"].clone());
    Json(json!({"data": null})).into_response()
}

async fn delete_ipset_entry(
    State(s): State<Shared>,
    Path((_n, vmid, name, cidr)): Path<(String, u32, String, String)>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "no ticket");
    }
    let mut s = s.lock().unwrap();
    let vm = vm_or_missing!(s, vmid);
    if let Some(entries) = vm.ipsets.get_mut(&name) {
        entries.retain(|c| c != &cidr);
    }
    Json(json!({"data": null})).into_response()
}
