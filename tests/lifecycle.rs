#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod mock_pve;

use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mock_pve::{Shared, new_state, serve};
use serde_json::{Value, json};
use tadokoro::{
    api::{AppState, router},
    auth::{ProviderAuthenticator, ProviderClaims},
    pve::PveClient,
    reconcile::{Reconciler, Settings},
};
use tower::ServiceExt;
use uuid::Uuid;

// Test-only Ed25519 key pair (the same one the Flash provider uses in its tests).
const PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICKoEEWPLg2OazcyTWzBEw/mMPPXatNOUcEUWDHo2y0Y\n-----END PRIVATE KEY-----\n";
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcBpAFx4KtN1FYwvSN0XJMWSGiAJPjzetPXEiuMX2azg=\n-----END PUBLIC KEY-----\n";
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAERHnScWeyI8R9LNgXVEJGjb/Cg8sopnWQJlfqkOv02 me@host";

struct Harness {
    app: Router,
    pve: Shared,
    org: Uuid,
    project: Uuid,
}

async fn harness(max_vms: usize) -> Harness {
    let pve = new_state();
    let url = serve(pve.clone()).await;
    let client = PveClient::new(
        &url,
        "tadokoro@pve!provider",
        "secret",
        mock_pve::NODE,
        None,
    )
    .unwrap();
    let reconciler = Reconciler::new(
        client,
        Settings {
            images: BTreeMap::from([("ubuntu-26.04".to_owned(), 9000)]),
            storage: "local-lvm".into(),
            ip_pool: "10.100.16.0/29".parse().unwrap(),
            network_prefix: 16,
            gateway: Ipv4Addr::new(10, 100, 0, 1),
            nameserver: Ipv4Addr::new(10, 100, 0, 2),
            search_domain: "hetero.internal".into(),
            max_vms,
        },
    );
    let authenticator = ProviderAuthenticator::from_public_keys_json(
        "heterocloud",
        "heterocloud-vm",
        &json!({"test-key": PUBLIC_KEY}).to_string(),
    )
    .unwrap();
    let app = router(Arc::new(AppState {
        authenticator,
        reconciler,
        region: "heteronet-global".into(),
    }));
    Harness {
        app,
        pve,
        org: Uuid::now_v7(),
        project: Uuid::now_v7(),
    }
}

fn token(h: &Harness, instance: Uuid, action: &str, generation: i64, audience: &str) -> String {
    let now = Utc::now().timestamp();
    let claims = ProviderClaims {
        issuer: "heterocloud".into(),
        audience: audience.into(),
        subject: Uuid::now_v7(),
        user_id: None,
        organization_id: h.org,
        project_id: h.project,
        service_instance_id: instance,
        action: action.into(),
        generation,
        jwt_id: Uuid::now_v7(),
        issued_at: now,
        not_before: now - 5,
        expires_at: now + 60,
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("test-key".into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

fn spec(memory: u32, disk: u32) -> Value {
    json!({
        "region": "heteronet-global", "image": "ubuntu-26.04", "cpu_cores": 2, "memory_mib": memory,
        "disk_gib": disk, "ssh_authorized_keys": [KEY]
    })
}

async fn send(h: &Harness, request: Request<Body>) -> (StatusCode, Value) {
    let response = h.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn put(
    h: &Harness,
    instance: Uuid,
    generation: i64,
    name: &str,
    spec: Value,
) -> (StatusCode, Value) {
    put_with(h, instance, generation, name, spec, "heterocloud-vm").await
}

async fn put_with(
    h: &Harness,
    instance: Uuid,
    generation: i64,
    name: &str,
    spec: Value,
    aud: &str,
) -> (StatusCode, Value) {
    let t = token(h, instance, "service-instance.reconcile", generation, aud);
    send(
        h,
        Request::put(format!("/internal/v1/service-instances/{instance}"))
            .header("authorization", format!("Bearer {t}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"generation": generation, "name": name, "spec": spec}).to_string(),
            ))
            .unwrap(),
    )
    .await
}

/// Repeat the PUT the way the HeteroCloud worker does, until the provider accepts.
async fn converge(h: &Harness, instance: Uuid, generation: i64, name: &str, spec: Value) -> Value {
    for _ in 0..30 {
        let (status, body) = put(h, instance, generation, name, spec.clone()).await;
        match status {
            StatusCode::ACCEPTED => return body,
            StatusCode::SERVICE_UNAVAILABLE => continue,
            other => panic!("unexpected {other}: {body}"),
        }
    }
    panic!("never converged");
}

async fn remove(h: &Harness, instance: Uuid, generation: i64) -> (StatusCode, Value) {
    let t = token(
        h,
        instance,
        "service-instance.delete",
        generation,
        "heterocloud-vm",
    );
    send(
        h,
        Request::delete(format!(
            "/internal/v1/service-instances/{instance}?generation={generation}"
        ))
        .header("authorization", format!("Bearer {t}"))
        .body(Body::empty())
        .unwrap(),
    )
    .await
}

fn vm_of(h: &Harness, instance: Uuid) -> (u32, mock_pve::MockVm) {
    let s = h.pve.lock().unwrap();
    let suffix = format!("-{}", instance.simple());
    s.vms
        .iter()
        .find(|(_, vm)| vm.config.get("name").is_some_and(|n| n.ends_with(&suffix)))
        .map(|(id, vm)| (*id, vm.clone()))
        .expect("VM exists")
}

#[tokio::test]
async fn creates_updates_and_deletes_a_vm() {
    let h = harness(8).await;
    let instance = Uuid::now_v7();

    let body = converge(&h, instance, 1, "Web Server", spec(2048, 20)).await;
    assert_eq!(body["status"]["phase"], "ready");
    assert_eq!(body["status"]["ip_address"], "10.100.16.1");
    assert_eq!(body["status"]["power_state"], "running");
    assert_eq!(body["status"]["observed_generation"], 1);
    let (vmid, vm) = vm_of(&h, instance);
    assert_eq!(vm.config["tags"], "hc-vm;hc-ip-10-100-16-1");
    assert_eq!(vm.config["ipconfig0"], "ip=10.100.16.1/16,gw=10.100.0.1");
    assert_eq!(vm.config["memory"], "2048");
    assert_eq!(
        vm.config["scsi0"],
        "local-lvm:base-9000-disk-0,discard=on,size=20G"
    );
    assert_eq!(
        vm.config["name"],
        format!("web-server-{}", instance.simple())
    );
    assert!(vm.config["sshkeys"].contains("ssh-ed25519%20AAAA"));
    assert_eq!(vm.node, "pve02");
    let operation = body["operation_id"].clone();

    // The same command is idempotent.
    let again = converge(&h, instance, 1, "Web Server", spec(2048, 20)).await;
    assert_eq!(again["operation_id"], operation);
    assert_eq!(
        h.pve
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.starts_with("clone"))
            .count(),
        1
    );

    // A new generation with more memory restarts the VM and keeps its address.
    let updated = converge(&h, instance, 2, "Web Server", spec(4096, 40)).await;
    assert_eq!(updated["status"]["observed_generation"], 2);
    assert_eq!(updated["status"]["ip_address"], "10.100.16.1");
    let (_, vm) = vm_of(&h, instance);
    assert_eq!(vm.config["memory"], "4096");
    assert_eq!(
        vm.config["scsi0"],
        "local-lvm:base-9000-disk-0,discard=on,size=40G"
    );
    assert_eq!(vm.status, "running");
    assert!(
        h.pve
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c == &format!("stop {vmid}"))
    );

    // Status requires the current generation.
    let t = token(&h, instance, "vm.status.get", 2, "heterocloud-vm");
    let (status, body) = send(
        &h,
        Request::get(format!(
            "/internal/v1/service-instances/{instance}?generation=2"
        ))
        .header("authorization", format!("Bearer {t}"))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["vmid"], vmid);

    // Delete converges to "deleted" and removes the VM.
    let mut last = (StatusCode::SERVICE_UNAVAILABLE, Value::Null);
    for _ in 0..5 {
        last = remove(&h, instance, 3).await;
        if last.0 == StatusCode::ACCEPTED {
            break;
        }
    }
    assert_eq!(last.0, StatusCode::ACCEPTED);
    assert_eq!(last.1["status"]["phase"], "deleted");
    assert!(!h.pve.lock().unwrap().vms.contains_key(&vmid));
    // Repeating a delete is a no-op.
    assert_eq!(remove(&h, instance, 3).await.0, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn stopped_spec_leaves_the_vm_off() {
    let h = harness(8).await;
    let instance = Uuid::now_v7();
    let mut s = spec(2048, 20);
    s["stopped"] = json!(true);
    let body = converge(&h, instance, 1, "cold", s).await;
    assert_eq!(body["status"]["power_state"], "stopped");
    assert_eq!(vm_of(&h, instance).1.status, "stopped");
}

#[tokio::test]
async fn addresses_are_unique_and_pool_exhaustion_is_reported() {
    let h = harness(100).await;
    // /29 has six hosts.
    let mut ips = Vec::new();
    for _ in 0..6 {
        let instance = Uuid::now_v7();
        let body = converge(&h, instance, 1, "vm", spec(1024, 10)).await;
        ips.push(body["status"]["ip_address"].as_str().unwrap().to_owned());
    }
    ips.sort();
    ips.dedup();
    assert_eq!(ips.len(), 6);
    let instance = Uuid::now_v7();
    let mut status = StatusCode::OK;
    for _ in 0..6 {
        status = put(&h, instance, 1, "extra", spec(1024, 10)).await.0;
        if status == StatusCode::INSUFFICIENT_STORAGE {
            break;
        }
    }
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
}

#[tokio::test]
async fn vm_limit_is_enforced() {
    let h = harness(1).await;
    converge(&h, Uuid::now_v7(), 1, "first", spec(1024, 10)).await;
    let (status, body) = put(&h, Uuid::now_v7(), 1, "second", spec(1024, 10)).await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{body}");
}

#[tokio::test]
async fn rejects_bad_tokens_and_specs() {
    let h = harness(8).await;
    let instance = Uuid::now_v7();
    let (status, _) = put_with(&h, instance, 1, "x", spec(1024, 10), "heterocloud-flash").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let no_auth = send(
        &h,
        Request::put(format!("/internal/v1/service-instances/{instance}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"generation": 1, "name": "x", "spec": spec(1024, 10)}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(no_auth.0, StatusCode::UNAUTHORIZED);

    // A delete token cannot reconcile.
    let t = token(&h, instance, "service-instance.delete", 1, "heterocloud-vm");
    let wrong_action = send(
        &h,
        Request::put(format!("/internal/v1/service-instances/{instance}"))
            .header("authorization", format!("Bearer {t}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"generation": 1, "name": "x", "spec": spec(1024, 10)}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(wrong_action.0, StatusCode::UNAUTHORIZED);

    let mut bad = spec(1024, 10);
    bad["cpu_cores"] = json!(99);
    assert_eq!(
        put(&h, instance, 1, "x", bad).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut unknown = spec(1024, 10);
    unknown["gpu"] = json!(true);
    assert_eq!(
        put(&h, instance, 1, "x", unknown).await.0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        h.pve.lock().unwrap().calls.is_empty(),
        "no Proxmox call for rejected commands"
    );
}

#[tokio::test]
async fn generation_and_scope_rules() {
    let h = harness(8).await;
    let instance = Uuid::now_v7();
    converge(&h, instance, 5, "svc", spec(1024, 10)).await;

    assert_eq!(
        put(&h, instance, 4, "svc", spec(1024, 10)).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        put(&h, instance, 5, "svc", spec(2048, 10)).await.0,
        StatusCode::CONFLICT
    );
    // Disks never shrink and the image is immutable.
    let (status, _) = put(&h, instance, 6, "svc", spec(1024, 8)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Another tenant cannot touch the VM even with a valid token.
    let other = Harness {
        app: h.app.clone(),
        pve: h.pve.clone(),
        org: Uuid::now_v7(),
        project: h.project,
    };
    assert_eq!(
        put(&other, instance, 6, "svc", spec(1024, 10)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(remove(&other, instance, 6).await.0, StatusCode::FORBIDDEN);
}
