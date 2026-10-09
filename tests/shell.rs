#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod mock_pve;

use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc, time::Duration};

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mock_pve::{new_state, serve};
use serde_json::json;
use tadokoro::{
    api::{AppState, router},
    auth::{ProviderAuthenticator, ProviderClaims},
    pve::PveClient,
    reconcile::{Reconciler, Settings},
};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use uuid::Uuid;

const PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICKoEEWPLg2OazcyTWzBEw/mMPPXatNOUcEUWDHo2y0Y\n-----END PRIVATE KEY-----\n";
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcBpAFx4KtN1FYwvSN0XJMWSGiAJPjzetPXEiuMX2azg=\n-----END PUBLIC KEY-----\n";
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAERHnScWeyI8R9LNgXVEJGjb/Cg8sopnWQJlfqkOv02 me@host";

fn token(org: Uuid, project: Uuid, instance: Uuid, action: &str, generation: i64) -> String {
    let now = Utc::now().timestamp();
    let claims = ProviderClaims {
        issuer: "heterocloud".into(),
        audience: "heterocloud-vm".into(),
        subject: Uuid::now_v7(),
        user_id: None,
        organization_id: org,
        project_id: project,
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

struct Env {
    addr: std::net::SocketAddr,
    pve: mock_pve::Shared,
    org: Uuid,
    project: Uuid,
    instance: Uuid,
}

async fn env(sessions: usize) -> Env {
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
            max_vms: 4,
            flash_snat: vec![],
            external: None,
        },
        None,
        None,
    );
    let authenticator = ProviderAuthenticator::from_public_keys_json(
        "heterocloud",
        "heterocloud-vm",
        &json!({"test-key": PUBLIC_KEY}).to_string(),
    )
    .unwrap();
    let app = router(Arc::new(AppState {
        authenticator,
        reconciler: reconciler.clone(),
        region: "heteronet-global".into(),
        shell_sessions: Arc::new(tokio::sync::Semaphore::new(sessions)),
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (org, project, instance) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    // Create the VM through the provider API, polling like the worker.
    let http = reqwest::Client::new();
    let spec = json!({"region": "heteronet-global", "image": "ubuntu-26.04", "cpu_cores": 1, "memory_mib": 1024, "disk_gib": 10, "ssh_authorized_keys": [KEY]});
    for _ in 0..30 {
        let response = http
            .put(format!(
                "http://{addr}/internal/v1/service-instances/{instance}"
            ))
            .bearer_auth(token(
                org,
                project,
                instance,
                "service-instance.reconcile",
                1,
            ))
            .json(&json!({"generation": 1, "name": "shell", "spec": spec}))
            .send()
            .await
            .unwrap();
        if response.status() == 202 {
            return Env {
                addr,
                pve,
                org,
                project,
                instance,
            };
        }
    }
    panic!("VM never converged");
}

fn shell_request(
    e: &Env,
    action: &str,
    generation: i64,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    shell_request_for(e, "shell", action, generation)
}

fn shell_request_for(
    e: &Env,
    path: &str,
    action: &str,
    generation: i64,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let url = format!(
        "ws://{}/internal/v1/service-instances/{}/{path}?generation={generation}",
        e.addr, e.instance
    );
    let mut request = url.into_client_request().unwrap();
    request.headers_mut().insert(
        "Authorization",
        format!(
            "Bearer {}",
            token(e.org, e.project, e.instance, action, generation)
        )
        .parse()
        .unwrap(),
    );
    request
}

#[tokio::test]
async fn the_shell_relays_input_output_and_resizes() {
    let e = env(4).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(shell_request(&e, "vm.shell", 1))
        .await
        .unwrap();

    socket
        .send(Message::Binary(b"echo hi\n".to_vec().into()))
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The handshake's "OK" is swallowed; what arrives is the terminal output (binary).
    assert_eq!(reply, Message::Binary(b"echo:echo hi\n".to_vec().into()));

    socket
        .send(Message::Text(
            r#"{"type":"resize","cols":120,"rows":40}"#.into(),
        ))
        .await
        .unwrap();
    // Multi-byte input is counted in bytes by the frame.
    socket
        .send(Message::Binary("é".as_bytes().to_vec().into()))
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(reply, Message::Binary("echo:é".as_bytes().to_vec().into()));
    assert!(
        e.pve
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c.ends_with("120x40")),
        "resize reached Proxmox"
    );
    socket.close(None).await.unwrap();
}

#[tokio::test]
async fn shell_requires_a_running_vm_and_the_right_token() {
    let e = env(4).await;
    // Wrong action, wrong generation and a stopped VM are refused before any socket exists.
    for (action, generation) in [("service-instance.reconcile", 1), ("vm.shell", 2)] {
        let result = tokio_tungstenite::connect_async(shell_request(&e, action, generation)).await;
        assert!(result.is_err(), "{action} generation {generation}");
    }
    {
        let mut s = e.pve.lock().unwrap();
        for vm in s.vms.values_mut().filter(|vm| !vm.template) {
            vm.status = "stopped".into();
        }
    }
    assert!(
        tokio_tungstenite::connect_async(shell_request(&e, "vm.shell", 1))
            .await
            .is_err()
    );
    assert!(
        !e.pve
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c.starts_with("termproxy")),
        "no terminal was started"
    );
}

#[tokio::test]
async fn open_shells_are_bounded() {
    let e = env(1).await;
    let (_first, _) = tokio_tungstenite::connect_async(shell_request(&e, "vm.shell", 1))
        .await
        .unwrap();
    assert!(
        tokio_tungstenite::connect_async(shell_request(&e, "vm.shell", 1))
            .await
            .is_err(),
        "the second shell is refused"
    );
}

#[tokio::test]
async fn the_graphical_console_authenticates_for_the_browser() {
    let e = env(4).await;
    let (mut socket, _) =
        tokio_tungstenite::connect_async(shell_request_for(&e, "console", "vm.console", 1))
            .await
            .unwrap();
    async fn next(
        socket: &mut (
                 impl futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
                 + Unpin
             ),
    ) -> Vec<u8> {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        message.into_data().to_vec()
    }
    assert_eq!(next(&mut socket).await, b"RFB 003.008\n");
    socket
        .send(Message::Binary(b"RFB 003.008\n".to_vec().into()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut socket).await,
        vec![1, 1],
        "the browser is offered no authentication"
    );
    socket.send(Message::Binary(vec![1].into())).await.unwrap();
    assert_eq!(next(&mut socket).await, vec![0, 0, 0, 0]);
    // From here on the stream is relayed unchanged.
    socket.send(Message::Binary(vec![1].into())).await.unwrap();
    assert_eq!(next(&mut socket).await, b"SERVERINIT");
}

#[tokio::test]
async fn the_console_needs_its_own_action() {
    let e = env(4).await;
    assert!(
        tokio_tungstenite::connect_async(shell_request_for(&e, "console", "vm.shell", 1))
            .await
            .is_err()
    );
    assert!(
        tokio_tungstenite::connect_async(shell_request_for(&e, "shell", "vm.console", 1))
            .await
            .is_err()
    );
}
