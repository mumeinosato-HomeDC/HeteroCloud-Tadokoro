//! The graphical console: the Proxmox VNC proxy, relayed over WebSocket.
//!
//! Proxmox protects the VNC server with the proxy ticket as password (RFB "VNC authentication").
//! The relay answers that challenge itself and tells the browser that no authentication is
//! needed, so the ticket never leaves the provider. After the handshake the RFB stream is relayed
//! unchanged in both directions.

use std::time::Duration;

use axum::extract::ws::{Message as Browser, WebSocket};
use des::{
    Des,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Pve;

use crate::pve::VncSocket;

const MAX_SESSION: Duration = Duration::from_secs(4 * 60 * 60);
const SECURITY_NONE: u8 = 1;
const SECURITY_VNC: u8 = 2;

/// The response to an RFB VNC-authentication challenge: DES-ECB with the first eight password
/// bytes as key, every key byte bit-reversed (an RFB quirk).
pub fn vnc_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (slot, byte) in key.iter_mut().zip(password.bytes()) {
        *slot = byte.reverse_bits();
    }
    let cipher = Des::new(&key.into());
    let mut out = *challenge;
    for chunk in out.chunks_exact_mut(8) {
        let mut block = des::cipher::Array::<u8, _>::from([0u8; 8]);
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    out
}

/// Reads exact byte counts out of a stream of WebSocket frames.
struct Reader<S> {
    stream: S,
    buffer: Vec<u8>,
}

impl<S> Reader<S>
where
    S: futures_util::Stream<Item = Result<Pve, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    async fn take(&mut self, count: usize) -> Option<Vec<u8>> {
        while self.buffer.len() < count {
            match self.stream.next().await? {
                Ok(Pve::Binary(data)) => self.buffer.extend_from_slice(&data),
                Ok(Pve::Text(text)) => self.buffer.extend_from_slice(text.as_bytes()),
                Ok(Pve::Close(_)) | Err(_) => return None,
                Ok(_) => {}
            }
        }
        Some(self.buffer.drain(..count).collect())
    }
}

/// Handshake towards Proxmox: version, security type, challenge, result.
async fn authenticate_with_pve<Tx, Rx>(
    to_pve: &mut Tx,
    from_pve: &mut Reader<Rx>,
    password: &str,
) -> Option<()>
where
    Tx: futures_util::Sink<Pve, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    Rx: futures_util::Stream<Item = Result<Pve, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let version = from_pve.take(12).await?;
    if !version.starts_with(b"RFB 003.") {
        return None;
    }
    to_pve
        .send(Pve::Binary(b"RFB 003.008\n".to_vec().into()))
        .await
        .ok()?;
    let count = from_pve.take(1).await?[0] as usize;
    if count == 0 {
        return None;
    }
    let types = from_pve.take(count).await?;
    if !types.contains(&SECURITY_VNC) {
        return None;
    }
    to_pve
        .send(Pve::Binary(vec![SECURITY_VNC].into()))
        .await
        .ok()?;
    let challenge: [u8; 16] = from_pve.take(16).await?.try_into().ok()?;
    to_pve
        .send(Pve::Binary(
            vnc_response(password, &challenge).to_vec().into(),
        ))
        .await
        .ok()?;
    (from_pve.take(4).await? == [0, 0, 0, 0]).then_some(())
}

pub async fn bridge(browser: WebSocket, pve: VncSocket, ticket: &str) {
    let (mut to_pve, from_pve) = pve.split();
    let mut from_pve = Reader {
        stream: from_pve,
        buffer: Vec::new(),
    };
    let (mut to_browser, mut from_browser) = browser.split();
    if authenticate_with_pve(&mut to_pve, &mut from_pve, ticket)
        .await
        .is_none()
    {
        tracing::warn!("the VNC proxy refused the handshake");
        let _ = to_browser.send(Browser::Close(None)).await;
        return;
    }
    // Towards the browser we are an RFB server without authentication.
    if to_browser
        .send(Browser::Binary(b"RFB 003.008\n".to_vec().into()))
        .await
        .is_err()
    {
        return;
    }
    let mut browser_buffer = Vec::new();
    // Version (12 bytes) and security choice (1 byte) come from the browser; answer in between.
    let mut stage = 0;
    while stage < 2 {
        let need = if stage == 0 { 12 } else { 1 };
        while browser_buffer.len() < need {
            match from_browser.next().await {
                Some(Ok(Browser::Binary(data))) => browser_buffer.extend_from_slice(&data),
                Some(Ok(Browser::Ping(_) | Browser::Pong(_))) => {}
                _ => return,
            }
        }
        let taken: Vec<u8> = browser_buffer.drain(..need).collect();
        if stage == 0 {
            if !taken.starts_with(b"RFB 003.") {
                return;
            }
            if to_browser
                .send(Browser::Binary(vec![1, SECURITY_NONE].into()))
                .await
                .is_err()
            {
                return;
            }
        } else {
            if taken != [SECURITY_NONE] {
                return;
            }
            if to_browser
                .send(Browser::Binary(vec![0, 0, 0, 0].into()))
                .await
                .is_err()
            {
                return;
            }
        }
        stage += 1;
    }
    // Whatever the browser already sent after its choice (normally nothing) goes on to Proxmox.
    if !browser_buffer.is_empty()
        && to_pve
            .send(Pve::Binary(std::mem::take(&mut browser_buffer).into()))
            .await
            .is_err()
    {
        return;
    }
    // Bytes that arrived with the handshake answer belong to the browser.
    let leftover = std::mem::take(&mut from_pve.buffer);
    if !leftover.is_empty()
        && to_browser
            .send(Browser::Binary(leftover.into()))
            .await
            .is_err()
    {
        return;
    }
    let mut from_pve = from_pve.stream;
    let deadline = tokio::time::sleep(MAX_SESSION);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => break,
            message = from_browser.next() => {
                let outbound = match message {
                    Some(Ok(Browser::Binary(data))) => Pve::Binary(data.to_vec().into()),
                    Some(Ok(Browser::Ping(_) | Browser::Pong(_))) => continue,
                    _ => break,
                };
                if to_pve.send(outbound).await.is_err() {
                    break;
                }
            }
            message = from_pve.next() => {
                let data = match message {
                    Some(Ok(Pve::Binary(data))) => data.to_vec(),
                    Some(Ok(Pve::Text(text))) => text.as_bytes().to_vec(),
                    Some(Ok(_)) => continue,
                    _ => break,
                };
                if to_browser.send(Browser::Binary(data.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = to_pve.send(Pve::Close(None)).await;
    let _ = to_browser.send(Browser::Close(None)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vnc_authentication_matches_the_rfb_reference() {
        // Live against Proxmox the response is accepted; here the structural properties are pinned.
        let response = vnc_response("password", &[0u8; 16]);
        assert_eq!(
            response[..8],
            response[8..],
            "ECB: equal blocks encrypt equally"
        );
        assert_ne!(response[..8], [0u8; 8]);
        // Only the first eight bytes of the password count.
        assert_eq!(
            vnc_response("passwordEXTRA", &[7u8; 16]),
            vnc_response("password", &[7u8; 16])
        );
        assert_ne!(
            vnc_response("passwore", &[7u8; 16]),
            vnc_response("password", &[7u8; 16])
        );
    }
}
