//! The browser shell: the Proxmox serial terminal, relayed over WebSocket.
//!
//! The browser side speaks the same small protocol as the Flash shell: binary frames are
//! terminal input, a text frame `{"type":"resize","cols":N,"rows":N}` resizes the terminal
//! and terminal output comes back as binary frames. Towards Proxmox the frames are
//! translated to the `termproxy` protocol (`0:<len>:<data>` input, `1:<cols>:<rows>:` resize,
//! `2` keepalive).

use std::time::Duration;

use axum::extract::ws::{Message as Browser, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio_tungstenite::tungstenite::Message as Pve;

use crate::pve::{TermProxy, TerminalSocket};

const KEEPALIVE: Duration = Duration::from_secs(30);
const MAX_SESSION: Duration = Duration::from_secs(4 * 60 * 60);

#[derive(Deserialize)]
struct Control {
    #[serde(rename = "type")]
    kind: String,
    cols: Option<u16>,
    rows: Option<u16>,
}

/// `0:<byte length>:<data>`, the termproxy input frame.
pub fn input_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = format!("0:{}:", data.len()).into_bytes();
    frame.extend_from_slice(data);
    frame
}

/// `1:<cols>:<rows>:`, the termproxy resize frame; sizes are clamped to a sane range.
pub fn resize_frame(cols: u16, rows: u16) -> String {
    format!("1:{}:{}:", cols.clamp(10, 500), rows.clamp(2, 200))
}

fn pve_text(bytes: Vec<u8>) -> Pve {
    // termproxy frames are text; keyboard input is UTF-8, anything else is replaced.
    Pve::Text(String::from_utf8_lossy(&bytes).into_owned().into())
}

pub async fn bridge(browser: WebSocket, mut pve: TerminalSocket, proxy: TermProxy) {
    // The terminal proxy first wants "<user>:<ticket>\n" and answers "OK".
    if pve
        .send(Pve::Text(
            format!("{}:{}\n", proxy.user, proxy.ticket).into(),
        ))
        .await
        .is_err()
    {
        return;
    }
    let (mut to_browser, mut from_browser) = browser.split();
    let (mut to_pve, mut from_pve) = pve.split();
    let mut authenticated = false;
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    let deadline = tokio::time::sleep(MAX_SESSION);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => break,
            _ = keepalive.tick() => {
                if to_pve.send(Pve::Text("2".into())).await.is_err() {
                    break;
                }
            }
            message = from_browser.next() => {
                let Some(Ok(message)) = message else { break };
                let outbound = match message {
                    Browser::Binary(data) => Some(pve_text(input_frame(&data))),
                    Browser::Text(text) => match serde_json::from_str::<Control>(&text) {
                        Ok(Control { kind, cols: Some(cols), rows: Some(rows) }) if kind == "resize" => {
                            Some(Pve::Text(resize_frame(cols, rows).into()))
                        }
                        // Anything else typed as text is plain input.
                        _ => Some(pve_text(input_frame(text.as_bytes()))),
                    },
                    Browser::Close(_) => break,
                    Browser::Ping(_) | Browser::Pong(_) => None,
                };
                if let Some(outbound) = outbound
                    && to_pve.send(outbound).await.is_err()
                {
                    break;
                }
            }
            message = from_pve.next() => {
                let Some(Ok(message)) = message else { break };
                let data: Vec<u8> = match message {
                    Pve::Text(text) => text.as_bytes().to_vec(),
                    Pve::Binary(data) => data.to_vec(),
                    Pve::Close(_) => break,
                    _ => continue,
                };
                if !authenticated {
                    authenticated = true;
                    // The first answer is the "OK" of the handshake; keep any output after it.
                    let rest = data.strip_prefix(b"OK").unwrap_or(&data);
                    if rest.is_empty() {
                        continue;
                    }
                    if to_browser.send(Browser::Binary(rest.to_vec().into())).await.is_err() {
                        break;
                    }
                    continue;
                }
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
    fn input_frames_count_bytes_not_characters() {
        assert_eq!(input_frame(b"ls\n"), b"0:3:ls\n");
        assert_eq!(input_frame("é".as_bytes()), "0:2:é".as_bytes());
    }

    #[test]
    fn resize_frames_are_clamped() {
        assert_eq!(resize_frame(120, 40), "1:120:40:");
        assert_eq!(resize_frame(0, 0), "1:10:2:");
        assert_eq!(resize_frame(60_000, 60_000), "1:500:200:");
    }
}
