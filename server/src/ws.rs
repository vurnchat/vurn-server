//! # WebSocket Gateway
//!
//! Local WebSocket gateway that bridges browser clients to the P2P network.
//!
//! Runs on localhost and uses the same WS protocol the VurnChat web client
//! expects, while routing offline messages through the P2P DHT.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::p2p::NodeCommand;

// ── Protocol constants ──────────────────────────────────────────────

const PROFILE_SUCCESS: [u8; 3] = [0xFE, 0x00, 0x00];
const PROFILE_OCCUPIED: [u8; 3] = [0xFF, 0x00, 0x01];

// ── Profile entry ───────────────────────────────────────────────────

pub struct ProfileEntry {
    owner_hash: Vec<u8>,
    blob: Vec<u8>,
}

// ── Shared state ────────────────────────────────────────────────────

/// Internal state of the WebSocket gateway.
pub struct GatewayStateInner {
    /// WS senders: user_hash → list of send channels
    pub clients: HashMap<Vec<u8>, Vec<mpsc::UnboundedSender<Vec<u8>>>>,
    /// Blind profiles: search index → encrypted blob
    pub blind_profiles: HashMap<Vec<u8>, ProfileEntry>,
    /// Owner hash → search index (one username per user)
    pub user_profiles: HashMap<Vec<u8>, Vec<u8>>,
    /// P2P node command channel (for DHT mailbox storage)
    pub p2p_cmd_tx: Option<mpsc::Sender<NodeCommand>>,
}

use std::collections::HashMap;

impl Default for GatewayStateInner {
    fn default() -> Self {
        Self {
            clients: HashMap::new(),
            blind_profiles: HashMap::new(),
            user_profiles: HashMap::new(),
            p2p_cmd_tx: None,
        }
    }
}

pub type SharedState = Arc<RwLock<GatewayStateInner>>;

// ── Router ──────────────────────────────────────────────────────────

pub fn build_gateway_router() -> Router<SharedState> {
    Router::new().route("/ws", get(ws_handler))
}

// ── WebSocket upgrade ───────────────────────────────────────────────

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(gateway_state): State<SharedState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, gateway_state))
}

// ── Connection handler ──────────────────────────────────────────────

async fn handle_ws_connection(socket: WebSocket, gateway_state: SharedState) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Step 1: Registration
    let session_id: Vec<u8> = match ws_stream.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        Some(Ok(_)) => {
            warn!("Client sent non-binary first message");
            return;
        }
        Some(Err(e)) => {
            error!("WebSocket error during registration: {e}");
            return;
        }
        None => {
            info!("Client disconnected before registration");
            return;
        }
    };

    if session_id.is_empty() {
        warn!("Client sent empty session ID");
        return;
    }

    info!("Client registered: {}", hex_fmt(&session_id, 8));
    let session_id = Arc::new(session_id);

    // Step 2: Create forwarding channel
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    {
        let mut map = gateway_state.write().await;
        map.clients
            .entry(session_id.to_vec())
            .or_default()
            .push(tx);
    }

    // Step 3: Spawn forward task
    let sid_clone = session_id.clone();
    let state_clone = gateway_state.clone();
    let forward_task = tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            if ws_sink.send(Message::Binary(payload)).await.is_err() {
                info!("Forward task: client {} disconnected", hex_fmt(&sid_clone, 8));
                let mut map = state_clone.write().await;
                if let Some(senders) = map.clients.get_mut(sid_clone.as_ref()) {
                    senders.retain(|s| !s.is_closed());
                    if senders.is_empty() {
                        map.clients.remove(sid_clone.as_ref());
                    }
                }
                break;
            }
        }
    });

    // Step 4: Read messages from client
    while let Some(msg) = ws_stream.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                if data.len() >= 2 && data[0] == 0x00 {
                    handle_profile_operation(&gateway_state, &session_id, data[1], &data[2..]).await;
                } else {
                    relay_or_p2p(&gateway_state, &session_id, &data).await;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
            Ok(Message::Text(_)) => {}
            Err(e) => {
                error!("WS error for {}: {e}", hex_fmt(&session_id, 8));
                break;
            }
        }
    }

    // Step 5: Cleanup
    info!("Client disconnected: {}", hex_fmt(&session_id, 8));
    {
        let mut map = gateway_state.write().await;
        if let Some(senders) = map.clients.get_mut(session_id.as_ref()) {
            senders.retain(|s| !s.is_closed());
            if senders.is_empty() {
                map.clients.remove(session_id.as_ref());
            }
        }
    }
    forward_task.abort();
}

// ── Relay ───────────────────────────────────────────────────────────

/// Try local delivery first, else store in P2P DHT mailbox.
async fn relay_or_p2p(state: &SharedState, sender_id: &[u8], data: &[u8]) {
    if data.len() < 2 {
        return;
    }

    let id_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if id_len == 0 || data.len() < 2 + id_len {
        return;
    }

    let recipient_id = &data[2..2 + id_len];
    let payload = &data[2 + id_len..];
    if payload.is_empty() {
        return;
    }

    // Build forward frame
    let mut forward = Vec::with_capacity(2 + sender_id.len() + payload.len());
    forward.extend_from_slice(&(sender_id.len() as u16).to_le_bytes());
    forward.extend_from_slice(sender_id);
    forward.extend_from_slice(payload);

    // Try local delivery
    let delivered = {
        let map = state.read().await;
        if let Some(senders) = map.clients.get(recipient_id) {
            let mut ok = false;
            for tx in senders {
                if tx.send(forward.clone()).is_ok() {
                    ok = true;
                }
            }
            ok
        } else {
            false
        }
    };

    if delivered {
        info!("Local relay: {} → {}", hex_fmt(sender_id, 8), hex_fmt(recipient_id, 8));
        return;
    }

    // Store in DHT mailbox via P2P node
    info!(
        "P2P store: queueing {}b for {} in DHT",
        payload.len(),
        hex_fmt(recipient_id, 8)
    );

    let map = state.read().await;
    if let Some(ref cmd_tx) = map.p2p_cmd_tx {
        let msg = crate::p2p::encode_mailbox_message(sender_id, payload);
        let key = crate::p2p::mailbox_key(recipient_id);
        let cmd = NodeCommand::DhtStore {
            key: key.to_vec(),
            value: msg,
        };
        if let Err(e) = cmd_tx.send(cmd).await {
            warn!("Failed to send DHT store: {e}");
        }
    }
}

// ── Profile operations (unchanged) ──────────────────────────────────

async fn handle_profile_operation(
    state: &SharedState,
    client_id: &[u8],
    opcode: u8,
    payload: &[u8],
) {
    let response = match opcode {
        0x01 => handle_register_profile(state, client_id, payload).await,
        0x02 => handle_lookup_profile(state, payload).await,
        0x03 => handle_unregister_profile(state, client_id, payload).await,
        0x04 => handle_update_profile(state, client_id, payload).await,
        _ => {
            warn!("Unknown profile operation: 0x{opcode:02x}");
            return;
        }
    };

    if let Some(data) = response {
        let map = state.read().await;
        if let Some(senders) = map.clients.get(client_id) {
            for tx in senders {
                let _ = tx.send(data.clone());
            }
        }
    }
}

async fn handle_register_profile(
    state: &SharedState,
    owner_id: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        return None;
    }
    let new_index = payload[..32].to_vec();
    let blob = payload[32..].to_vec();
    let mut map = state.write().await;
    if let Some(existing) = map.blind_profiles.get(&new_index) {
        if existing.owner_hash != owner_id {
            return Some(PROFILE_OCCUPIED.to_vec());
        }
    }
    let old_index = map.user_profiles.get(owner_id).cloned();
    if let Some(ref old) = old_index {
        if *old != new_index {
            map.blind_profiles.remove(old);
        }
    }
    map.blind_profiles.insert(new_index, ProfileEntry {
        owner_hash: owner_id.to_vec(),
        blob,
    });
    map.user_profiles.insert(owner_id.to_vec(), old_index.unwrap_or_default());
    Some(PROFILE_SUCCESS.to_vec())
}

async fn handle_lookup_profile(state: &SharedState, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        return None;
    }
    let index = payload[..32].to_vec();
    let map = state.read().await;
    if let Some(entry) = map.blind_profiles.get(&index) {
        let mut resp = vec![0xFE, 0x01];
        resp.extend_from_slice(&(entry.blob.len() as u16).to_le_bytes());
        resp.extend_from_slice(&entry.blob);
        Some(resp)
    } else {
        Some(vec![0xFF, 0x01, 0x00])
    }
}

async fn handle_unregister_profile(
    state: &SharedState,
    caller_id: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        return None;
    }
    let index = payload[..32].to_vec();
    let mut map = state.write().await;
    match map.blind_profiles.get(&index) {
        Some(entry) if entry.owner_hash == caller_id => {
            map.blind_profiles.remove(&index);
            Some(vec![0xFE, 0x02, 0x00])
        }
        _ => Some(vec![0xFF, 0x02, 0x00]),
    }
}

async fn handle_update_profile(
    state: &SharedState,
    caller_id: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        return None;
    }
    let index = payload[..32].to_vec();
    let new_blob = payload[32..].to_vec();
    if new_blob.is_empty() {
        return None;
    }
    let mut map = state.write().await;
    match map.blind_profiles.get_mut(&index) {
        Some(entry) if entry.owner_hash == caller_id => {
            entry.blob = new_blob;
            Some(vec![0xFE, 0x03, 0x00])
        }
        _ => Some(vec![0xFF, 0x03, 0x00]),
    }
}

// ── Helper ──────────────────────────────────────────────────────────

pub fn hex_fmt(bytes: &[u8], max: usize) -> String {
    let len = bytes.len().min(max);
    let s: String = bytes[..len].iter().map(|b| format!("{b:02x}")).collect();
    if bytes.len() > max {
        format!("{s}…({}b)", bytes.len())
    } else {
        format!("{s}({}b)", bytes.len())
    }
}
