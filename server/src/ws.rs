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
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, trace, warn};

use crate::p2p::NodeCommand;
use tokio::sync::oneshot;

// ── Protocol constants ──────────────────────────────────────────────

const PROFILE_SUCCESS: [u8; 3] = [0xFE, 0x00, 0x00];
const PROFILE_OCCUPIED: [u8; 3] = [0xFF, 0x00, 0x01];

/// Rate limit: max store operations per second per client
const RATE_LIMIT_STORE_PER_SEC: f64 = 10.0;
/// Rate limit: max retrieve/lookup operations per second per client
const RATE_LIMIT_LOOKUP_PER_SEC: f64 = 1.0;

// ── Shared state ────────────────────────────────────────────────────

/// Simple token bucket for rate limiting.
#[derive(Clone)]
pub struct TokenBucket {
    tokens: f64,
    last_refill: std::time::Instant,
    rate: f64,
    capacity: f64,
}

impl TokenBucket {
    pub fn new(rate: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: std::time::Instant::now(),
            rate,
            capacity,
        }
    }

    /// Try to consume `n` tokens. Returns `true` if allowed.
    pub fn try_consume(&mut self, n: f64) -> bool {
        self.refill();
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = std::time::Instant::now();
    }
}

/// Internal state of the WebSocket gateway.
pub struct GatewayStateInner {
    /// WS senders: user_hash → list of send channels
    pub clients: HashMap<Vec<u8>, Vec<mpsc::UnboundedSender<Vec<u8>>>>,
    /// P2P node command channel (for DHT mailbox storage and profiles)
    pub p2p_cmd_tx: Option<mpsc::Sender<NodeCommand>>,
    /// Whether the P2P node has at least one connection
    pub p2p_connected: bool,
    /// Per-client rate limiters: session_id → (store_bucket, lookup_bucket)
    pub rate_limiters: HashMap<Vec<u8>, (TokenBucket, TokenBucket)>,
}

use std::collections::HashMap;

impl Default for GatewayStateInner {
    fn default() -> Self {
        Self {
            clients: HashMap::new(),
            p2p_cmd_tx: None,
            p2p_connected: false,
            rate_limiters: HashMap::new(),
        }
    }
}

pub type SharedState = Arc<RwLock<GatewayStateInner>>;

// ── Router ──────────────────────────────────────────────────────────

pub fn build_gateway_router() -> Router<SharedState> {
    Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(health_handler))
}

/// GET /health — returns 200 if the gateway and P2P node are operational.
async fn health_handler(
    State(gateway_state): State<SharedState>,
) -> impl IntoResponse {
    let map = gateway_state.read().await;
    if map.p2p_connected {
        (StatusCode::OK, "OK\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "P2P not connected\n")
    }
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

    // Subscribe to GossipSub topic for realtime delivery
    {
        let map = gateway_state.read().await;
        if let Some(ref cmd_tx) = map.p2p_cmd_tx {
            let topic = hex::encode(&session_id);
            let _ = cmd_tx.send(NodeCommand::Subscribe { topic }).await;
            info!("Subscribed to GossipSub topic for {}", hex_fmt(&session_id, 8));
        }
    }

    // Init rate limiters for this client
    {
        let mut map = gateway_state.write().await;
        map.rate_limiters.insert(session_id.to_vec(), (
            TokenBucket::new(RATE_LIMIT_STORE_PER_SEC, RATE_LIMIT_STORE_PER_SEC),
            TokenBucket::new(RATE_LIMIT_LOOKUP_PER_SEC, RATE_LIMIT_LOOKUP_PER_SEC),
        ));
    }

    // Trigger DHT mailbox retrieval for offline messages
    {
        let map = gateway_state.read().await;
        if let Some(ref cmd_tx) = map.p2p_cmd_tx {
            let cmd = NodeCommand::MailboxRetrieve { user_hash: session_id.clone() };
            let _ = cmd_tx.send(cmd).await;
            info!("MailboxRetrieve triggered for {}", hex_fmt(&session_id, 8));
        }
    }

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
        // Remove rate limiters for this client
        map.rate_limiters.remove(session_id.as_ref());
        // Clean up senders
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

/// Check if a client has exceeded their rate limit for store operations.
fn check_rate_limit_store(state: &mut GatewayStateInner, client_id: &[u8]) -> bool {
    if let Some((ref mut store_bucket, _)) = state.rate_limiters.get_mut(client_id) {
        store_bucket.try_consume(1.0)
    } else {
        true // no rate limiter = allow
    }
}

/// Try local delivery first, else GossipSub, else store in DHT mailbox.
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

    // Rate limit: max 10 store operations per second per client
    {
        let mut map = state.write().await;
        if !check_rate_limit_store(&mut map, sender_id) {
            warn!("Rate limit exceeded for store: {}", hex_fmt(sender_id, 8));
            return;
        }
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

    // Try GossipSub realtime delivery (for recipients on other nodes)
    {
        let map = state.read().await;
        if let Some(ref cmd_tx) = map.p2p_cmd_tx {
            let topic = hex::encode(recipient_id);
            let cmd = NodeCommand::Publish {
                topic: topic.clone(),
                data: forward.clone(),
            };
            let _ = cmd_tx.send(cmd).await;
            trace!("GossipSub publish to topic {} for {}", topic, hex_fmt(recipient_id, 8));
        }
    }

    // Store in sequential DHT mailbox via P2P node (durable offline store)
    info!(
        "MailboxStore: queueing {}b for {}",
        payload.len(),
        hex_fmt(recipient_id, 8)
    );

    {
        let map = state.read().await;
        if let Some(ref cmd_tx) = map.p2p_cmd_tx {
            let cmd = NodeCommand::MailboxStore {
                recipient_hash: recipient_id.to_vec(),
                sender_hash: sender_id.to_vec(),
                payload: payload.to_vec(),
            };
            if let Err(e) = cmd_tx.send(cmd).await {
                warn!("Failed to send MailboxStore: {e}");
            }
        }
    }
}

// ── Profile operations (DHT-backed) ──────────────────────────────────

async fn handle_profile_operation(
    state: &SharedState,
    client_id: &[u8],
    opcode: u8,
    payload: &[u8],
) {
    let response = match opcode {
        0x01 => handle_register_profile(state, client_id, payload).await,
        0x02 => handle_lookup_profile(state, payload).await,
        0x03 => handle_unregister_profile(state, payload).await,
        0x04 => handle_update_profile(state, payload).await,
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

/// Register a blind username in the DHT.
/// 1. First queries DHT to check if the search_index is already taken
/// 2. If free, stores the encrypted blob in DHT via ProfileStore
async fn handle_register_profile(
    state: &SharedState,
    _owner_id: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        return None;
    }
    let index = payload[..32].to_vec();
    let blob = payload[32..].to_vec();

    let cmd_tx = {
        let map = state.read().await;
        map.p2p_cmd_tx.clone()
    };
    let cmd_tx = cmd_tx?;

    // Step 1: Check if profile already exists in DHT
    let (tx, rx) = oneshot::channel();
    if cmd_tx.send(NodeCommand::ProfileLookup {
        index: index.clone(),
        resp: tx,
    }).await.is_err() {
        return None;
    }

    let existing = match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
        Ok(Ok(blob)) => blob,
        _ => None,
    };

    if existing.is_some() {
        info!("Profile occupied: index {}", hex_fmt(&index, 8));
        return Some(PROFILE_OCCUPIED.to_vec());
    }

    // Step 2: Store in DHT
    if cmd_tx.send(NodeCommand::ProfileStore { index, blob }).await.is_err() {
        return None;
    }

    Some(PROFILE_SUCCESS.to_vec())
}

/// Look up a blind username in the DHT.
/// Queries DHT via ProfileLookup, returns the encrypted blob or "not found".
async fn handle_lookup_profile(state: &SharedState, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        return None;
    }
    let index = payload[..32].to_vec();

    let cmd_tx = {
        let map = state.read().await;
        map.p2p_cmd_tx.clone()
    };
    let cmd_tx = cmd_tx?;

    let (tx, rx) = oneshot::channel();
    if cmd_tx.send(NodeCommand::ProfileLookup {
        index,
        resp: tx,
    }).await.is_err() {
        return None;
    }

    let blob = match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
        Ok(Ok(b)) => b,
        _ => None,
    };

    match blob {
        Some(data) => {
            let mut resp = vec![0xFE, 0x01];
            let len16 = data.len() as u16;
            resp.extend_from_slice(&len16.to_le_bytes());
            resp.extend_from_slice(&data);
            Some(resp)
        }
        None => Some(vec![0xFF, 0x01, 0x00]),
    }
}

/// Unregister is not supported for DHT-backed profiles.
/// Returns "operation failed" to the client.
async fn handle_unregister_profile(
    _state: &SharedState,
    _payload: &[u8],
) -> Option<Vec<u8>> {
    info!("UnregisterProfile not supported in DHT mode");
    Some(vec![0xFF, 0x02, 0x00])
}

/// Update profile by overwriting the DHT entry.
/// Anyone who knows the search_index can overwrite, which is acceptable
/// since the blob is AES-GCM encrypted with a key derived from the username.
async fn handle_update_profile(
    state: &SharedState,
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

    let cmd_tx = {
        let map = state.read().await;
        map.p2p_cmd_tx.clone()
    };
    let cmd_tx = cmd_tx?;

    if cmd_tx.send(NodeCommand::ProfileStore { index, blob: new_blob }).await.is_err() {
        return None;
    }

    Some(vec![0xFE, 0x03, 0x00])
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
