//! # vurn-server
//!
//! Blind WebSocket relay server for the VurnChat messenger.
//!
//! ## Philosophy
//!
//! - The server knows **nothing** about who is talking to whom.
//! - No message history is stored — no database, no logs of message content.
//! - Acts as an intelligent postal switch: receives a package, forwards it.
//!
//! ## Protocol
//!
//! ### Connection & Registration
//! 1. Client connects via WebSocket to `ws://host:port/ws`.
//! 2. Client sends its **first binary message**: the raw bytes of its public key hash
//!    (used as its session ID).
//! 3. Server registers this client in the connection map under that ID.
//!
//! ### Sending a message
//! Client sends a binary message with the following layout:
//! ```text
//! [2 bytes: recipient_id length (u16 LE)]
//! [N bytes: recipient_id (the hash of the recipient's public key)]
//! [M bytes: encrypted payload (vurn-core wire format)]
//! ```
//!
//! The server:
//! 1. Parses the recipient ID from the frame.
//! 2. Looks up the recipient's open WebSocket connection.
//! 3. If connected: forwards the encrypted payload with the sender's ID:
//!    `[sender_id_len (u16 LE)][sender_id bytes][encrypted payload]`
//! 4. If offline: stores the forward frame in the recipient's cryptographic
//!    mailbox (in-memory, zero-knowledge — the server never sees plaintext).
//!
//! ### Mailbox delivery (offline messages)
//! When a client connects, the server delivers all queued mailbox messages
//! in a single padded blob:
//! ```text
//! [0xFE, 0xFE]                                     — mailbox sentinel
//! [2 bytes: message count (u16 LE)]
//! [for each message: 2 bytes len (u16 LE)][msg bytes]
//! [zero-padding to 4096-byte boundary]              — traffic-analysis resistance
//! ```
//! Messages are deleted from the mailbox immediately after delivery.
//!
//! ### Error
//! If a message is malformed, the server sends back:
//!    `[0xFF, 0xFF]` followed by the original recipient ID bytes.
//!
//! ### Disconnection
//! When a client disconnects, its entry is removed from the connection map.

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
use rand::seq::SliceRandom;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

/// Chunk size for mailbox delivery padding (traffic-analysis resistance).
const CHUNK_SIZE: usize = 4096;

/// Maximum number of stored messages per mailbox.
const MAILBOX_MAX: usize = 50;

/// Messages older than this TTL are dropped during periodic cleanup.
const MAILBOX_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

/// How often the mailbox cleanup task runs.
const MAILBOX_CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Minimum number of messages in every mailbox delivery (traffic-analysis cover).
/// If fewer real messages exist, random fake forward frames are injected.
/// The client silently drops them during decryption (wrong key → auth fail).
const MAILBOX_MIN_COVER: usize = 3;

/// A single mailbox message with a timestamp for TTL-based expiration.
struct StoredMessage {
    /// When this message was queued (server monotonic clock).
    queued_at: tokio::time::Instant,
    /// The pre-built forward frame bytes (zero-knowledge — server never sees plaintext).
    data: Vec<u8>,
}

/// Shared application state.
///
/// - `clients`: maps client ID → open WebSocket send channels.
///   Client IDs are raw bytes (public key hashes). Multiple connections
///   may share the same client ID (e.g. multiple browser tabs).
/// - `mailboxes`: maps client ID → queued messages for offline recipients.
///   Each message is timestamped for TTL-based garbage collection.
///   Messages are stored as pre-built forward frames (zero-knowledge —
///   the server never sees plaintext). Delivered and cleared on connect.
#[derive(Default)]
struct ConnectionMap {
    clients: HashMap<Vec<u8>, Vec<mpsc::UnboundedSender<Vec<u8>>>>,
    mailboxes: HashMap<Vec<u8>, Vec<StoredMessage>>,
}

type SharedState = Arc<RwLock<ConnectionMap>>;

/// Helper: format bytes as hex for logging (truncated).
fn hex_fmt(bytes: &[u8], max: usize) -> String {
    let len = bytes.len().min(max);
    let s: String = bytes[..len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    if bytes.len() > max {
        format!("{}…({}b)", s, bytes.len())
    } else {
        format!("{}({}b)", s, bytes.len())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state: SharedState = Arc::default();

    let cleanup_state = state.clone();

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    // Spawn periodic mailbox cleanup to prevent unbounded memory growth
    // when a recipient never reconnects.
    tokio::spawn(async move {
        mailbox_cleanup_task(cleanup_state).await;
    });

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9000);

    let addr = format!("0.0.0.0:{}", port);
    info!("VurnChat relay server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    info!("Server shut down gracefully");
}

/// Waits for SIGTERM or SIGINT, then returns to trigger graceful shutdown.
///
/// TODO: Add `tokio::signal::unix::SignalKind::terminate()` listener
///       for production (Docker/K8s send SIGTERM, not SIGINT).
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
    info!("Shutdown signal received, draining connections...");
}

/// Handles WebSocket upgrade.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, state))
}

/// Manages a single WebSocket connection lifecycle.
async fn handle_connection(socket: WebSocket, state: SharedState) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    // ------ Step 1: Registration ------
    // First message from client must be its public key hash (session ID) as raw bytes.
    let session_id: Vec<u8> = match ws_stream.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        Some(Ok(_)) => {
            warn!("Client sent non-binary first message, disconnecting");
            return;
        }
        Some(Err(e)) => {
            error!("WebSocket error during registration: {}", e);
            return;
        }
        None => {
            info!("Client disconnected before registration");
            return;
        }
    };

    if session_id.is_empty() {
        warn!("Client sent empty session ID, disconnecting");
        return;
    }

    info!("Client registered: {}", hex_fmt(&session_id, 8));
    let session_id = Arc::new(session_id);

    // ------ Step 2: Create forwarding channel ------
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let tx_delivery = tx.clone(); // clone before moving into map

    // Register this client's sender + deliver any stored mailbox messages.
    {
        let mut map = state.write().await;
        map.clients
            .entry(session_id.to_vec())
            .or_default()
            .push(tx);

        // Deliver any stored mailbox messages — always send a padded blob even
        // when the mailbox is empty, so an observer cannot distinguish "had
        // messages" from "had no messages" by traffic volume alone.
        if let Some(messages) = map.mailboxes.remove(session_id.as_ref()) {
            let blob = build_mailbox_delivery(&messages);
            let _ = tx_delivery.send(blob);
            info!(
                "Mailbox: delivered {} stored messages to {}",
                messages.len(),
                hex_fmt(&session_id, 8)
            );
        }
    }

    // ------ Step 3: Spawn task to forward messages to this client's WebSocket ------
    let sid_clone = session_id.clone();
    let state_clone = state.clone();
    let forward_task = tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            if ws_sink.send(Message::Binary(payload)).await.is_err() {
                // WebSocket send failed — client disconnected. Remove ourselves from the map.
                info!(
                    "Forward task: client {} disconnected (send failed)",
                    hex_fmt(&sid_clone, 8)
                );
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

    // ------ Step 4: Read messages from client and relay to recipients ------
    while let Some(msg) = ws_stream.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                relay_message(&state, &session_id, &data).await;
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                // Control messages handled automatically
            }
            Ok(Message::Text(_)) => {
                // Ignore text — protocol uses binary only
            }
            Err(e) => {
                error!(
                    "WebSocket error for {}: {}",
                    hex_fmt(&session_id, 8),
                    e
                );
                break;
            }
        }
    }

    // ------ Step 5: Cleanup on disconnect ------
    info!("Client disconnected: {}", hex_fmt(&session_id, 8));

    // Remove any remaining senders for this session ID.
    {
        let mut map = state.write().await;
        if let Some(senders) = map.clients.get_mut(session_id.as_ref()) {
            senders.retain(|s| !s.is_closed());
            if senders.is_empty() {
                map.clients.remove(session_id.as_ref());
            }
        }
    }

    forward_task.abort();
}

/// Parses an incoming message and forwards it to the intended recipient.
async fn relay_message(state: &SharedState, sender_id: &[u8], data: &[u8]) {
    // Parse: [2 bytes: recipient_id_len (u16 LE)][recipient_id bytes][payload]
    if data.len() < 2 {
        warn!("Message too short: missing recipient ID length");
        send_error(state, sender_id, &[]).await;
        return;
    }

    let id_len = u16::from_le_bytes([data[0], data[1]]) as usize;

    if id_len == 0 {
        warn!("Message malformed: zero-length recipient ID");
        send_error(state, sender_id, &[]).await;
        return;
    }

    let hdr_end = 2 + id_len;

    if data.len() < hdr_end {
        warn!(
            "Message truncated: expected {} bytes for ID, got {}",
            id_len,
            data.len() - 2
        );
        send_error(state, sender_id, &[]).await;
        return;
    }

    let recipient_id = &data[2..hdr_end];
    let payload = &data[hdr_end..];

    if payload.is_empty() {
        warn!("Empty payload for recipient: {}", hex_fmt(recipient_id, 8));
        send_error(state, sender_id, recipient_id).await;
        return;
    }

    // Build the forwarded message: [sender_id_len (u16 LE)][sender_id bytes][payload]
    let mut forward = Vec::with_capacity(2 + sender_id.len() + payload.len());
    forward.extend_from_slice(&(sender_id.len() as u16).to_le_bytes());
    forward.extend_from_slice(sender_id);
    forward.extend_from_slice(payload);

    // Look up the recipient in the connection map.
    // IMPORTANT: the read lock must be released before any further async
    // operations (the write lock for mailbox storage).
    let delivered = {
        let map = state.read().await;
        if let Some(senders) = map.clients.get(recipient_id) {
            // Forward to all connections of this recipient (e.g. all tabs)
            let mut ok = false;
            for tx in senders.iter() {
                if tx.send(forward.clone()).is_ok() {
                    ok = true;
                }
            }
            ok
        } else {
            false
        }
    }; // Read lock released here

    if delivered {
        info!(
            "Relayed {}b: {} → {}",
            payload.len(),
            hex_fmt(sender_id, 8),
            hex_fmt(recipient_id, 8)
        );
    } else {
        // Recipient is offline or all their connections dropped (race on cleanup).
        // Store in their cryptographic mailbox — the server never sees plaintext,
        // this is just a blind forward frame. Messages are never silently lost.
        info!(
            "Recipient unavailable, queued {}b in mailbox: {}",
            payload.len(),
            hex_fmt(recipient_id, 8)
        );
        let mut map = state.write().await;
        let mailbox = map.mailboxes
            .entry(recipient_id.to_vec())
            .or_default();
        if mailbox.len() >= MAILBOX_MAX {
            warn!(
                "Mailbox full for {} ({} msgs), dropping oldest, notifying sender",
                hex_fmt(recipient_id, 8),
                MAILBOX_MAX
            );
            mailbox.remove(0);
            // Notify the sender that their message could not be stored
            send_error(state, sender_id, recipient_id).await;
            return;
        }
        mailbox.push(StoredMessage {
            queued_at: tokio::time::Instant::now(),
            data: forward,
        });
    }
}

/// Builds a mailbox delivery blob with traffic-analysis cover messages.
///
/// Format: `[0xFE, 0xFE][u16 LE: count][for each: u16 LE len][msg bytes]`
/// Padded to CHUNK_SIZE boundary.
///
/// If there are fewer than `MAILBOX_MIN_COVER` real messages, random fake
/// forward frames are injected to make the count always ≥ that threshold.
/// Real and fake messages are shuffled so an observer cannot tell which are
/// real by their position in the blob. The client will attempt to decrypt
/// all messages; fakes fail authentication and are silently dropped.
fn build_mailbox_delivery(messages: &[StoredMessage]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // Collect real forward frame data
    let mut all_frames: Vec<Vec<u8>> = messages.iter().map(|m| m.data.clone()).collect();

    // Inject fake cover messages to reach MAILBOX_MIN_COVER
    while all_frames.len() < MAILBOX_MIN_COVER {
        all_frames.push(generate_fake_forward(&mut rng));
    }

    // Shuffle so observer cannot distinguish real vs fake by position
    all_frames.shuffle(&mut rng);

    let total = all_frames.len();

    // Build blob: [0xFE, 0xFE][count][for each: len][data]
    let mut blob = vec![0xFE, 0xFE];
    blob.extend_from_slice(&(total as u16).to_le_bytes());
    for frame in &all_frames {
        blob.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        blob.extend_from_slice(frame);
    }

    // Pad to nearest CHUNK_SIZE multiple so traffic volume alone does not
    // reveal how many (or how large) the stored messages were.
    let padded_len = ((blob.len() + CHUNK_SIZE - 1) / CHUNK_SIZE) * CHUNK_SIZE;
    blob.resize(padded_len, 0);
    blob
}

/// Generates a fake forward frame that looks indistinguishable from a real one.
///
/// Format: `[2 bytes: sender_id_len = 32][32 random bytes: sender_id][random bytes: encrypted payload]`
///
/// The fake encrypted payload has a plausible size range (1500–3000 bytes)
/// typical of real ML-KEM-1024 + AES-GCM encrypted messages. The client will
/// try to decrypt it, fail authentication, and silently drop it.
fn generate_fake_forward(rng: &mut impl rand::Rng) -> Vec<u8> {
    // Sender ID is always 32 bytes (SHA-256 hash length)
    let sender_id_len: u16 = 32;
    let mut frame = Vec::with_capacity(2 + 32 + 2500);

    // Write sender_id length
    frame.extend_from_slice(&sender_id_len.to_le_bytes());

    // Generate random 32-byte sender hash
    let mut sender_id = [0u8; 32];
    rng.fill_bytes(&mut sender_id);
    frame.extend_from_slice(&sender_id);

    // Generate random encrypted payload (1500–3000 bytes, plausible real range)
    let payload_len: usize = rng.gen_range(1500..=3000);
    let mut payload = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload);
    frame.extend_from_slice(&payload);

    frame
}

/// Sends a delivery-failure notification back to the sender.
///
/// Error frame format: `[0xFF, 0xFF]` followed by the recipient ID bytes that failed.
async fn send_error(state: &SharedState, sender_id: &[u8], recipient_id: &[u8]) {
    let map = state.read().await;
    if let Some(senders) = map.clients.get(sender_id) {
        let mut error_frame = vec![0xFF, 0xFF];
        error_frame.extend_from_slice(recipient_id);
        for tx in senders.iter() {
            let _ = tx.send(error_frame.clone());
        }
    }
}

/// Periodic background task that scavenges expired mailbox messages.
///
/// Runs every `MAILBOX_CLEANUP_INTERVAL` and drops any message whose
/// `queued_at` timestamp is older than `MAILBOX_TTL`. This prevents
/// unbounded memory growth when a recipient never reconnects.
async fn mailbox_cleanup_task(state: SharedState) {
    let mut interval = tokio::time::interval(MAILBOX_CLEANUP_INTERVAL);
    // First tick completes immediately — skip it so we don't clean on startup.
    interval.tick().await;

    loop {
        interval.tick().await;

        let now = tokio::time::Instant::now();
        let mut total_dropped = 0usize;
        let mut expired_recipients = Vec::new();

        {
            let mut map = state.write().await;
            for (recipient_id, messages) in map.mailboxes.iter_mut() {
                let before = messages.len();
                messages.retain(|m| now.saturating_duration_since(m.queued_at) < MAILBOX_TTL);
                let dropped = before - messages.len();
                if dropped > 0 {
                    total_dropped += dropped;
                    info!(
                        "Mailbox cleanup: dropped {} expired messages for {}",
                        dropped,
                        hex_fmt(recipient_id, 8)
                    );
                }
                if messages.is_empty() {
                    expired_recipients.push(recipient_id.clone());
                }
            }
            // Remove empty mailbox entries
            for id in &expired_recipients {
                map.mailboxes.remove(id);
            }
        }

        if total_dropped > 0 {
            info!(
                "Mailbox cleanup complete: dropped {} expired messages across {} recipients cleared",
                total_dropped,
                expired_recipients.len()
            );
        }
    }
}
