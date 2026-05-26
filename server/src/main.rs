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
//! 3. Forwards the encrypted payload with the sender's ID:
//!    `[sender_id_len (u16 LE)][sender_id bytes][encrypted payload]`
//!
//! If the recipient is not connected, the server sends back an error frame:
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
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

/// Shared application state: maps client ID → channel to send messages to that client.
///
/// Client IDs are raw bytes (public key hashes). Multiple WebSocket connections may
/// share the same client ID (e.g. multiple browser tabs).
#[derive(Default)]
struct ConnectionMap {
    clients: HashMap<Vec<u8>, Vec<mpsc::UnboundedSender<Vec<u8>>>>,
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

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

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

    // Register this client's sender in the shared connection map.
    {
        let mut map = state.write().await;
        map.clients
            .entry(session_id.to_vec())
            .or_default()
            .push(tx);
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

    // Look up the recipient in the connection map
    let map = state.read().await;
    if let Some(senders) = map.clients.get(recipient_id) {
        // Forward to all connections of this recipient (e.g. all tabs)
        let mut delivered = false;
        for tx in senders.iter() {
            if tx.send(forward.clone()).is_ok() {
                delivered = true;
            }
        }
        if delivered {
            info!(
                "Relayed {}b: {} → {}",
                payload.len(),
                hex_fmt(sender_id, 8),
                hex_fmt(recipient_id, 8)
            );
        } else {
            warn!(
                "All connections lost for recipient: {}",
                hex_fmt(recipient_id, 8)
            );
            send_error(state, sender_id, recipient_id).await;
        }
    } else {
        warn!(
            "Recipient not connected: {}",
            hex_fmt(recipient_id, 8)
        );
        send_error(state, sender_id, recipient_id).await;
    }
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
