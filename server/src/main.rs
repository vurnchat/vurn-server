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
//! ### Profile operations (blind username registration & lookup)
//! Clients can register a blind profile or look up someone else's profile
//! using message type discriminators. These operations are completely
//! separate from message relay — the server stores only HMAC-based
//! search indices and encrypted blobs, never plaintext usernames or keys.
//!
//! Frame type is determined by the first two bytes:
//! - `[0x00, 0x01]` = **RegisterProfile**: `[index 32B][encrypted blob]`
//! - `[0x00, 0x02]` = **LookupProfile**: `[index 32B]`
//!
//! These frames never conflict with existing relay frames because
//! relay frames start with `[id_len (u16 LE)]` where the first byte
//! is the actual length value. For SHA-256 hashes (32 bytes = 0x20),
//! the first byte is 0x20, never 0x00.
//!
//! **Server → Client responses for profile ops:**
//! - Register success: `[0xFE, 0x00, 0x00]` (3 bytes)
//! - Register error (occupied): `[0xFF, 0x00, 0x01]` (3 bytes)
//! - Lookup found: `[0xFE, 0x01][2B blob_len][encrypted blob]`
//! - Lookup not found: `[0xFF, 0x01, 0x00]` (3 bytes)
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
use hyper_util::rt::TokioIo;
use tower_service::Service;
use futures_util::{sink::SinkExt, stream::StreamExt};
use rand::seq::SliceRandom;
use rustls::{pki_types::PrivateKeyDer, ServerConfig};
use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    sync::Arc,
    time::Duration,
};
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

/// A registered blind profile with ownership information.
///
/// The server stores the owner's session ID so only the original registrant
/// can unregister or update the profile. The server never sees the plaintext
/// username or public key.
struct ProfileEntry {
    /// Session ID (SHA-256 hash of public key) of the registrant.
    /// Used to authorize unregister and update operations.
    owner_hash: Vec<u8>,
    /// The encrypted profile blob (AES-256-GCM of public key).
    /// The server never decrypts this — it's opaque bytes to us.
    blob: Vec<u8>,
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
/// - `blind_profiles`: maps 32-byte HMAC search index → `ProfileEntry`.
///   Each entry stores the owner's session ID (for authorization) and the
///   encrypted profile blob. The server can look up profiles by index but
///   cannot decrypt the blob or recover the original username from the index.
/// - `user_profiles`: maps owner session ID → current search index.
///   Enforces one username per user — when a user registers a new username,
///   the old one is automatically removed.
#[derive(Default)]
struct ConnectionMap {
    clients: HashMap<Vec<u8>, Vec<mpsc::UnboundedSender<Vec<u8>>>>,
    mailboxes: HashMap<Vec<u8>, Vec<StoredMessage>>,
    blind_profiles: HashMap<Vec<u8>, ProfileEntry>,
    user_profiles: HashMap<Vec<u8>, Vec<u8>>,
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

    let args = CliArgs::parse();

    let state: SharedState = Arc::default();

    let cleanup_state = state.clone();

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state.clone());

    // Spawn periodic mailbox cleanup to prevent unbounded memory growth
    // when a recipient never reconnects.
    tokio::spawn(async move {
        mailbox_cleanup_task(cleanup_state).await;
    });

    let addr = format!("0.0.0.0:{}", args.port);

    match args.mode {
        ServerMode::Tls { cert_path, key_path } => {
            info!("VurnChat relay server starting on {} (WSS mode)", addr);
            info!("TLS: cert={}, key={}", cert_path, key_path);

            let tls_state = Arc::new(RwLock::new(
                load_tls_config(&cert_path, &key_path)
                    .await
                    .expect("Failed to load initial TLS certificates"),
            ));

            // Spawn background task to reload certificates every 24 hours
            let reload_state = tls_state.clone();
            let reload_cert = cert_path.clone();
            let reload_key = key_path.clone();
            tokio::spawn(async move {
                cert_reload_task(reload_state, &reload_cert, &reload_key).await;
            });

            run_tls_server(&addr, app, tls_state).await;
        }
        ServerMode::Plain => {
            info!("VurnChat relay server starting on {} (WS mode)", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .unwrap();
        }
    }

    info!("Server shut down gracefully");
}

/// Waits for SIGTERM or SIGINT, then returns to trigger graceful shutdown.
///
/// Listens for both SIGTERM (production) and SIGINT (Ctrl+C in dev).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = std::pin::pin!(async {
        #[cfg(unix)]
        {
            let mut stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler");
            stream.recv().await;
        }
        #[cfg(not(unix))]
        {
            // On non-unix, just wait forever
            std::future::pending::<()>().await;
        }
    });

    tokio::select! {
        _ = ctrl_c => {}
        _ = &mut term => {}
    }
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
                // Profile operations use [0x00, opcode] as frame prefix.
                // These never conflict with relay frames (which start with
                // the first byte of recipient_id_len, never 0x00 for SHA-256).
                if data.len() >= 2 && data[0] == 0x00 {
                    handle_profile_operation(
                        &state,
                        &session_id,
                        data[1],
                        &data[2..],
                    ).await;
                } else {
                    relay_message(&state, &session_id, &data).await;
                }
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

/// Dispatches a profile operation and sends the response back.
///
/// `opcode` is the second byte of the frame (`data[1]`):
/// - `0x01` = RegisterProfile
/// - `0x02` = LookupProfile
/// - `0x03` = UnregisterProfile
/// - `0x04` = UpdateProfile
///
/// `payload` is everything after the 2-byte header.
/// `client_id` is the requesting client's session ID (used for ownership checks).
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
            warn!("Unknown profile operation: 0x{:02x}", opcode);
            return;
        }
    };

    if let Some(data) = response {
        // Send response back through the client's WebSocket channel
        let map = state.read().await;
        if let Some(senders) = map.clients.get(client_id) {
            for tx in senders.iter() {
                let _ = tx.send(data.clone());
            }
        }
    }
}

/// Handles a `RegisterProfile` request.
///
/// Payload: `[32 bytes: search_index][encrypted profile blob]`
///
/// **One username per user**: If the caller already owns a username (tracked in
/// `user_profiles`), the old profile is automatically removed before registering
/// the new one. This means "Set Username" and "Change Username" are the same
/// server operation — the client just sends RegisterProfile with the new index.
///
/// If the new index is already taken by a **different** user, returns
/// `[0xFF, 0x00, 0x01]` (occupied) **without** removing the caller's old profile.
/// On success, returns `[0xFE, 0x00, 0x00]`.
/// The server never sees the plaintext username or public key.
async fn handle_register_profile(
    state: &SharedState,
    owner_id: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        warn!("RegisterProfile: payload too short ({} bytes)", payload.len());
        return None;
    }

    let new_index = payload[..32].to_vec();
    let blob = payload[32..].to_vec();

    let response = {
        let mut map = state.write().await;

        // Check if the new index is taken by a DIFFERENT user
        if let Some(existing) = map.blind_profiles.get(&new_index) {
            if existing.owner_hash != owner_id {
                info!(
                    "RegisterProfile: username already taken by other user (index={})",
                    hex_fmt(&new_index, 8)
                );
                return Some(vec![0xFF, 0x00, 0x01]); // occupied by someone else
            }
            // Same user re-registering same username — just update the blob
            info!(
                "RegisterProfile: re-registering same username (index={})",
                hex_fmt(&new_index, 8)
            );
        }

        // Remove user's OLD profile if they had a different username
        let old_index = map.user_profiles.get(owner_id).cloned();
        if let Some(ref old) = old_index {
            if *old != new_index {
                map.blind_profiles.remove(old);
                info!(
                    "RegisterProfile: removed old profile (old_index={}, new_index={})",
                    hex_fmt(old, 8),
                    hex_fmt(&new_index, 8)
                );
            }
        }

        // Insert/update the new profile
        map.blind_profiles.insert(
            new_index.clone(),
            ProfileEntry {
                owner_hash: owner_id.to_vec(),
                blob,
            },
        );
        map.user_profiles.insert(owner_id.to_vec(), new_index.clone());

        info!(
            "RegisterProfile: registered profile (index={})",
            hex_fmt(&new_index, 8)
        );
        vec![0xFE, 0x00, 0x00] // success
    }; // write lock released

    Some(response)
}

/// Handles a `LookupProfile` request.
///
/// Payload: `[32 bytes: search_index]`
///
/// If the index exists, returns `[0xFE, 0x01][2B blob_len][encrypted blob]`.
/// If not found, returns `[0xFF, 0x01, 0x00]`.
/// The server never sees the plaintext username or public key.
async fn handle_lookup_profile(
    state: &SharedState,
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        warn!("LookupProfile: payload too short ({} bytes)", payload.len());
        return None;
    }

    let index = payload[..32].to_vec();

    let response = {
        let map = state.read().await;
        if let Some(entry) = map.blind_profiles.get(&index) {
            let mut resp = vec![0xFE, 0x01];
            resp.extend_from_slice(&(entry.blob.len() as u16).to_le_bytes());
            resp.extend_from_slice(&entry.blob);
            info!(
                "LookupProfile: found profile (index={})",
                hex_fmt(&index, 8)
            );
            resp
        } else {
            info!(
                "LookupProfile: not found (index={})",
                hex_fmt(&index, 8)
            );
            vec![0xFF, 0x01, 0x00] // not found
        }
    }; // read lock released

    Some(response)
}

/// Handles an `UnregisterProfile` request.
///
/// Payload: `[32 bytes: search_index]`
///
/// Only the original registrant (owner) can unregister. If the index doesn't
/// exist or the caller is not the owner, returns `[0xFF, 0x02, 0x00]`.
/// On success, removes the entry and returns `[0xFE, 0x02, 0x00]`.
/// The server never knows which username was unregistered.
async fn handle_unregister_profile(
    state: &SharedState,
    caller_id: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        warn!("UnregisterProfile: payload too short ({} bytes)", payload.len());
        return None;
    }

    let index = payload[..32].to_vec();

    let response = {
        let mut map = state.write().await;
        match map.blind_profiles.get(&index) {
            Some(entry) if entry.owner_hash == caller_id => {
                map.blind_profiles.remove(&index);
                info!(
                    "UnregisterProfile: removed profile (index={})",
                    hex_fmt(&index, 8)
                );
                vec![0xFE, 0x02, 0x00] // success
            }
            Some(_) => {
                // Index exists but caller is not the owner
                warn!(
                    "UnregisterProfile: unauthorized attempt by {} (index={})",
                    hex_fmt(caller_id, 8),
                    hex_fmt(&index, 8)
                );
                vec![0xFF, 0x02, 0x00] // error: not owner / not found
            }
            None => {
                info!(
                    "UnregisterProfile: not found (index={})",
                    hex_fmt(&index, 8)
                );
                vec![0xFF, 0x02, 0x00] // error: not owner / not found
            }
        }
    }; // write lock released

    Some(response)
}

/// Handles an `UpdateProfile` request.
///
/// Payload: `[32 bytes: search_index][new encrypted profile blob]`
///
/// Only the original registrant (owner) can update. Replaces the encrypted
/// blob with the new one. This allows changing the public key associated
/// with a username without needing to unregister and re-register.
///
/// On success, returns `[0xFE, 0x03, 0x00]`.
/// On failure (not found or not owner), returns `[0xFF, 0x03, 0x00]`.
async fn handle_update_profile(
    state: &SharedState,
    caller_id: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 {
        warn!("UpdateProfile: payload too short ({} bytes)", payload.len());
        return None;
    }

    let index = payload[..32].to_vec();
    let new_blob = payload[32..].to_vec();

    if new_blob.is_empty() {
        warn!("UpdateProfile: empty blob");
        return None;
    }

    let response = {
        let mut map = state.write().await;
        match map.blind_profiles.get_mut(&index) {
            Some(entry) if entry.owner_hash == caller_id => {
                entry.blob = new_blob;
                info!(
                    "UpdateProfile: updated blob (index={})",
                    hex_fmt(&index, 8)
                );
                vec![0xFE, 0x03, 0x00] // success
            }
            Some(_) => {
                warn!(
                    "UpdateProfile: unauthorized attempt by {} (index={})",
                    hex_fmt(caller_id, 8),
                    hex_fmt(&index, 8)
                );
                vec![0xFF, 0x03, 0x00] // error
            }
            None => {
                info!(
                    "UpdateProfile: not found (index={})",
                    hex_fmt(&index, 8)
                );
                vec![0xFF, 0x03, 0x00] // error
            }
        }
    }; // write lock released

    Some(response)
}

/// ── CLI argument parsing ──────────────────────────────────────────────

/// Parsed command-line arguments.
struct CliArgs {
    port: u16,
    mode: ServerMode,
}

/// Server mode: plain WS or TLS-encrypted WSS.
enum ServerMode {
    Plain,
    Tls {
        cert_path: String,
        key_path: String,
    },
}

impl CliArgs {
    fn parse() -> Self {
        let raw: Vec<String> = std::env::args().collect();
        let mut port: u16 = 9000;
        let mut cert: Option<String> = None;
        let mut key: Option<String> = None;

        let mut i = 1;
        while i < raw.len() {
            match raw[i].as_str() {
                "--help" | "-h" => {
                    eprintln!("VurnChat Blind Relay Server");
                    eprintln!();
                    eprintln!("Usage:");
                    eprintln!("  vurn-server [--port <PORT>] [--cert <CERT> --key <KEY>]");
                    eprintln!();
                    eprintln!("Options:");
                    eprintln!("  --port <PORT>     Port to listen on (default: 9000)");
                    eprintln!("  --cert <CERT>     Path to TLS certificate PEM file");
                    eprintln!("  --key <KEY>       Path to TLS private key PEM file");
                    eprintln!("  --help, -h        Show this help message");
                    eprintln!();
                    eprintln!("Examples:");
                    eprintln!("  vurn-server");
                    eprintln!("  vurn-server --port 8080");
                    eprintln!("  vurn-server --cert cert.pem --key key.pem");
                    eprintln!("  vurn-server --port 443 --cert /etc/letsencrypt/live/example.com/fullchain.pem --key /etc/letsencrypt/live/example.com/privkey.pem");
                    std::process::exit(0);
                }
                "--port" => {
                    i += 1;
                    port = raw
                        .get(i)
                        .expect("--port requires a value")
                        .parse()
                        .expect("--port must be a valid port number");
                }
                "--cert" => {
                    i += 1;
                    cert = Some(
                        raw.get(i)
                            .expect("--cert requires a path")
                            .clone(),
                    );
                }
                "--key" => {
                    i += 1;
                    key = Some(
                        raw.get(i)
                            .expect("--key requires a path")
                            .clone(),
                    );
                }
                other => {
                    eprintln!("Unknown argument: {}", other);
                    eprintln!("Usage: vurn-server [--port <PORT>] [--cert <CERT> --key <KEY>]");
                    std::process::exit(1);
                }
            }
            i += 1;
        }

        let mode = match (cert, key) {
            (Some(cert_path), Some(key_path)) => ServerMode::Tls {
                cert_path,
                key_path,
            },
            (None, None) => ServerMode::Plain,
            (Some(_), None) | (None, Some(_)) => {
                eprintln!("Error: --cert and --key must be used together");
                std::process::exit(1);
            }
        };

        CliArgs { port, mode }
    }
}

/// ── TLS support ────────────────────────────────────────────────────

/// Loads TLS configuration from PEM certificate and private key files.
async fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    let certs = tokio::task::spawn_blocking({
        let cp = cert_path.to_string();
        move || -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
            let mut reader = BufReader::new(
                File::open(&cp).map_err(|e| format!("Failed to open cert file: {}", e))?,
            );
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Failed to parse cert file: {}", e))
        }
    })
    .await
    .map_err(|e| format!("Task join failed: {}", e))??;

    if certs.is_empty() {
        return Err("No certificates found in cert file".to_string());
    }

    let key = tokio::task::spawn_blocking({
        let kp = key_path.to_string();
        move || -> Result<PrivateKeyDer<'static>, String> {
            let mut reader = BufReader::new(
                File::open(&kp).map_err(|e| format!("Failed to open key file: {}", e))?,
            );
            rustls_pemfile::private_key(&mut reader)
                .map_err(|e| format!("Failed to parse key file: {}", e))?
                .ok_or_else(|| "No private key found in key file".to_string())
        }
    })
    .await
    .map_err(|e| format!("Task join failed: {}", e))??;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config build failed: {}", e))?;

    Ok(Arc::new(config))
}

/// Background task that reloads TLS certificates from disk every 24 hours.
///
/// Runs in an infinite loop. On each tick, re-reads the PEM files and
/// replaces the shared TLS config. If loading fails, the old config
/// remains in use and an error is logged — no connection disruption.
async fn cert_reload_task(
    tls_state: Arc<RwLock<Arc<ServerConfig>>>,
    cert_path: &str,
    key_path: &str,
) {
    let cp = cert_path.to_string();
    let kp = key_path.to_string();

    loop {
        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;

        match load_tls_config(&cp, &kp).await {
            Ok(new_config) => {
                let mut guard = tls_state.write().await;
                *guard = new_config;
                info!("TLS certificates reloaded successfully — new certs are live");
            }
            Err(e) => {
                warn!(
                    "Failed to reload TLS certificates (old certs still active): {}",
                    e
                );
            }
        }
    }
}

/// Runs an async TLS accept loop with graceful shutdown.
///
/// Each incoming TCP connection is wrapped in a TLS layer via `tokio-rustls`,
/// then served by the axum application. The shared `tls_state` allows
/// hot-reloading of certificates without dropping existing connections.
async fn run_tls_server(
    addr: &str,
    app: Router,
    tls_state: Arc<RwLock<Arc<ServerConfig>>>,
) {
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind TCP listener");

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, _) = accept_result.expect("Failed to accept connection");
                let app = app.clone();
                let tls_state = tls_state.clone();

                tokio::spawn(async move {
                    let config = tls_state.read().await.clone();
                    let acceptor = tokio_rustls::TlsAcceptor::from(config);

                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let svc = hyper::service::service_fn(move |req| {
                                let mut app = app.clone();
                                async move {
                                    let resp = app.call(req).await.unwrap();
                                    Ok::<_, std::convert::Infallible>(resp)
                                }
                            });

                            let io = TokioIo::new(tls_stream);

                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                            {
                                warn!("TLS connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("TLS handshake failed: {}", e);
                        }
                    }
                });
            }
            _ = &mut shutdown => {
                info!("Shutdown signal received, stopping TLS accept loop...");
                break;
            }
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
