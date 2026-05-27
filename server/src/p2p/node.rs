//! # P2P Node — Zero-Trust Mailbox
//!
//! Core libp2p node for VurnChat's distributed network layer.
//!
//! ## Mailbox Store (Zero-Trust)
//!
//! Uses an in-memory `HashMap<Vec<u8>, u64>` to track the current seq index.
//! Each message is stored in a signed `DhtEnvelope` at `vmb_<hash>_<seq>`.
//! No `vmb_<hash>_index` key exists — the index is discovered via speculative
//! sequential probing (`FetchingIndex` state) on restart.
//!
//! ## Mailbox Retrieve
//!
//! Collected `DhtEnvelope`s are verified by Ed25519 signature before emission.
//! Invalid signatures are silently dropped (spam/forgery resistance).

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use ed25519_dalek::SigningKey;
use futures::StreamExt;
use kad::store::MemoryStore;
use libp2p::{
    swarm::SwarmEvent,
    Multiaddr, PeerId,
};
use tokio::sync::mpsc;
use tracing::{info, warn, trace};

use libp2p::{kad, gossipsub, identify};

use crate::p2p::dht;

// ── Composed behaviour ──────────────────────────────────────────────

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "NodeBehaviourEvent")]
pub struct NodeBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: libp2p::ping::Behaviour,
}

#[derive(Debug)]
pub enum NodeBehaviourEvent {
    Kademlia(kad::Event),
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Ping(libp2p::ping::Event),
}

impl From<kad::Event> for NodeBehaviourEvent {
    fn from(e: kad::Event) -> Self { NodeBehaviourEvent::Kademlia(e) }
}
impl From<gossipsub::Event> for NodeBehaviourEvent {
    fn from(e: gossipsub::Event) -> Self { NodeBehaviourEvent::Gossipsub(e) }
}
impl From<identify::Event> for NodeBehaviourEvent {
    fn from(e: identify::Event) -> Self { NodeBehaviourEvent::Identify(e) }
}
impl From<libp2p::ping::Event> for NodeBehaviourEvent {
    fn from(e: libp2p::ping::Event) -> Self { NodeBehaviourEvent::Ping(e) }
}

// ── Events & Commands ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum NodeEvent {
    MessageReceived { from: PeerId, data: Vec<u8> },
    MailboxRetrieved { user_hash: Vec<u8>, messages: Vec<Vec<u8>> },
    PeerDiscovered(PeerId),
    ListeningOn(Multiaddr),
    Error(String),
}

#[derive(Debug, Clone)]
pub enum NodeCommand {
    DhtStore { key: Vec<u8>, value: Vec<u8> },
    DhtGet { key: Vec<u8> },
    /// Store in sequential mailbox — creates signed DhtEnvelope, single put_record.
    MailboxStore { recipient_hash: Vec<u8>, sender_hash: Vec<u8>, payload: Vec<u8> },
    /// Retrieve all messages — uses in-memory index or speculative probing.
    MailboxRetrieve { user_hash: Vec<u8> },
    Dial { addr: Multiaddr },
    Subscribe { topic: String },
    Publish { topic: String, data: Vec<u8> },
    Bootstrap,
}

// ── Pending command (for speculative FetchingIndex) ─────────────────

#[derive(Debug, Clone)]
enum PendingNodeCommand {
    MailboxStore { recipient_hash: Vec<u8>, sender_hash: Vec<u8>, payload: Vec<u8> },
    MailboxRetrieve { user_hash: Vec<u8> },
}

impl PendingNodeCommand {
    fn user_hash(&self) -> &[u8] {
        match self {
            PendingNodeCommand::MailboxStore { recipient_hash, .. } => recipient_hash,
            PendingNodeCommand::MailboxRetrieve { user_hash } => user_hash,
        }
    }
}

// ── Internal state machine ──────────────────────────────────────────

enum MailboxState {
    Idle,
    /// Speculatively probing DHT seq 1, 2, 3... until finding a gap.
    /// Falls back to Idle after 30 seconds if no DHT response arrives.
    FetchingIndex {
        pending_command: PendingNodeCommand,
        /// Next seq to probe (starts at 1, increments on each FoundRecord)
        probe_seq: u64,
        /// Highest consecutively verified seq found
        max_found: u64,
        /// Deadline: if exceeded, transition to Idle to avoid hanging
        deadline: std::time::Instant,
    },
    /// Collecting individual seq messages after index was determined.
    /// Falls back to Idle after 30 seconds, emitting partial results.
    CollectingMessages {
        user_hash: Vec<u8>,
        messages: Vec<Vec<u8>>,
        remaining: Vec<u64>,
        /// Deadline: if exceeded, emit partial results and transition to Idle
        deadline: std::time::Instant,
    },
}

impl MailboxState {
    fn is_idle(&self) -> bool {
        matches!(self, MailboxState::Idle)
    }
}

// ── Node struct ─────────────────────────────────────────────────────

pub struct P2PNode {
    pub peer_id: PeerId,
    pub cmd_tx: mpsc::Sender<NodeCommand>,
    #[allow(dead_code)]
    pub handle: tokio::task::JoinHandle<()>,
}

impl P2PNode {
    pub async fn new(
        listen_addr: &str,
        event_tx: mpsc::Sender<NodeEvent>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        info!("P2P node identity: {peer_id}");

        // Generate a dedicated Ed25519 keypair for DhtEnvelope signing
        let signing_key = generate_signing_key();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_dns()?
            .with_behaviour(|key| {
                let pid = key.public().to_peer_id();

                let kademlia = {
                    let mut k = kad::Behaviour::new(pid, MemoryStore::new(pid));
                    k.set_mode(Some(kad::Mode::Server));
                    k
                };

                let gs_config = gossipsub::ConfigBuilder::default()
                    .max_transmit_size(10 * 1024 * 1024)
                    .heartbeat_interval(Duration::from_secs(1))
                    .build()
                    .expect("GossipSub config");
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gs_config,
                )
                .expect("GossipSub init");

                let identify = identify::Behaviour::new(
                    identify::Config::new(
                        "vurnchat/0.1.0".to_string(),
                        key.public(),
                    ),
                );

                let ping = libp2p::ping::Behaviour::new(
                    libp2p::ping::Config::new()
                        .with_interval(Duration::from_secs(15)),
                );

                NodeBehaviour {
                    kademlia,
                    gossipsub,
                    identify,
                    ping,
                }
            })?
            .build();

        swarm.listen_on(listen_addr.parse()?)?;

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<NodeCommand>(256);

        let handle = tokio::spawn(async move {
            let ev_tx = event_tx;
            let mut mailbox_state = MailboxState::Idle;
            let mut mailbox_indices: HashMap<Vec<u8>, u64> = HashMap::new();

            // Timeout polling: every 5 seconds, check if FetchingIndex or
            // CollectingMessages has expired.
            let mut timeout_tick = tokio::time::interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    _ = timeout_tick.tick() => {
                        mailbox_state = check_state_timeout(mailbox_state, &ev_tx);
                    }
                    event = swarm.select_next_some() => {
                        mailbox_state = handle_swarm_event(
                            event, &ev_tx, &mut swarm, mailbox_state,
                            &mut mailbox_indices, &signing_key,
                        ).await;
                        mailbox_state = check_state_timeout(mailbox_state, &ev_tx);
                    }
                    cmd = cmd_rx.recv() => {
                        let Some(cmd) = cmd else { break; };
                        mailbox_state = handle_command(
                            &mut swarm, cmd, &ev_tx, mailbox_state,
                            &mut mailbox_indices, &signing_key,
                        ).await;
                        mailbox_state = check_state_timeout(mailbox_state, &ev_tx);
                    }
                }
            }
        });

        Ok(Self {
            peer_id,
            cmd_tx,
            handle,
        })
    }
}

/// Generate an Ed25519 signing key using the system's secure RNG.
fn generate_signing_key() -> SigningKey {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

// ── Event handling ─────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_swarm_event(
    event: SwarmEvent<NodeBehaviourEvent>,
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    mailbox_state: MailboxState,
    mailbox_indices: &mut HashMap<Vec<u8>, u64>,
    signing_key: &SigningKey,
) -> MailboxState {
    match event {
        SwarmEvent::Behaviour(be) => match be {
            NodeBehaviourEvent::Kademlia(kad_event) => {
                handle_kad_event(kad_event, ev_tx, swarm, mailbox_state, mailbox_indices, signing_key).await
            }
            NodeBehaviourEvent::Gossipsub(gs_event) => {
                handle_gossipsub_event(gs_event, ev_tx);
                mailbox_state
            }
            NodeBehaviourEvent::Identify(identify_event) => {
                handle_identify_event(identify_event, ev_tx).await;
                mailbox_state
            }
            NodeBehaviourEvent::Ping(ping_event) => {
                if ping_event.result.is_ok() {
                    trace!("Ping OK: peer={}", ping_event.peer);
                } else {
                    trace!("Ping failed: peer={}", ping_event.peer);
                }
                mailbox_state
            }
        },
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("P2P listening on {address}");
            let _ = ev_tx.send(NodeEvent::ListeningOn(address)).await;
            mailbox_state
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            let _ = ev_tx.send(NodeEvent::PeerDiscovered(peer_id)).await;
            mailbox_state
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            info!("P2P connection closed: {peer_id}");
            mailbox_state
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            trace!("Incoming connection error: {error}");
            mailbox_state
        }
        other => {
            trace!("P2P event: {other:?}");
            mailbox_state
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_kad_event(
    event: kad::Event,
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    mut state: MailboxState,
    mailbox_indices: &mut HashMap<Vec<u8>, u64>,
    signing_key: &SigningKey,
) -> MailboxState {
    match event {
        kad::Event::OutboundQueryProgressed { result, .. } => {
            use kad::QueryResult;
            match result {
                QueryResult::GetRecord(Ok(ok)) => match ok {
                    kad::GetRecordOk::FoundRecord(peer_record) => {
                        let key = peer_record.record.key.to_vec();
                        let value = peer_record.record.value.clone();
                        state = handle_found_record(key, Some(value), ev_tx, swarm, state, mailbox_indices, signing_key).await;
                    }
                    kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {
                        // A seq key not found — signals end of mailbox OR gap
                        state = handle_not_found(ev_tx, swarm, state, mailbox_indices, signing_key).await;
                    }
                },
                QueryResult::GetRecord(Err(e)) => {
                    warn!("DHT get_record failed: {e:?}");
                    if !state.is_idle() {
                        state = MailboxState::Idle;
                    }
                }
                QueryResult::PutRecord(Ok(ok)) => {
                    trace!("DHT put_record succeeded: {ok:?}");
                }
                QueryResult::PutRecord(Err(e)) => {
                    warn!("DHT put_record failed: {e:?}");
                }
                QueryResult::Bootstrap(Ok(ok)) => {
                    trace!("DHT bootstrap completed: {ok:?}");
                }
                QueryResult::Bootstrap(Err(e)) => {
                    warn!("DHT bootstrap failed: {e:?}");
                }
                _ => {}
            }
            state
        }
        kad::Event::RoutingUpdated { peer, .. } => {
            let _ = ev_tx.send(NodeEvent::PeerDiscovered(peer)).await;
            state
        }
        _ => state,
    }
}

/// Handle a FoundRecord response — process according to current state.
async fn handle_found_record(
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    state: MailboxState,
    mailbox_indices: &mut HashMap<Vec<u8>, u64>,
    signing_key: &SigningKey,
) -> MailboxState {
    use MailboxState::*;

    match state {
        // ── FetchingIndex: we got a record at probe_seq ──
        FetchingIndex { pending_command, probe_seq, max_found, deadline } => {
            let user_hash = pending_command.user_hash().to_vec();

            // Try to verify the envelope
            let valid = value.as_ref()
                .and_then(|v| dht::deserialize_envelope(v).ok())
                .filter(|env| {
                    // Check seq matches our probe and signature is valid
                    env.seq == probe_seq && dht::verify_envelope(env, &user_hash).is_ok()
                })
                .is_some();

            if valid {
                info!("FetchingIndex: verified seq {probe_seq} for {}",
                    hex_fmt(&user_hash, 8));
                // Advance to next probe
                let next_seq = probe_seq + 1;
                let seq_key = dht::mailbox_seq_key(&user_hash, next_seq);
                swarm.behaviour_mut().kademlia.get_record(seq_key);
                FetchingIndex {
                    pending_command,
                    probe_seq: next_seq,
                    max_found: probe_seq,
                    deadline,
                }
            } else {
                // Gap found — this seq doesn't exist or is invalid
                // Index = max_found (last consecutively verified seq)
                info!("FetchingIndex: gap at seq {probe_seq} for {}, index={max_found}",
                    hex_fmt(&user_hash, 8));
                mailbox_indices.insert(user_hash.clone(), max_found);
                resume_pending_command(&pending_command, max_found, ev_tx, swarm, mailbox_indices, signing_key).await
            }
        }

        // ── CollectingMessages: collect and verify ──
        CollectingMessages { user_hash, messages, remaining, deadline } => {
            collect_message(user_hash, remaining, value, key, ev_tx, swarm, messages, deadline).await
        }

        // ── Idle: standalone DHT get_record result ──
        Idle => {
            let user_hash = dht::parse_user_hash_from_key(&key)
                .map(|h| h.to_vec())
                .unwrap_or_default();
            let msgs = value.map(|v| vec![v]).unwrap_or_default();
            let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                user_hash,
                messages: msgs,
            }).await;
            Idle
        }
    }
}

/// Handle a FinishedWithNoAdditionalRecord (seq not found in DHT).
async fn handle_not_found(
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    state: MailboxState,
    mailbox_indices: &mut HashMap<Vec<u8>, u64>,
    signing_key: &SigningKey,
) -> MailboxState {
    use MailboxState::*;

    match state {
        FetchingIndex { pending_command, probe_seq, max_found, deadline: _ } => {
            let user_hash = pending_command.user_hash().to_vec();
            // DHT says this seq doesn't exist — gap found
            info!("FetchingIndex: seq {probe_seq} not in DHT for {}, index={max_found}",
                hex_fmt(&user_hash, 8));
            mailbox_indices.insert(user_hash.clone(), max_found);
            resume_pending_command(&pending_command, max_found, ev_tx, swarm, mailbox_indices, signing_key).await
        }
        CollectingMessages { user_hash, messages, remaining, deadline } => {
            // Seq doesn't exist — skip it and continue
            collect_message(user_hash, remaining, None, Vec::new(), ev_tx, swarm, messages, deadline).await
        }
        Idle => Idle,
    }
}

/// Resume a pending command with a known index.
///
/// For `MailboxStore`: create signed DhtEnvelope, store at seq = index + 1.
/// For `MailboxRetrieve`: emit empty (index=0) or start collecting seq messages.
async fn resume_pending_command(
    pending: &PendingNodeCommand,
    index: u64,
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    mailbox_indices: &mut HashMap<Vec<u8>, u64>,
    signing_key: &SigningKey,
) -> MailboxState {
    match pending {
        PendingNodeCommand::MailboxStore { recipient_hash, sender_hash, payload } => {
            let new_index = index + 1;
            let seq_key = dht::mailbox_seq_key(recipient_hash, new_index);

            // Build the legacy payload body (sender_hash + encrypted_payload)
            let msg_body = dht::encode_mailbox_message(sender_hash, payload);

            // Create and sign DhtEnvelope
            let mut envelope = dht::DhtEnvelope {
                payload: msg_body,
                seq: new_index,
                sender_pubkey: signing_key.verifying_key().to_bytes().to_vec(),
                signature: vec![],
            };
            dht::sign_envelope(&mut envelope, signing_key, recipient_hash);

            let envelope_bytes = match dht::serialize_envelope(&envelope) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to serialize DhtEnvelope: {e}");
                    return MailboxState::Idle;
                }
            };

            // Single put_record — no index key!
            let _ = swarm.behaviour_mut().kademlia.put_record(
                kad::Record {
                    key: seq_key,
                    value: envelope_bytes,
                    publisher: None,
                    expires: None,
                },
                kad::Quorum::One,
            );
            mailbox_indices.insert(recipient_hash.clone(), new_index);
            info!("MailboxStore (lazy): signed seq {new_index} for {}",
                hex_fmt(recipient_hash, 8));
            MailboxState::Idle
        }
        PendingNodeCommand::MailboxRetrieve { user_hash } => {
            if index == 0 {
                info!("MailboxRetrieve (lazy): index=0 for {}",
                    hex_fmt(user_hash, 8));
                let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                    user_hash: user_hash.clone(),
                    messages: vec![],
                }).await;
                MailboxState::Idle
            } else {
                info!("MailboxRetrieve (lazy): index={index}, fetching {index} msgs for {}",
                    hex_fmt(user_hash, 8));
                let remaining: Vec<u64> = (1..=index).collect();
                let first_seq = remaining[0];
                let seq_key = dht::mailbox_seq_key(user_hash, first_seq);
                swarm.behaviour_mut().kademlia.get_record(seq_key);
                MailboxState::CollectingMessages {
                    user_hash: user_hash.clone(),
                    messages: vec![],
                    remaining,
                    deadline: Instant::now() + Duration::from_secs(30),
                }
            }
        }
    }
}

/// Collect a message from DHT, verify its envelope, and continue or emit.
/// The `deadline` is preserved from the parent `CollectingMessages` state.
async fn collect_message(
    user_hash: Vec<u8>,
    mut remaining: Vec<u64>,
    value: Option<Vec<u8>>,
    _key: Vec<u8>,
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    mut messages: Vec<Vec<u8>>,
    deadline: std::time::Instant,
) -> MailboxState {
    if remaining.is_empty() {
        let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
            user_hash,
            messages,
        }).await;
        return MailboxState::Idle;
    }

    let seq = remaining[0];
    let mut verified = false;

    if let Some(data) = &value {
        if let Ok(envelope) = dht::deserialize_envelope(data) {
            if envelope.seq == seq && dht::verify_envelope(&envelope, &user_hash).is_ok() {
                // Verified — extract payload (legacy format: sender_hash + encrypted_payload)
                if let Ok((_sender, _payload)) = dht::decode_mailbox_message(&envelope.payload) {
                    messages.push(envelope.payload.clone());
                    info!("MailboxRetrieve: collected verified seq {seq} for {}",
                        hex_fmt(&user_hash, 8));
                    verified = true;
                }
            }
        }
    }

    if !verified {
        info!("MailboxRetrieve: seq {seq} invalid or missing for {}",
            hex_fmt(&user_hash, 8));
    }

    remaining.remove(0);

    if remaining.is_empty() {
        let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
            user_hash,
            messages,
        }).await;
        MailboxState::Idle
    } else {
        let next_seq = remaining[0];
        let seq_key = dht::mailbox_seq_key(&user_hash, next_seq);
        swarm.behaviour_mut().kademlia.get_record(seq_key);
        MailboxState::CollectingMessages {
            user_hash,
            messages,
            remaining,
            deadline,
        }
    }
}

// ── Identify ────────────────────────────────────────────────────────

async fn handle_identify_event(
    event: identify::Event,
    ev_tx: &mpsc::Sender<NodeEvent>,
) {
    match event {
        identify::Event::Received { peer_id, info, .. } => {
            info!("Identify received from {peer_id}: agent={}, protocols={:?}",
                info.agent_version, info.protocols);
            let _ = ev_tx.send(NodeEvent::PeerDiscovered(peer_id)).await;
        }
        _ => {}
    }
}

// ── GossipSub ───────────────────────────────────────────────────────

fn handle_gossipsub_event(
    event: gossipsub::Event,
    ev_tx: &mpsc::Sender<NodeEvent>,
) {
    if let gossipsub::Event::Message {
        propagation_source,
        message,
        ..
    } = event
    {
        let _ = ev_tx.send(NodeEvent::MessageReceived {
            from: propagation_source,
            data: message.data,
        });
    }
}

// ── Command handling ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    cmd: NodeCommand,
    ev_tx: &mpsc::Sender<NodeEvent>,
    mailbox_state: MailboxState,
    mailbox_indices: &mut HashMap<Vec<u8>, u64>,
    signing_key: &SigningKey,
) -> MailboxState {
    let NodeBehaviour {
        ref mut kademlia,
        ref mut gossipsub,
        identify: _,
        ping: _,
    } = swarm.behaviour_mut();

    match cmd {
        NodeCommand::Dial { addr } => {
            let _ = swarm.dial(addr);
            mailbox_state
        }

        // ── Raw DHT operations ──
        NodeCommand::DhtStore { key, value } => {
            use kad::Record;
            let record = Record {
                key: kad::RecordKey::new(&key),
                value,
                publisher: None,
                expires: None,
            };
            let _ = kademlia.put_record(record, kad::Quorum::One);
            mailbox_state
        }
        NodeCommand::DhtGet { key } => {
            kademlia.get_record(kad::RecordKey::new(&key));
            mailbox_state
        }

        // ── MailboxStore: fast path (in-memory index) or speculative probing ──
        NodeCommand::MailboxStore { recipient_hash, sender_hash, payload } => {
            if !mailbox_state.is_idle() {
                warn!("MailboxStore: previous operation still in progress, dropping");
                return mailbox_state;
            }

            // Fast path: index is in memory
            if let Some(&current_index) = mailbox_indices.get(&recipient_hash) {
                let new_index = current_index + 1;
                let seq_key = dht::mailbox_seq_key(&recipient_hash, new_index);

                // Create and sign DhtEnvelope
                let msg_body = dht::encode_mailbox_message(&sender_hash, &payload);
                let mut envelope = dht::DhtEnvelope {
                    payload: msg_body,
                    seq: new_index,
                    sender_pubkey: signing_key.verifying_key().to_bytes().to_vec(),
                    signature: vec![],
                };
                dht::sign_envelope(&mut envelope, signing_key, &recipient_hash);

                let envelope_bytes = match dht::serialize_envelope(&envelope) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Failed to serialize DhtEnvelope: {e}");
                        return mailbox_state;
                    }
                };

                // Single put_record — no index key!
                let _ = kademlia.put_record(
                    kad::Record {
                        key: seq_key,
                        value: envelope_bytes,
                        publisher: None,
                        expires: None,
                    },
                    kad::Quorum::One,
                );
                mailbox_indices.insert(recipient_hash.clone(), new_index);
                info!("MailboxStore (fast): signed seq {new_index} for {}",
                    hex_fmt(&recipient_hash, 8));
                return mailbox_state;
            }

            // Lazy seeding: index not in memory, probe sequentially from seq 1
            info!("MailboxStore (lazy): probing seq 1 for {}",
                hex_fmt(&recipient_hash, 8));
            let seq_key = dht::mailbox_seq_key(&recipient_hash, 1);
            kademlia.get_record(seq_key);
            MailboxState::FetchingIndex {
                pending_command: PendingNodeCommand::MailboxStore {
                    recipient_hash,
                    sender_hash,
                    payload,
                },
                probe_seq: 1,
                max_found: 0,
                deadline: Instant::now() + Duration::from_secs(30),
            }
        }

        // ── MailboxRetrieve: fast path (in-memory) or speculative probing ──
        NodeCommand::MailboxRetrieve { user_hash } => {
            if !mailbox_state.is_idle() {
                warn!("MailboxRetrieve: previous operation still in progress, dropping");
                return mailbox_state;
            }

            if let Some(&index) = mailbox_indices.get(&user_hash) {
                if index == 0 {
                    info!("MailboxRetrieve (fast): index=0 for {}",
                        hex_fmt(&user_hash, 8));
                    let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                        user_hash: user_hash.clone(),
                        messages: vec![],
                    }).await;
                    return mailbox_state;
                }
                info!("MailboxRetrieve (fast): index={index}, fetching {index} msgs for {}",
                    hex_fmt(&user_hash, 8));
                let remaining: Vec<u64> = (1..=index).collect();
                let first_seq = remaining[0];
                let seq_key = dht::mailbox_seq_key(&user_hash, first_seq);
                kademlia.get_record(seq_key);
                return MailboxState::CollectingMessages {
                    user_hash,
                    messages: vec![],
                    remaining,
                    deadline: Instant::now() + Duration::from_secs(30),
                };
            }

            // Lazy seeding: probe sequentially from seq 1
            info!("MailboxRetrieve (lazy): probing seq 1 for {}",
                hex_fmt(&user_hash, 8));
            let seq_key = dht::mailbox_seq_key(&user_hash, 1);
            kademlia.get_record(seq_key);
            MailboxState::FetchingIndex {
                pending_command: PendingNodeCommand::MailboxRetrieve { user_hash },
                probe_seq: 1,
                max_found: 0,
                deadline: Instant::now() + Duration::from_secs(30),
            }
        }

        // ── GossipSub ──
        NodeCommand::Subscribe { topic } => {
            let _ = gossipsub.subscribe(&gossipsub::IdentTopic::new(topic));
            mailbox_state
        }
        NodeCommand::Publish { topic, data } => {
            let _ = gossipsub.publish(gossipsub::TopicHash::from_raw(topic), data);
            mailbox_state
        }
        NodeCommand::Bootstrap => {
            let _ = kademlia.bootstrap();
            mailbox_state
        }
    }
}

/// If a state-machine state has exceeded its deadline, fall back to `Idle`.
/// - `FetchingIndex`: just resets (no messages to emit).
/// - `CollectingMessages`: emits whatever messages were collected so far.
///
/// This prevents the event loop from hanging indefinitely on a slow DHT.
fn check_state_timeout(
    state: MailboxState,
    ev_tx: &mpsc::Sender<NodeEvent>,
) -> MailboxState {
    match state {
        MailboxState::FetchingIndex { deadline, .. } if Instant::now() >= deadline => {
            warn!("FetchingIndex timed out (30s), falling back to Idle");
            MailboxState::Idle
        }
        MailboxState::CollectingMessages { user_hash, messages, deadline, .. }
            if Instant::now() >= deadline =>
        {
            warn!(
                "CollectingMessages timed out (30s), emitting {} collected msgs for {}",
                messages.len(),
                hex_fmt(&user_hash, 8),
            );
            let _ = ev_tx.try_send(NodeEvent::MailboxRetrieved {
                user_hash,
                messages,
            });
            MailboxState::Idle
        }
        _ => state,
    }
}

// ── Helper ──────────────────────────────────────────────────────────

fn hex_fmt(bytes: &[u8], max: usize) -> String {
    let len = bytes.len().min(max);
    let s: String = bytes[..len].iter().map(|b| format!("{b:02x}")).collect();
    if bytes.len() > max {
        format!("{s}…({}b)", bytes.len())
    } else {
        format!("{s}({}b)", bytes.len())
    }
}
