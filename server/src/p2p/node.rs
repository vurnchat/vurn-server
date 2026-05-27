//! # P2P Node
//!
//! Core libp2p node for VurnChat's distributed network layer.
//!
//! ## Sequential Mailbox Keys
//!
//! - `vmb_<hash>_<seq>` — stores individual message (seq = 1, 2, 3...)
//! - `vmb_<hash>_index` — DHT hint for the current max seq
//!
//! ## MailboxStore (synchronous)
//!
//! Uses an in-memory `HashMap<Vec<u8>, u64>` to track the current index.
//! This avoids the two-phase DHT problem (get index → store).
//!
//! 1. Read index from HashMap (or 0)
//! 2. Increment, store message at seq key in DHT
//! 3. Also write index to DHT as a hint for other nodes
//!
//! ## MailboxRetrieve (DHT state machine)
//!
//! 1. DHT get_record for `vmb_<hash>_index` → get index
//! 2. For seq = 1..=index: DHT get_record for each seq key
//! 3. Collect results, emit MailboxRetrieved when done

use std::{collections::HashMap, time::Duration};
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
    /// Store in sequential mailbox — uses in-memory index, synchronous.
    MailboxStore { recipient_hash: Vec<u8>, sender_hash: Vec<u8>, payload: Vec<u8> },
    /// Retrieve all messages — uses DHT state machine.
    MailboxRetrieve { user_hash: Vec<u8> },
    Dial { addr: Multiaddr },
    Subscribe { topic: String },
    Publish { topic: String, data: Vec<u8> },
    Bootstrap,
}

// ── Internal state machine ──────────────────────────────────────────

enum MailboxState {
    Idle,
    /// Waiting for index DHT response to begin retrieval.
    Retrieving { user_hash: Vec<u8> },
    /// Collecting individual seq messages after index was obtained.
    Collecting {
        user_hash: Vec<u8>,
        messages: Vec<Vec<u8>>,
        remaining: Vec<u64>,
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
            // In-memory index counter: recipient_hash → current max seq
            let mut mailbox_indices: HashMap<Vec<u8>, u64> = HashMap::new();

            loop {
                tokio::select! {
                    event = swarm.select_next_some() => {
                        mailbox_state = handle_swarm_event(event, &ev_tx, &mut swarm, mailbox_state).await;
                    }
                    cmd = cmd_rx.recv() => {
                        let Some(cmd) = cmd else { break; };
                        mailbox_state = handle_command(
                            &mut swarm, cmd, &ev_tx, mailbox_state, &mut mailbox_indices,
                        ).await;
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

// ── Event handling ─────────────────────────────────────────────────

async fn handle_swarm_event(
    event: SwarmEvent<NodeBehaviourEvent>,
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    mailbox_state: MailboxState,
) -> MailboxState {
    match event {
        SwarmEvent::Behaviour(be) => match be {
            NodeBehaviourEvent::Kademlia(kad_event) => {
                handle_kad_event(kad_event, ev_tx, swarm, mailbox_state).await
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

async fn handle_kad_event(
    event: kad::Event,
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    mut state: MailboxState,
) -> MailboxState {
    match event {
        kad::Event::OutboundQueryProgressed { result, .. } => {
            use kad::QueryResult;
            match result {
                QueryResult::GetRecord(Ok(ok)) => match ok {
                    kad::GetRecordOk::FoundRecord(peer_record) => {
                        let key = peer_record.record.key.to_vec();
                        let value = Some(peer_record.record.value.clone());
                        handle_get_record_response(key, value, ev_tx, swarm, &mut state).await
                    }
                    kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {
                        // Key not found in DHT.
                        // For Retrieving: treat as index = 0 → emit empty.
                        // For Collecting: treat seq as not found → skip.
                        match &state {
                            MailboxState::Retrieving { user_hash } => {
                                info!("MailboxRetrieve: no index found in DHT for {}",
                                    hex_fmt(user_hash, 8));
                                let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                                    user_hash: user_hash.clone(),
                                    messages: vec![],
                                }).await;
                                state = MailboxState::Idle;
                            }
                            MailboxState::Collecting { user_hash, messages, remaining } => {
                                // The "not found" is for a seq that doesn't exist.
                                // Skip it and continue with the next.
                                let mut remaining = remaining.clone();
                                let mut messages = messages.clone();
                                if !remaining.is_empty() {
                                    remaining.remove(0);
                                }
                                if remaining.is_empty() {
                                    let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                                        user_hash: user_hash.clone(),
                                        messages: messages.clone(),
                                    }).await;
                                    state = MailboxState::Idle;
                                } else {
                                    let next_seq = remaining[0];
                                    let seq_key = dht::mailbox_seq_key(user_hash, next_seq);
                                    swarm.behaviour_mut().kademlia.get_record(seq_key);
                                    state = MailboxState::Collecting {
                                        user_hash: user_hash.clone(),
                                        messages: messages.clone(),
                                        remaining,
                                    };
                                }
                            }
                            MailboxState::Idle => {
                                // Standalone DHT get — not found is normal
                                state = MailboxState::Idle;
                            }
                        }
                        state
                    }
                },
                QueryResult::GetRecord(Err(e)) => {
                    warn!("DHT get_record failed: {e:?}");
                    if !state.is_idle() {
                        state = MailboxState::Idle;
                    }
                    state
                }
                QueryResult::PutRecord(Ok(ok)) => {
                    trace!("DHT put_record succeeded: {ok:?}");
                    state
                }
                QueryResult::PutRecord(Err(e)) => {
                    warn!("DHT put_record failed: {e:?}");
                    state
                }
                QueryResult::Bootstrap(Ok(ok)) => {
                    trace!("DHT bootstrap completed: {ok:?}");
                    state
                }
                QueryResult::Bootstrap(Err(e)) => {
                    warn!("DHT bootstrap failed: {e:?}");
                    state
                }
                _ => state,
            }
        }
        kad::Event::RoutingUpdated { peer, .. } => {
            let _ = ev_tx.send(NodeEvent::PeerDiscovered(peer)).await;
            state
        }
        _ => state,
    }
}

/// Process a GetRecord response in the context of the mailbox state machine.
async fn handle_get_record_response(
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    ev_tx: &mpsc::Sender<NodeEvent>,
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    state: &mut MailboxState,
) -> MailboxState {
    match state {
        // ── Retrieving: got index, start collecting seq messages ──
        MailboxState::Retrieving { user_hash } => {
            let current_index = value.as_deref().map(dht::decode_index).unwrap_or(0);
            if current_index == 0 {
                info!("MailboxRetrieve: index=0 for {}", hex_fmt(user_hash, 8));
                let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                    user_hash: user_hash.clone(),
                    messages: vec![],
                }).await;
                return MailboxState::Idle;
            }

            info!(
                "MailboxRetrieve: index={}, fetching {} msgs for {}",
                current_index, current_index, hex_fmt(user_hash, 8)
            );

            let remaining: Vec<u64> = (1..=current_index).collect();
            let first_seq = remaining[0];
            let seq_key = dht::mailbox_seq_key(user_hash, first_seq);
            swarm.behaviour_mut().kademlia.get_record(seq_key);

            MailboxState::Collecting {
                user_hash: user_hash.clone(),
                messages: vec![],
                remaining,
            }
        }

        // ── Collecting: got a seq message, add to collection ──
        MailboxState::Collecting { user_hash, messages, remaining } => {
            if remaining.is_empty() {
                let msgs = messages.clone();
                let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                    user_hash: user_hash.clone(),
                    messages: msgs,
                }).await;
                return MailboxState::Idle;
            }

            let seq = remaining[0];
            if let Some(data) = value {
                messages.push(data);
                info!("MailboxRetrieve: collected seq {seq} for {}", hex_fmt(user_hash, 8));
            } else {
                info!("MailboxRetrieve: seq {seq} not found in DHT for {}", hex_fmt(user_hash, 8));
            }
            remaining.remove(0);

            if remaining.is_empty() {
                let msgs = messages.clone();
                let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                    user_hash: user_hash.clone(),
                    messages: msgs,
                }).await;
                MailboxState::Idle
            } else {
                let next_seq = remaining[0];
                let seq_key = dht::mailbox_seq_key(user_hash, next_seq);
                swarm.behaviour_mut().kademlia.get_record(seq_key);
                MailboxState::Collecting {
                    user_hash: user_hash.clone(),
                    messages: messages.clone(),
                    remaining: remaining.clone(),
                }
            }
        }

        // ── Idle: standalone DHT get_record result ──
        MailboxState::Idle => {
            let user_hash = dht::parse_user_hash_from_key(&key)
                .map(|h| h.to_vec())
                .unwrap_or_default();
            let msgs = value.map(|v| vec![v]).unwrap_or_default();
            let _ = ev_tx.send(NodeEvent::MailboxRetrieved {
                user_hash,
                messages: msgs,
            }).await;
            MailboxState::Idle
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
    _ev_tx: &mpsc::Sender<NodeEvent>,
    mailbox_state: MailboxState,
    mailbox_indices: &mut HashMap<Vec<u8>, u64>,
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

        // ── MailboxStore: synchronous via in-memory index ──
        NodeCommand::MailboxStore { recipient_hash, sender_hash, payload } => {
            use kad::Record;

            let current_index = mailbox_indices.get(&recipient_hash).copied().unwrap_or(0);
            let new_index = current_index + 1;

            // 1. Store message at vmb_<hash>_<seq>
            let seq_key = dht::mailbox_seq_key(&recipient_hash, new_index);
            let msg = dht::encode_mailbox_message(&sender_hash, &payload);
            let _ = kademlia.put_record(
                Record {
                    key: seq_key,
                    value: msg,
                    publisher: None,
                    expires: None,
                },
                kad::Quorum::One,
            );

            // 2. Update in-memory index
            mailbox_indices.insert(recipient_hash.clone(), new_index);

            // 3. Write index hint to DHT (best-effort, for cross-node retrieval)
            let index_key = dht::mailbox_index_key(&recipient_hash);
            let idx_bytes = dht::encode_index(new_index);
            let _ = kademlia.put_record(
                Record {
                    key: index_key,
                    value: idx_bytes,
                    publisher: None,
                    expires: None,
                },
                kad::Quorum::One,
            );

            info!(
                "MailboxStore: seq {new_index} (in-mem) for {}",
                hex_fmt(&recipient_hash, 8)
            );

            mailbox_state
        }

        // ── MailboxRetrieve: DHT state machine ──
        NodeCommand::MailboxRetrieve { user_hash } => {
            if !mailbox_state.is_idle() {
                warn!("MailboxRetrieve: previous operation still in progress, dropping");
                return mailbox_state;
            }

            info!(
                "MailboxRetrieve: querying DHT index for {}",
                hex_fmt(&user_hash, 8)
            );
            let index_key = dht::mailbox_index_key(&user_hash);
            kademlia.get_record(index_key);

            MailboxState::Retrieving { user_hash }
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
