//! # P2P Node
//!
//! Core libp2p node for VurnChat's distributed network layer.
//!
//! Sets up the Swarm with:
//! - **Kademlia DHT** — peer discovery, mailbox storage/retrieval
//! - **GossipSub** — topic-based broadcast (future group chats)
//! - **Ping** — keepalive and liveness checks

use std::time::Duration;
use futures::StreamExt;
use kad::store::MemoryStore;
use libp2p::{
    swarm::SwarmEvent,
    Multiaddr, PeerId,
};
use tokio::sync::mpsc;
use tracing::{info, warn, trace};

use libp2p::{kad, gossipsub, identify};

// ── Composed behaviour ──────────────────────────────────────────────

/// All libp2p behaviours combined via the derive macro.
///
/// `to_swarm` attribute tells the derive macro to use our custom
/// `NodeBehaviourEvent` type instead of generating an anonymous enum.
/// The derive macro requires `From<SubBehaviour::ToSwarm>` impls for
/// each field's event type.
#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "NodeBehaviourEvent")]
pub struct NodeBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: libp2p::ping::Behaviour,
}

/// Custom event type for the composed behaviour.
///
/// We define this explicitly to avoid matching on generated associated types.
/// Each variant mirrors one sub-behaviour's ToSwarm event type.
#[derive(Debug)]
pub enum NodeBehaviourEvent {
    Kademlia(kad::Event),
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Ping(libp2p::ping::Event),
}

// ── From impls required by the derive macro ─────────────────────────

impl From<kad::Event> for NodeBehaviourEvent {
    fn from(e: kad::Event) -> Self {
        NodeBehaviourEvent::Kademlia(e)
    }
}

impl From<gossipsub::Event> for NodeBehaviourEvent {
    fn from(e: gossipsub::Event) -> Self {
        NodeBehaviourEvent::Gossipsub(e)
    }
}

impl From<identify::Event> for NodeBehaviourEvent {
    fn from(e: identify::Event) -> Self {
        NodeBehaviourEvent::Identify(e)
    }
}

impl From<libp2p::ping::Event> for NodeBehaviourEvent {
    fn from(e: libp2p::ping::Event) -> Self {
        NodeBehaviourEvent::Ping(e)
    }
}

// ── Events & Commands ──────────────────────────────────────────────

/// Events emitted by the P2P node's event loop.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum NodeEvent {
    /// A message was received (from direct or gossipsub)
    MessageReceived { from: PeerId, data: Vec<u8> },
    /// DHT record retrieved
    MailboxRetrieved { key: Vec<u8>, value: Option<Vec<u8>> },
    /// A new peer was discovered
    PeerDiscovered(PeerId),
    /// Listen address the node is accepting connections on
    ListeningOn(Multiaddr),
    /// An error occurred
    Error(String),
}

/// Commands that can be sent to the P2P node.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum NodeCommand {
    /// Store a value in the DHT at the given key.
    DhtStore { key: Vec<u8>, value: Vec<u8> },
    /// Retrieve a value from the DHT by key.
    DhtGet { key: Vec<u8> },
    /// Dial a specific peer address (bootstrap).
    Dial { addr: Multiaddr },
    /// Subscribe to a GossipSub topic.
    Subscribe { topic: String },
    /// Publish on a GossipSub topic.
    Publish { topic: String, data: Vec<u8> },
    /// Bootstrap the DHT
    Bootstrap,
}

// ── Node struct ─────────────────────────────────────────────────────

pub struct P2PNode {
    pub peer_id: PeerId,
    pub cmd_tx: mpsc::Sender<NodeCommand>,
    #[allow(dead_code)]
    pub handle: tokio::task::JoinHandle<()>,
}

impl P2PNode {
    /// Creates and starts a new P2P node.
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
            loop {
                tokio::select! {
                    event = swarm.select_next_some() => {
                        handle_swarm_event(event, &ev_tx).await;
                    }
                    cmd = cmd_rx.recv() => {
                        let Some(cmd) = cmd else { break; };
                        handle_command(&mut swarm, cmd).await;
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

/// Process a SwarmEvent and dispatch to behaviour-specific handlers.
async fn handle_swarm_event(
    event: SwarmEvent<NodeBehaviourEvent>,
    ev_tx: &mpsc::Sender<NodeEvent>,
) {
    match event {
        SwarmEvent::Behaviour(be) => match be {
            NodeBehaviourEvent::Kademlia(kad_event) => {
                handle_kad_event(kad_event, ev_tx).await;
            }
            NodeBehaviourEvent::Gossipsub(gs_event) => {
                handle_gossipsub_event(gs_event, ev_tx).await;
            }
            NodeBehaviourEvent::Identify(identify_event) => {
                handle_identify_event(identify_event, ev_tx).await;
            }
            NodeBehaviourEvent::Ping(ping_event) => {
                if ping_event.result.is_ok() {
                    trace!("Ping OK: peer={}", ping_event.peer);
                } else {
                    trace!("Ping failed: peer={}", ping_event.peer);
                }
            }
        },
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("P2P listening on {address}");
            let _ = ev_tx.send(NodeEvent::ListeningOn(address)).await;
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            let _ = ev_tx.send(NodeEvent::PeerDiscovered(peer_id)).await;
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            info!("P2P connection closed: {peer_id}");
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            trace!("Incoming connection error: {error}");
        }
        other => {
            trace!("P2P event: {other:?}");
        }
    }
}

/// Handle Kademlia events (DHT operations).
async fn handle_kad_event(
    event: kad::Event,
    ev_tx: &mpsc::Sender<NodeEvent>,
) {
    info!("KAD_EVENT: {event:?}");
    match event {
        kad::Event::OutboundQueryProgressed { result, id, stats, .. } => {
            use kad::QueryResult;
            info!("KAD QueryResult [{id:?} stats={stats:?}]: {result:?}");
            match result {
                QueryResult::GetRecord(Ok(ok)) => match ok {
                    kad::GetRecordOk::FoundRecord(peer_record) => {
                        let key = peer_record.record.key.to_vec();
                        let value = peer_record.record.value.clone();
                        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
                        info!("DHT get_record FOUND: key={} value_len={}", key_hex, value.len());
                        let _ = ev_tx
                            .send(NodeEvent::MailboxRetrieved {
                                key,
                                value: Some(value),
                            })
                            .await;
                    }
                    kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {
                        info!("DHT get_record finished (no more records)");
                    }
                },
                QueryResult::GetRecord(Err(e)) => {
                    warn!("DHT get_record failed: {e:?}");
                }
                QueryResult::PutRecord(Ok(ok)) => {
                    info!("DHT put_record succeeded: {ok:?}");
                }
                QueryResult::PutRecord(Err(e)) => {
                    warn!("DHT put_record failed: {e:?}");
                }
                QueryResult::Bootstrap(Ok(ok)) => {
                    info!("DHT bootstrap completed: {ok:?}");
                }
                QueryResult::Bootstrap(Err(e)) => {
                    warn!("DHT bootstrap failed: {e:?}");
                }
                QueryResult::StartProviding(Ok(_)) => {}
                QueryResult::StartProviding(Err(e)) => {
                    warn!("DHT start_providing failed: {e:?}");
                }
                _ => {
                    info!("KAD unhandled query result: {result:?}");
                }
            }
        }
        kad::Event::RoutingUpdated { peer, .. } => {
            info!("KAD routing updated: {peer}");
            let _ = ev_tx.send(NodeEvent::PeerDiscovered(peer)).await;
        }
        // Inbound queries are handled automatically by Kademlia
        _ => {}
    }
}

/// Handle Identify events (peer info exchange).
/// Identify automatically populates Kademlia routing tables.
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
        identify::Event::Sent { peer_id, .. } => {
            trace!("Identify sent to {peer_id}");
        }
        identify::Event::Pushed { peer_id, .. } => {
            trace!("Identify pushed to {peer_id}");
        }
        identify::Event::Error { peer_id, error, .. } => {
            warn!("Identify error with {peer_id}: {error}");
        }
    }
}

/// Handle GossipSub events (pub/sub messages).
async fn handle_gossipsub_event(
    event: gossipsub::Event,
    ev_tx: &mpsc::Sender<NodeEvent>,
) {
    if let gossipsub::Event::Message {
        propagation_source,
        message,
        ..
    } = event
    {
        let _ = ev_tx
            .send(NodeEvent::MessageReceived {
                from: propagation_source,
                data: message.data,
            })
            .await;
    }
}

// ── Command handling ────────────────────────────────────────────────

/// Process a NodeCommand by calling the appropriate method on the swarm.
async fn handle_command(swarm: &mut libp2p::Swarm<NodeBehaviour>, cmd: NodeCommand) {
    let NodeBehaviour {
        ref mut kademlia,
        ref mut gossipsub,
        identify: _,
        ping: _,
    } = swarm.behaviour_mut();

    match cmd {
        NodeCommand::Dial { addr } => {
            let _ = swarm.dial(addr);
        }
        NodeCommand::DhtStore { key, value } => {
            use kad::Record;
            let record = Record {
                key: kad::RecordKey::new(&key),
                value,
                publisher: None,
                expires: None,
            };
            // Use Quorum::One for fast writes — Kademlia will replicate
            // to the K closest nodes during background maintenance.
            let _ = kademlia.put_record(record, kad::Quorum::One);
        }
        NodeCommand::DhtGet { key } => {
            kademlia.get_record(kad::RecordKey::new(&key));
        }
        NodeCommand::Subscribe { topic } => {
            let _ = gossipsub.subscribe(&gossipsub::IdentTopic::new(topic));
        }
        NodeCommand::Publish { topic, data } => {
            let _ = gossipsub.publish(gossipsub::TopicHash::from_raw(topic), data);
        }
        NodeCommand::Bootstrap => {
            let _ = kademlia.bootstrap();
        }
    }
}
