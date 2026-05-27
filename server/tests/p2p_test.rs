//! Integration tests for P2P DHT store + retrieve.
//!
//! Runs two libp2p nodes in the same process, connects them,
//! stores a record via one node, and retrieves it via the other.

use std::time::Duration;
use tokio::sync::mpsc;
use tracing::info;
use vurn_server::p2p::{P2PNode, NodeCommand, NodeEvent};

/// Helper: wait for an event matching a predicate, with timeout.
async fn wait_for_event<F>(
    rx: &mut mpsc::Receiver<NodeEvent>,
    timeout: Duration,
    mut pred: F,
) -> Option<NodeEvent>
where
    F: FnMut(&NodeEvent) -> bool,
{
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(event) if pred(&event) => return Some(event),
                    Some(event) => {
                        info!("wait_for_event: skipping {:?}", event);
                        continue;
                    },
                    None => return None,
                }
            }
            _ = tokio::time::sleep(timeout) => return None,
        }
    }
}

/// Start tracing with RUST_LOG
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into())
        )
        .try_init();
}

#[tokio::test]
async fn test_p2p_dht_same_node() {
    init_tracing();

    let (ev_tx, mut ev_rx) = mpsc::channel::<NodeEvent>(256);

    let node = P2PNode::new("/ip4/127.0.0.1/tcp/0", ev_tx)
        .await
        .expect("Failed to create P2P node");

    info!("Node created, peer_id={}", node.peer_id);

    // Wait for listen address
    let _listen = wait_for_event(&mut ev_rx, Duration::from_secs(5), |e| {
        matches!(e, NodeEvent::ListeningOn(_))
    })
    .await
    .expect("Node never got a listen address");

    info!("Node is listening");

    // Bootstrap DHT (even though we're alone)
    node.cmd_tx.send(NodeCommand::Bootstrap).await.ok();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Store a record
    let test_key = b"vurn_test_local_key";
    let test_value = b"Hello from local DHT store+retrieve!";
    info!("Storing record locally...");
    node.cmd_tx
        .send(NodeCommand::DhtStore {
            key: test_key.to_vec(),
            value: test_value.to_vec(),
        })
        .await
        .ok();

    // Wait a bit for put_record to complete
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Retrieve the record
    info!("Retrieving record locally...");
    node.cmd_tx
        .send(NodeCommand::DhtGet {
            key: test_key.to_vec(),
        })
        .await
        .ok();

    let retrieved = wait_for_event(&mut ev_rx, Duration::from_secs(10), |e| {
        matches!(e, NodeEvent::MailboxRetrieved { .. })
    })
    .await;

    match retrieved {
        Some(NodeEvent::MailboxRetrieved { user_hash, messages }) => {
            let hash_hex: String = user_hash.iter().map(|b| format!("{b:02x}")).collect();
            if messages.is_empty() {
                panic!("❌ DHT retrieve returned 0 messages for user_hash={hash_hex}")
            }
            let data = &messages[0];
            let text = String::from_utf8_lossy(data);
            info!("✅ Local DHT retrieve SUCCESS! user_hash={hash_hex}, value={text}");
            assert_eq!(
                data.as_slice(),
                test_value,
                "Retrieved value should match stored value"
            );
            println!("PASS: Same-node DHT store+retrieve works correctly!");
        }
        Some(other) => {
            panic!("❌ Expected MailboxRetrieved, got: {other:?}")
        }
        None => {
            panic!("❌ Timed out waiting for MailboxRetrieved event (DHT retrieve failed)")
        }
    }
}

#[tokio::test]
async fn test_p2p_dht_cross_node() {
    init_tracing();

    // ── 1. Create two P2P nodes ──

    let (ev_tx_a, mut ev_rx_a) = mpsc::channel::<NodeEvent>(256);
    let (ev_tx_b, mut ev_rx_b) = mpsc::channel::<NodeEvent>(256);

    let node_a = P2PNode::new("/ip4/127.0.0.1/tcp/0", ev_tx_a)
        .await
        .expect("Failed to create Node A");

    let node_b = P2PNode::new("/ip4/127.0.0.1/tcp/0", ev_tx_b)
        .await
        .expect("Failed to create Node B");

    info!("Node A peer_id={}", node_a.peer_id);
    info!("Node B peer_id={}", node_b.peer_id);

    // ── 2. Wait for both nodes to get their listen addresses ──

    let listen_a = wait_for_event(&mut ev_rx_a, Duration::from_secs(5), |e| {
        matches!(e, NodeEvent::ListeningOn(_))
    })
    .await
    .expect("Node A never got a listen address");

    let listen_addr_a = match listen_a {
        NodeEvent::ListeningOn(addr) => addr,
        _ => unreachable!(),
    };
    info!("Node A listening on {listen_addr_a}");

    let _listen_b = wait_for_event(&mut ev_rx_b, Duration::from_secs(5), |e| {
        matches!(e, NodeEvent::ListeningOn(_))
    })
    .await
    .expect("Node B never got a listen address");

    info!("Both nodes are listening");

    // ── 3. Connect Node B → Node A by dialing ──

    info!("Dialing Node A at {listen_addr_a}");
    node_b
        .cmd_tx
        .send(NodeCommand::Dial {
            addr: listen_addr_a.clone(),
        })
        .await
        .ok();

    // Wait for DHT routing table to be populated
    // ConnectionEstablished -> PeerDiscovered
    // Then RoutingUpdated -> also PeerDiscovered
    tokio::time::sleep(Duration::from_secs(3)).await;

    // ── 4. Bootstrap both nodes' DHT ──

    info!("Bootstrapping both nodes...");
    node_a.cmd_tx.send(NodeCommand::Bootstrap).await.ok();
    node_b.cmd_tx.send(NodeCommand::Bootstrap).await.ok();

    // Wait for DHT bootstrap to complete
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ── 5. Store a record on Node A ──

    let test_key = b"vurn_test_cross_key_1234567";
    let test_value = b"Hello from cross-node P2P DHT!";

    info!("Storing record on Node A...");
    node_a
        .cmd_tx
        .send(NodeCommand::DhtStore {
            key: test_key.to_vec(),
            value: test_value.to_vec(),
        })
        .await
        .ok();

    // Wait for the store to propagate
    tokio::time::sleep(Duration::from_secs(3)).await;

    // ── 6. Retrieve the record from Node B ──

    info!("Retrieving record from Node B...");
    node_b
        .cmd_tx
        .send(NodeCommand::DhtGet {
            key: test_key.to_vec(),
        })
        .await
        .ok();

    let retrieved = wait_for_event(&mut ev_rx_b, Duration::from_secs(15), |e| {
        matches!(e, NodeEvent::MailboxRetrieved { .. })
    })
    .await;

    match retrieved {
        Some(NodeEvent::MailboxRetrieved { user_hash, messages }) => {
            let hash_hex: String = user_hash.iter().map(|b| format!("{b:02x}")).collect();
            if messages.is_empty() {
                panic!("❌ Cross-node DHT retrieve returned 0 messages for user_hash={hash_hex}")
            }
            let data = &messages[0];
            let text = String::from_utf8_lossy(data);
            info!("✅ Cross-node DHT retrieve SUCCESS! user_hash={hash_hex}, value={text}");
            assert_eq!(
                data.as_slice(),
                test_value,
                "Retrieved value should match stored value"
            );
            println!("PASS: Cross-node DHT store+retrieve works correctly!");
        }
        Some(other) => {
            panic!("❌ Expected MailboxRetrieved, got: {other:?}")
        }
        None => {
            panic!("❌ Timed out waiting for MailboxRetrieved event (DHT retrieve failed)")
        }
    }
}
