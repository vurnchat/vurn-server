//! # DHT-backed Mailbox
//!
//! Stores offline messages in the Kademlia DHT instead of local memory.
//!
//! When a user comes online, they query the DHT at `vmb_` + their hash
//! to retrieve any messages stored while they were offline.
//! The DHT automatically replicates mailbox data across nodes.

use crate::p2p::{P2PNode, NodeCommand, mailbox_key, encode_mailbox_message};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

/// Shared mailbox state: pending DHT lookups by key.
#[derive(Default)]
struct MailboxState {
    pending_retrievals: Vec<Vec<u8>>,
}

/// Bridges WebSocket mailbox events to DHT operations.
pub struct MailboxManager {
    state: Arc<RwLock<MailboxState>>,
    #[allow(dead_code)]
    cmd_tx: mpsc::Sender<NodeCommand>,
}

impl MailboxManager {
    pub fn new(p2p_node: &P2PNode) -> Self {
        Self {
            state: Arc::default(),
            cmd_tx: p2p_node.cmd_tx.clone(),
        }
    }

    /// Store a message for an offline recipient via DHT.
    #[allow(dead_code)]
    pub async fn store_message(
        &self,
        recipient_hash: &[u8],
        sender_hash: &[u8],
        encrypted_payload: &[u8],
    ) {
        let msg = encode_mailbox_message(sender_hash, encrypted_payload);
        let key = mailbox_key(recipient_hash);

        let cmd = NodeCommand::DhtStore {
            key: key.to_vec(),
            value: msg,
        };

        if let Err(e) = self.cmd_tx.send(cmd).await {
            warn!("Failed to send DHT store command: {e}");
        } else {
            info!(
                "Mailbox: stored message in DHT for recipient {}",
                hex_fmt(recipient_hash, 8)
            );
        }
    }

    /// Retrieve messages from the DHT for a user who just connected.
    #[allow(dead_code)]
    pub async fn retrieve_messages(&self, user_hash: &[u8]) {
        let key = mailbox_key(user_hash);

        {
            let mut state = self.state.write().await;
            if state.pending_retrievals.iter().any(|k| k == &key.to_vec()) {
                info!("Mailbox: retrieval already in flight for {}", hex_fmt(user_hash, 8));
                return;
            }
            state.pending_retrievals.push(key.to_vec());
        }

        let cmd = NodeCommand::DhtGet { key: key.to_vec() };

        if let Err(e) = self.cmd_tx.send(cmd).await {
            warn!("Failed to send DHT get command: {e}");
        } else {
            info!("Mailbox: requesting DHT messages for {}", hex_fmt(user_hash, 8));
        }
    }

    /// Handles a DHT retrieval result from the P2P event loop.
    pub async fn handle_retrieval_result(
        &self,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Option<Vec<Vec<u8>>> {
        {
            let mut state = self.state.write().await;
            state.pending_retrievals.retain(|k| k != &key);
        }

        match value {
            Some(data) => {
                info!(
                    "Mailbox: retrieved {} bytes from DHT for key {}",
                    data.len(),
                    hex_fmt(&key, 8)
                );
                Some(vec![data])
            }
            None => {
                info!("Mailbox: no messages found in DHT for key {}", hex_fmt(&key, 8));
                None
            }
        }
    }
}

/// Format bytes as hex for logging (truncated).
fn hex_fmt(bytes: &[u8], max: usize) -> String {
    let len = bytes.len().min(max);
    let s: String = bytes[..len].iter().map(|b| format!("{b:02x}")).collect();
    if bytes.len() > max {
        format!("{s}…({}b)", bytes.len())
    } else {
        format!("{s}({}b)", bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mailbox_key_format() {
        let hash = b"12345678901234567890123456789012";
        let key = mailbox_key(hash);
        let kb = key.to_vec();
        assert!(kb.starts_with(b"vmb_"));
        assert_eq!(&kb[4..], hash);
    }
}
