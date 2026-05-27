//! # DHT-backed Mailbox with Local Sled Backup
//!
//! Stores offline messages in the Kademlia DHT and backs them up locally
//! in a Sled embedded database for durability.
//!
//! ## Flow
//! 1. Message arrives for offline user
//! 2. `MailboxManager::store_message()` writes to Sled, then sends `MailboxStore` command
//! 3. On user reconnect: `MailboxRetrieve` triggers DHT lookup
//! 4. Retrieved messages are persisted to Sled via `backup_retrieved()`
//! 5. If DHT lookup fails, Sled provides fallback

use crate::p2p::{NodeCommand, dht};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

/// Prefix for Sled-tree namespacing.
/// Made `pub` so that P2P node (get_sled_max_seq) uses the same constant.
pub const SLED_MAILBOX_TREE: &str = "mailbox";

/// Shared mailbox manager with Sled backup.
pub struct MailboxManager {
    db: Arc<sled::Db>,
    cmd_tx: mpsc::Sender<NodeCommand>,
    /// Tracks keys with in-flight retrievals to avoid duplicates
    pending_retrievals: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl MailboxManager {
    /// Create a new MailboxManager with Sled storage at `db_path`.
    ///
    /// The database is opened at the given path; it will be created if it
    /// doesn't exist. The mailbox manager will use the P2P command channel
    /// for DHT operations.
    pub fn new(db_path: &str, p2p_cmd_tx: mpsc::Sender<NodeCommand>) -> Self {
        let db = sled::open(db_path).unwrap_or_else(|e| {
            warn!("Failed to open Sled DB at {db_path}: {e}, using in-memory fallback");
            sled::Config::new().temporary(true).open().expect("In-memory sled")
        });
        info!("MailboxManager: Sled DB opened at {db_path}");
        Self::with_db(Arc::new(db), p2p_cmd_tx)
    }

    /// Create a MailboxManager with an already-opened Sled DB.
    /// Used when the DB is shared with P2PNode (see P1.3 sled seeding).
    pub fn with_db(db: Arc<sled::Db>, p2p_cmd_tx: mpsc::Sender<NodeCommand>) -> Self {
        Self {
            db,
            cmd_tx: p2p_cmd_tx,
            pending_retrievals: Arc::default(),
        }
    }

    /// Store a message: write to Sled + send to DHT.
    pub async fn store_message(
        &self,
        recipient_hash: &[u8],
        sender_hash: &[u8],
        encrypted_payload: &[u8],
    ) {
        // 1. Write to local Sled backup (ignore errors — DHT is primary)
        if let Err(e) = self.write_sled_mailbox(recipient_hash, sender_hash, encrypted_payload) {
            warn!("Sled mailbox backup write failed: {e}");
        }

        // 2. Send sequential MailboxStore command to DHT via P2P node
        let cmd = NodeCommand::MailboxStore {
            recipient_hash: recipient_hash.to_vec(),
            sender_hash: sender_hash.to_vec(),
            payload: encrypted_payload.to_vec(),
        };

        if let Err(e) = self.cmd_tx.send(cmd).await {
            warn!("Failed to send MailboxStore command: {e}");
        } else {
            info!(
                "Mailbox: stored message in DHT + Sled for {}",
                hex_fmt(recipient_hash, 8)
            );
        }
    }

    /// Request retrieval of messages from DHT for a user who just connected.
    pub async fn retrieve_messages(&self, user_hash: &[u8]) {
        // Dedup: skip if retrieval is already in flight
        {
            let pending = self.pending_retrievals.read().await;
            if pending.iter().any(|k| k == user_hash) {
                info!("Mailbox: retrieval already in flight for {}", hex_fmt(user_hash, 8));
                return;
            }
        }

        {
            let mut pending = self.pending_retrievals.write().await;
            pending.push(user_hash.to_vec());
        }

        let cmd = NodeCommand::MailboxRetrieve {
            user_hash: user_hash.to_vec(),
        };

        if let Err(e) = self.cmd_tx.send(cmd).await {
            warn!("Failed to send MailboxRetrieve command: {e}");
            let mut pending = self.pending_retrievals.write().await;
            pending.retain(|k| k != user_hash);
        } else {
            info!("Mailbox: requesting DHT messages for {}", hex_fmt(user_hash, 8));
        }
    }

    /// Handle a DHT retrieval result — persist to Sled with seq-based dedup and return payloads.
    ///
    /// Each message is expected to be a serialized `DhtEnvelope`. We deserialize
    /// to extract the seq (for Sled dedup key) and the payload (for WS delivery).
    /// Legacy (non-envelope) messages fall back to timestamp-based keys.
    pub async fn handle_retrieval_result(
        &self,
        user_hash: &[u8],
        messages: &[Vec<u8>],
    ) -> Vec<Vec<u8>> {
        // Clear pending flag
        {
            let mut pending = self.pending_retrievals.write().await;
            pending.retain(|k| k != user_hash);
        }

        let mut payloads = Vec::with_capacity(messages.len());

        for msg in messages {
            match dht::deserialize_envelope(msg) {
                Ok(envelope) => {
                    // Seq-based key = dedup within user_hash
                    if let Err(e) = self.write_sled_raw_seq(user_hash, envelope.seq, msg) {
                        warn!("Sled backup write failed for seq {}: {e}", envelope.seq);
                    }
                    payloads.push(envelope.payload.clone());
                }
                Err(_) => {
                    // Legacy non-envelope format — store with timestamp key
                    if let Err(e) = self.write_sled_raw(user_hash, msg) {
                        warn!("Sled backup write failed for legacy data: {e}");
                    }
                    payloads.push(msg.clone());
                }
            }
        }

        info!(
            "Mailbox: retrieved {} messages from DHT for {}",
            payloads.len(),
            hex_fmt(user_hash, 8)
        );

        payloads
    }

    /// Backup messages that were retrieved via DHT — seq-based dedup.
    pub async fn backup_retrieved(&self, user_hash: &[u8], messages: &[Vec<u8>]) {
        for msg in messages {
            match dht::deserialize_envelope(msg) {
                Ok(envelope) => {
                    if let Err(e) = self.write_sled_raw_seq(user_hash, envelope.seq, msg) {
                        warn!("Sled backup_retrieved failed for seq {}: {e}", envelope.seq);
                    }
                }
                Err(_) => {
                    if let Err(e) = self.write_sled_raw(user_hash, msg) {
                        warn!("Sled backup_retrieved failed for legacy data: {e}");
                    }
                }
            }
        }
    }

    /// Get all stored messages from local Sled backup (fallback if DHT is unavailable).
    #[allow(dead_code)]
    pub async fn get_sled_backup(&self, user_hash: &[u8]) -> Vec<Vec<u8>> {
        let tree = match self.db.open_tree(SLED_MAILBOX_TREE) {
            Ok(t) => t,
            Err(_) => return vec![],
        };

        let prefix = user_hash.to_vec();
        let mut messages = vec![];

        for result in tree.scan_prefix(&prefix) {
            match result {
                Ok((_key, value)) => {
                    messages.push(value.to_vec());
                }
                Err(e) => {
                    warn!("Sled scan error: {e}");
                }
            }
        }

        messages
    }

    // ── Sled helpers ──

    fn write_sled_mailbox(
        &self,
        user_hash: &[u8],
        sender_hash: &[u8],
        payload: &[u8],
    ) -> Result<(), sled::Error> {
        let tree = self.db.open_tree(SLED_MAILBOX_TREE)?;
        let msg = dht::encode_mailbox_message(sender_hash, payload);

        // Use a timestamp-based key to avoid collisions
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let key = [user_hash, &ts.to_le_bytes()].concat();

        tree.insert(key, msg)?;
        tree.flush()?;
        Ok(())
    }

    /// Write raw data with a timestamp-based key (legacy fallback, no dedup).
    fn write_sled_raw(&self, user_hash: &[u8], data: &[u8]) -> Result<(), sled::Error> {
        let tree = self.db.open_tree(SLED_MAILBOX_TREE)?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let key = [user_hash, &ts.to_le_bytes()].concat();
        tree.insert(key, data)?;
        tree.flush()?;
        Ok(())
    }

    /// Write envelope data with a seq-based key — dedup-safe.
    /// Key format: `[user_hash || seq(8-byte BE)]`
    /// Same seq always maps to the same key, so duplicates overwrite cleanly.
    fn write_sled_raw_seq(&self, user_hash: &[u8], seq: u64, data: &[u8]) -> Result<(), sled::Error> {
        let tree = self.db.open_tree(SLED_MAILBOX_TREE)?;
        let key = [user_hash, &seq.to_be_bytes()].concat();
        tree.insert(key, data)?;
        tree.flush()?;
        Ok(())
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
