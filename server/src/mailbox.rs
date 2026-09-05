//! # DHT-backed Mailbox with Local Sled Backup
//!
//! Stores offline messages in the Kademlia DHT and backs them up locally
//! in a Sled embedded database for durability.

use crate::p2p::dht;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Prefix for Sled-tree namespacing.
/// Made `pub` so that P2P node (get_sled_max_seq) uses the same constant.
pub const SLED_MAILBOX_TREE: &str = "mailbox";

/// Sled tree that persists each recipient's set of already-delivered payload
/// hashes across connections and restarts. This is the exactly-once delivery
/// watermark: without it, every reconnect re-delivers the full mailbox history
/// (duplicate storm). It stores opaque content hashes only — no plaintext, no
/// timestamps, no sender/recipient metadata beyond what the relay already knows.
pub const SLED_DELIVERED_TREE: &str = "delivered_hashes";

/// Upper bound on persisted delivered-hash count per recipient.
/// When exceeded, the oldest hashes are trimmed (newest retained).
const MAX_PERSISTED_HASHES: usize = 8192;

/// Shared mailbox manager with Sled backup.
pub struct MailboxManager {
    db: Arc<sled::Db>,
    /// Tracks keys with in-flight retrievals to avoid duplicates
    pending_retrievals: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl MailboxManager {
    /// Create a MailboxManager with an already-opened Sled DB.
    pub fn with_db(db: Arc<sled::Db>) -> Self {
        Self {
            db,
            pending_retrievals: Arc::default(),
        }
    }

    // ── Persisted delivered-hash set (exactly-once watermark) ──────────

    /// Load the persisted set of delivered payload hashes for a recipient.
    pub fn load_delivered_hashes(&self, user_hash: &[u8]) -> Vec<u64> {
        let Ok(tree) = self.db.open_tree(SLED_DELIVERED_TREE) else {
            return vec![];
        };
        match tree.get(user_hash) {
            Ok(Some(raw)) => bincode::deserialize::<Vec<u64>>(&raw).unwrap_or_default(),
            _ => vec![],
        }
    }

    /// Persist the delivered payload hashes for a recipient (newest-kept, bounded).
    pub fn save_delivered_hashes(&self, user_hash: &[u8], hashes: &HashSet<u64>) {
        let mut all: Vec<u64> = hashes.iter().copied().collect();
        if all.len() > MAX_PERSISTED_HASHES {
            // Trim oldest (arbitrary order is fine — only the bound matters for dedup)
            all.sort_unstable();
            all.drain(..all.len() - MAX_PERSISTED_HASHES);
        }
        if let Ok(tree) = self.db.open_tree(SLED_DELIVERED_TREE) {
            if let Ok(bytes) = bincode::serialize(&all) {
                let _ = tree.insert(user_hash, bytes);
                let _ = tree.flush();
            }
        }
    }

    /// Remove the persisted delivered-hash entry for a recipient entirely.
    /// Used when a user wipes their account / re-keys.
    #[allow(dead_code)]
    pub fn clear_delivered_hashes(&self, user_hash: &[u8]) {
        if let Ok(tree) = self.db.open_tree(SLED_DELIVERED_TREE) {
            let _ = tree.remove(user_hash);
            let _ = tree.flush();
        }
    }

    /// Handle a DHT retrieval result — extract payloads from envelopes.
    ///
    /// Each message is expected to be a serialized `DhtEnvelope`. We deserialize
    /// to extract the payload (for WS delivery). Legacy (non-envelope) messages
    /// are passed through as-is.
    ///
    /// Dedup is handled by the caller via `check_and_mark_delivered` in ws.rs.
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
                    if dht::verify_envelope(&envelope, user_hash).is_ok() {
                        payloads.push(envelope.payload.clone());
                    } else {
                        warn!("Mailbox: invalid envelope seq {} for {}",
                            envelope.seq, hex_fmt(user_hash, 8));
                    }
                }
                Err(_) => {
                    // Legacy non-envelope format — deliver raw
                    payloads.push(msg.clone());
                }
            }
        }

        if !payloads.is_empty() {
            info!(
                "Mailbox: retrieved {} messages from DHT for {}",
                payloads.len(),
                hex_fmt(user_hash, 8)
            );
        }

        payloads
    }

    /// Read all stored messages from local Sled backup WITHOUT removing them.
    /// Returns `(sled_key, payload)` pairs so the caller can deliver first and
    /// delete only the records that were actually delivered (delete-on-success).
    pub async fn read_sled_backup(&self, user_hash: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let tree = match self.db.open_tree(SLED_MAILBOX_TREE) {
            Ok(t) => t,
            Err(_) => return vec![],
        };

        let prefix = user_hash.to_vec();
        let mut records = vec![];

        for result in tree.scan_prefix(&prefix) {
            match result {
                Ok((key, value)) => {
                    if let Ok(envelope) = dht::deserialize_envelope(&value) {
                        // Verify envelope integrity; drop corrupt records
                        if dht::verify_envelope(&envelope, user_hash).is_ok() {
                            records.push((key.to_vec(), envelope.payload));
                        } else {
                            warn!("Sled backup: invalid envelope, removing key {:?}", key);
                            let _ = tree.remove(key);
                        }
                    } else {
                        // Legacy format — deliver raw
                        records.push((key.to_vec(), value.to_vec()));
                    }
                }
                Err(e) => {
                    warn!("Sled scan error: {e}");
                }
            }
        }

        if !records.is_empty() {
            info!(
                "Mailbox: {} offline messages in Sled backup for {}",
                records.len(),
                hex_fmt(user_hash, 8)
            );
        }

        records
    }

    /// Remove specific keys from the local Sled mailbox backup.
    /// Call this ONLY after the records were actually delivered to a client
    /// (or are safe to drop) — never before, or messages can be lost.
    pub async fn remove_sled_records(&self, user_hash: &[u8], keys: &[Vec<u8>]) {
        if keys.is_empty() {
            return;
        }
        if let Ok(tree) = self.db.open_tree(SLED_MAILBOX_TREE) {
            for key in keys {
                let _ = tree.remove(key);
            }
            let _ = tree.flush();
        }
        info!(
            "Mailbox: removed {} delivered records from Sled backup for {}",
            keys.len(),
            hex_fmt(user_hash, 8)
        );
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
