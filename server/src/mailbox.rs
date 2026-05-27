//! # DHT-backed Mailbox with Local Sled Backup
//!
//! Stores offline messages in the Kademlia DHT and backs them up locally
//! in a Sled embedded database for durability.

use crate::p2p::dht;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Prefix for Sled-tree namespacing.
/// Made `pub` so that P2P node (get_sled_max_seq) uses the same constant.
pub const SLED_MAILBOX_TREE: &str = "mailbox";

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
