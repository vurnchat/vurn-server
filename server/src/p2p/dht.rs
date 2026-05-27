//! # DHT Operations
//!
//! Helpers for deriving DHT keys from user identities and managing
//! mailbox storage in the Kademlia DHT.
//!
//! ## Key Derivation
//!
//! VurnChat uses the user's public-key hash (SHA-256, 32 bytes) directly as
//! the DHT record key for their mailbox. This means:
//!
//! - The node responsible for a user's mailbox is the Kademlia node whose
//!   PeerId is XOR-closest to the user's hash.
//! - Users can be found by their hash without any server-side registration.
//! - The DHT automatically replicates the record to the K closest nodes,
//!   providing fault tolerance when nodes go offline.
//!
//! ## Constants
//!
//! - **REPLICATION_FACTOR** (`K=3`): Each mailbox record is stored on the
//!   3 nodes whose PeerIds are XOR-closest to the record key.
//! - **MAILBOX_TTL**: Records expire after 24 hours and are automatically
//!   purged by Kademlia's provider/record expiry.

use libp2p::kad::RecordKey;

/// Number of closest nodes to replicate a mailbox record on.
pub const REPLICATION_FACTOR: usize = 3;

/// Prefix for mailbox DHT keys — distinguishes mailbox records from
/// other potential DHT data.
const MAILBOX_KEY_PREFIX: &[u8] = b"vmb_";

/// Derives a DHT record key for a user's mailbox from their public key hash.
///
/// The format is: `vmb_` (4 bytes) + user_hash (32 bytes) = 36 bytes.
///
/// The prefix ensures mailbox keys don't collide with other DHT data and
/// allows future key namespacing.
pub fn mailbox_key(user_hash: &[u8]) -> RecordKey {
    let mut key = Vec::with_capacity(4 + user_hash.len());
    key.extend_from_slice(MAILBOX_KEY_PREFIX);
    key.extend_from_slice(user_hash);
    RecordKey::new(&key)
}

/// Encodes a mailbox message for DHT storage.
///
/// Format:
/// ```text
/// [2 bytes: sender_id_len (u16 LE)]
/// [N bytes: sender_id (user hash)]
/// [M bytes: encrypted payload (vurn-core wire format)]
/// ```
///
/// This is identical to the existing mailbox forward frame format,
/// so existing clients can parse it without changes.
pub fn encode_mailbox_message(sender_hash: &[u8], encrypted_payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + sender_hash.len() + encrypted_payload.len());
    data.extend_from_slice(&(sender_hash.len() as u16).to_le_bytes());
    data.extend_from_slice(sender_hash);
    data.extend_from_slice(encrypted_payload);
    data
}

/// Decodes a mailbox message from DHT storage.
///
/// Returns `(sender_hash, encrypted_payload)` or an error.
#[allow(dead_code)]
pub fn decode_mailbox_message(data: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    if data.len() < 2 {
        return Err("Mailbox message too short: missing sender_id_len");
    }
    let id_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + id_len {
        return Err("Mailbox message truncated: missing sender_id");
    }
    let sender_hash = &data[2..2 + id_len];
    let payload = &data[2 + id_len..];
    if payload.is_empty() {
        return Err("Mailbox message has empty payload");
    }
    Ok((sender_hash, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mailbox_key_derivation() {
        let user_hash = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let key = mailbox_key(user_hash);
        let key_bytes = key.to_vec();
        assert_eq!(key_bytes.len(), 4 + 32);
        assert_eq!(&key_bytes[..4], b"vmb_");
        assert_eq!(&key_bytes[4..], user_hash);
    }

    #[test]
    fn test_mailbox_message_roundtrip() {
        let sender = b"alice_hash_32_bytes_!!";
        let payload = b"encrypted_data_here";
        let encoded = encode_mailbox_message(sender, payload);
        let (decoded_sender, decoded_payload) = decode_mailbox_message(&encoded).unwrap();
        assert_eq!(decoded_sender, sender);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_mailbox_message_too_short() {
        assert!(decode_mailbox_message(b"").is_err());
        assert!(decode_mailbox_message(b"\x01\x00").is_err());
    }


}
