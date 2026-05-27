//! # DHT Operations
//!
//! Helpers for deriving DHT keys from user identities and managing
//! mailbox storage in the Kademlia DHT.
//!
//! ## Key Format
//!
//! Sequential keys avoid the Kademlia single-value-per-key limitation:
//!
//! - `vmb_<hash>_index` — stores current message count (8-byte LE u64)
//! - `vmb_<hash>_<seq>` — stores individual message (seq = 1..=index)
//!
//! ## Store Flow
//! 1. DhtGet for `vmb_<hash>_index` → get current index (or 0)
//! 2. Increment → store message at `vmb_<hash>_<new_index>`
//! 3. Store updated index at `vmb_<hash>_index`
//!
//! ## Retrieve Flow
//! 1. DhtGet for `vmb_<hash>_index` → get current index
//! 2. For seq = 1..=index, DhtGet for `vmb_<hash>_<seq>`
//! 3. Emit MailboxRetrieved with collected messages

use libp2p::kad::RecordKey;

const MAILBOX_KEY_PREFIX: &[u8] = b"vmb_";

/// DHT key for a user's mailbox index — stores current message count.
/// Format: `vmb_<hash>_index`
pub fn mailbox_index_key(user_hash: &[u8]) -> RecordKey {
    let mut key = Vec::with_capacity(4 + user_hash.len() + 6);
    key.extend_from_slice(MAILBOX_KEY_PREFIX);
    key.extend_from_slice(user_hash);
    key.extend_from_slice(b"_index");
    RecordKey::new(&key)
}

/// DHT key for a specific message in a user's mailbox.
/// Format: `vmb_<hash>_<seq>` where seq is 0-padded 20-digit decimal.
pub fn mailbox_seq_key(user_hash: &[u8], seq: u64) -> RecordKey {
    let seq_str = format!("_{seq:020}");
    let mut key = Vec::with_capacity(4 + user_hash.len() + seq_str.len());
    key.extend_from_slice(MAILBOX_KEY_PREFIX);
    key.extend_from_slice(user_hash);
    key.extend_from_slice(seq_str.as_bytes());
    RecordKey::new(&key)
}

/// Extract the user hash from a mailbox key.
/// Returns `None` if the key doesn't start with `vmb_`.
pub fn parse_user_hash_from_key(key: &[u8]) -> Option<&[u8]> {
    if !key.starts_with(b"vmb_") {
        return None;
    }
    // Key format: vmb_<hash>_index or vmb_<hash>_<seq>
    // Find the second underscore after vmb_
    let after_prefix = &key[4..];
    let hash_end = after_prefix.iter().position(|&b| b == b'_')?;
    Some(&after_prefix[..hash_end])
}

/// Encodes a mailbox message for DHT storage.
pub fn encode_mailbox_message(sender_hash: &[u8], encrypted_payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + sender_hash.len() + encrypted_payload.len());
    data.extend_from_slice(&(sender_hash.len() as u16).to_le_bytes());
    data.extend_from_slice(sender_hash);
    data.extend_from_slice(encrypted_payload);
    data
}

/// Decodes a mailbox message from DHT storage.
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

/// Encode a mailbox index (u64) as 8-byte LE bytes.
pub fn encode_index(index: u64) -> Vec<u8> {
    index.to_le_bytes().to_vec()
}

/// Decode a mailbox index from 8-byte LE bytes.
pub fn decode_index(bytes: &[u8]) -> u64 {
    if bytes.len() < 8 {
        return 0;
    }
    let arr: [u8; 8] = bytes[..8].try_into().unwrap_or([0; 8]);
    u64::from_le_bytes(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mailbox_index_key_format() {
        let user_hash = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let key = mailbox_index_key(user_hash);
        let key_bytes = key.to_vec();
        assert!(key_bytes.starts_with(b"vmb_"));
        assert!(key_bytes.ends_with(b"_index"));
        assert_eq!(&key_bytes[4..4 + 32], user_hash);
    }

    #[test]
    fn test_mailbox_seq_key_format() {
        let user_hash = b"0123456789abcdef0123456789abcdef";
        let key = mailbox_seq_key(user_hash, 42);
        let key_bytes = key.to_vec();
        assert!(key_bytes.starts_with(b"vmb_"));
        assert!(key_bytes.ends_with(b"00000000000000000042".as_ref()));
    }

    #[test]
    fn test_parse_user_hash_from_key() {
        let hash = b"abcdef0123456789abcdef0123456789";
        let index_key = mailbox_index_key(hash);
        assert_eq!(parse_user_hash_from_key(index_key.to_vec().as_ref()), Some(hash.as_ref()));

        let seq_key = mailbox_seq_key(hash, 7);
        assert_eq!(parse_user_hash_from_key(seq_key.to_vec().as_ref()), Some(hash.as_ref()));

        assert!(parse_user_hash_from_key(b"no_prefix").is_none());
        assert!(parse_user_hash_from_key(b"vmb_only").is_none());
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
    fn test_index_encode_decode() {
        for idx in [0, 1, 42, 999, u64::MAX] {
            let bytes = encode_index(idx);
            assert_eq!(bytes.len(), 8);
            assert_eq!(decode_index(&bytes), idx);
        }
        // Empty slice → 0
        assert_eq!(decode_index(b""), 0);
        // Short slice → tolerate
        assert_eq!(decode_index(&[1, 2, 3]), 0);
    }
}
