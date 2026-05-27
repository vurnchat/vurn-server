//! # DHT Operations — Zero-Trust Mailbox
//!
//! Sequential message keys with cryptographic envelopes for integrity.
//!
//! ## Key Format
//!
//! - `vmb_<hash>_<seq>` — stores a `DhtEnvelope` (payload + Ed25519 signature)
//!   No more `vmb_<hash>_index` key — the index is determined via speculative
//!   sequential probing (see `node.rs` → `FetchingIndex` state).
//!
//! ## DhtEnvelope
//!
//! Every Kademlia record is wrapped in a signed envelope:
//! ```rust
//! DhtEnvelope {
//!     payload,       // Already E2E encrypted (ML-KEM + AES-GCM) — opaque to the P2P layer
//!     seq,           // Ordering number, must match position in DHT key
//!     sender_pubkey, // Sender's Ed25519 public key
//!     signature,     // Ed25519(verify_buffer = payload || seq || recipient_hash)
//! }
//! ```
//!
//! Any node can verify the envelope without decrypting the payload, providing
//! Zero-Trust integrity for the distributed mailbox.

use libp2p::kad::RecordKey;
use serde::{Deserialize, Serialize};

const MAILBOX_KEY_PREFIX: &[u8] = b"vmb_";

/// Cryptographically signed envelope stored in the DHT.
///
/// The `signature` covers `(payload || seq || recipient_hash)` so that:
/// - Payload integrity: tampering is detected
/// - Seq ordering: replay attack with wrong seq is detected
/// - Recipient binding: message intended for a different user fails verification
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DhtEnvelope {
    /// E2E encrypted payload (ML-KEM+AES-GCM) — opaque to P2P layer
    pub payload: Vec<u8>,
    /// Sequence number for the recipient (1-based)
    pub seq: u64,
    /// Ed25519 public key of the sender (32 bytes for verification)
    pub sender_pubkey: Vec<u8>,
    /// Ed25519 signature over `(payload || seq(8-byte LE) || recipient_hash(32-byte))`
    pub signature: Vec<u8>,
}

// ── DHT key helpers ────────────────────────────────────────────────

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
/// Format: `vmb_<hash>_<seq>` — returns the `<hash>` portion.
pub fn parse_user_hash_from_key(key: &[u8]) -> Option<&[u8]> {
    if !key.starts_with(b"vmb_") {
        return None;
    }
    let after_prefix = &key[4..];
    let hash_end = after_prefix.iter().position(|&b| b == b'_')?;
    Some(&after_prefix[..hash_end])
}

/// Extract both user hash AND sequence number from a mailbox key.
/// Format: `vmb_<hash>_<seq>` where seq is 0-padded 20-digit decimal.
/// Returns `(user_hash, seq)` or `None` if the key is not a valid mailbox seq key.
pub fn parse_mailbox_key(key: &[u8]) -> Option<(Vec<u8>, u64)> {
    let user_hash = parse_user_hash_from_key(key)?;
    // Find the underscore after the hash
    let after_prefix = &key[4..];
    let hash_end = after_prefix.iter().position(|&b| b == b'_')?;
    // Everything after this underscore is the decimal seq string
    let seq_str = &after_prefix[hash_end + 1..];
    let seq_str_utf8 = std::str::from_utf8(seq_str).ok()?;
    let seq: u64 = seq_str_utf8.parse().ok()?;
    Some((user_hash.to_vec(), seq))
}

// ── DhtEnvelope serialization ──────────────────────────────────────

/// Serialize a DhtEnvelope into binary via bincode.
pub fn serialize_envelope(envelope: &DhtEnvelope) -> Result<Vec<u8>, String> {
    bincode::serialize(envelope)
        .map_err(|e| format!("Failed to serialize DhtEnvelope: {e}"))
}

/// Deserialize a DhtEnvelope from binary.
pub fn deserialize_envelope(data: &[u8]) -> Result<DhtEnvelope, String> {
    bincode::deserialize(data)
        .map_err(|e| format!("Failed to deserialize DhtEnvelope: {e}"))
}

// ── Ed25519 verification (no new dependency — uses ed25519-dalek) ──

/// Build the verify buffer for a DhtEnvelope:
/// `payload || seq(8-byte LE) || recipient_hash(32 bytes)`
///
/// Returns `None` if `recipient_hash` is shorter than 32 bytes
/// (would produce a buffer without recipient binding).
pub fn build_verify_buffer(payload: &[u8], seq: u64, recipient_hash: &[u8]) -> Option<Vec<u8>> {
    if recipient_hash.len() < 32 {
        return None;
    }
    let mut buf = Vec::with_capacity(payload.len() + 8 + 32);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&recipient_hash[..32]);
    Some(buf)
}

/// Verify an Ed25519 signature on a DhtEnvelope against a recipient hash.
///
/// Returns `Ok(())` if the signature is valid, `Err` otherwise.
pub fn verify_envelope(
    envelope: &DhtEnvelope,
    recipient_hash: &[u8],
) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_bytes: [u8; 32] = envelope.sender_pubkey.as_slice().try_into()
        .map_err(|_| format!(
            "Invalid sender_pubkey length: expected 32, got {}",
            envelope.sender_pubkey.len()
        ))?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| format!("Invalid Ed25519 public key: {e}"))?;

    let sig_bytes: [u8; 64] = envelope.signature.as_slice().try_into()
        .map_err(|_| format!(
            "Invalid signature length: expected 64, got {}",
            envelope.signature.len()
        ))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let verify_buf = build_verify_buffer(&envelope.payload, envelope.seq, recipient_hash)
        .ok_or_else(|| "Recipient hash too short for verify buffer".to_string())?;

    verifying_key.verify(&verify_buf, &signature)
        .map_err(|e| format!("Envelope signature verification FAILED: {e}"))?;

    Ok(())
}

/// Sign a DhtEnvelope using the provided Ed25519 signing key.
///
/// Sets the `signature` field on the envelope in-place.
pub fn sign_envelope(
    envelope: &mut DhtEnvelope,
    signing_key: &ed25519_dalek::SigningKey,
    recipient_hash: &[u8],
) {
    use ed25519_dalek::Signer;
    let verify_buf = build_verify_buffer(&envelope.payload, envelope.seq, recipient_hash)
        .expect("sign_envelope: recipient_hash must be at least 32 bytes");
    let signature = signing_key.sign(&verify_buf);
    envelope.signature = signature.to_bytes().to_vec();
}

// ── Legacy helpers (kept for backward compat — sender_hash in payload) ─

/// Encodes a mailbox message for DHT storage (legacy format, now wrapped in envelope).
pub fn encode_mailbox_message(sender_hash: &[u8], encrypted_payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + sender_hash.len() + encrypted_payload.len());
    data.extend_from_slice(&(sender_hash.len() as u16).to_le_bytes());
    data.extend_from_slice(sender_hash);
    data.extend_from_slice(encrypted_payload);
    data
}

/// Decodes a mailbox message from DHT storage (legacy format).
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
    fn test_mailbox_seq_key_format() {
        let user_hash = b"0123456789abcdef0123456789abcdef";
        let key = mailbox_seq_key(user_hash, 42);
        let key_bytes = key.to_vec();
        assert!(key_bytes.starts_with(b"vmb_"));
        assert!(key_bytes.ends_with(b"00000000000000000042".as_ref()));
    }

    #[test]
    fn test_parse_user_hash_from_seq_key() {
        let hash = b"abcdef0123456789abcdef0123456789";
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
    fn test_envelope_serialize_deserialize() {
        let env = DhtEnvelope {
            payload: b"encrypted_payload_bytes".to_vec(),
            seq: 42,
            sender_pubkey: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        let bytes = serialize_envelope(&env).unwrap();
        let deserialized = deserialize_envelope(&bytes).unwrap();
        assert_eq!(deserialized.payload, env.payload);
        assert_eq!(deserialized.seq, env.seq);
        assert_eq!(deserialized.sender_pubkey, env.sender_pubkey);
        assert_eq!(deserialized.signature, env.signature);
    }

    #[test]
    fn test_envelope_sign_and_verify() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let mut envelope = DhtEnvelope {
            payload: b"secret_message".to_vec(),
            seq: 1,
            sender_pubkey: verifying_key.to_bytes().to_vec(),
            signature: vec![],
        };

        let recipient_hash = b"abcdef0123456789abcdef0123456789"; // 32 bytes
        sign_envelope(&mut envelope, &signing_key, recipient_hash);

        assert!(!envelope.signature.is_empty(), "Signature must be set");
        assert_eq!(envelope.signature.len(), 64, "Ed25519 signature is 64 bytes");

        assert!(verify_envelope(&envelope, recipient_hash).is_ok(), "Valid signature must verify");

        // Tamper with payload — verification must fail
        let mut tampered = envelope.clone();
        tampered.payload[0] ^= 0xFF;
        assert!(verify_envelope(&tampered, recipient_hash).is_err(), "Tampered payload must fail");

        // Wrong recipient — verification must fail
        let wrong_recipient = b"00000000000000000000000000000000";
        assert!(verify_envelope(&envelope, wrong_recipient).is_err(), "Wrong recipient must fail");

        // Wrong seq — verification must fail
        let mut seq_tampered = envelope.clone();
        seq_tampered.seq = 99;
        assert!(verify_envelope(&seq_tampered, recipient_hash).is_err(), "Wrong seq must fail");
    }

    #[test]
    fn test_build_verify_buffer() {
        let payload = b"hello";
        let seq: u64 = 42;
        let hash = b"abcdef0123456789abcdef0123456789";

        let buf = build_verify_buffer(payload, seq, hash).unwrap();
        assert!(buf.starts_with(payload));
        // Check seq is at position after payload
        let seq_start = payload.len();
        let seq_bytes = &buf[seq_start..seq_start + 8];
        assert_eq!(u64::from_le_bytes(seq_bytes.try_into().unwrap()), seq);
        // Check hash is at the end
        let hash_start = seq_start + 8;
        assert_eq!(&buf[hash_start..], hash);

        // Short hash returns None
        assert!(build_verify_buffer(payload, seq, b"short").is_none());
    }
}

