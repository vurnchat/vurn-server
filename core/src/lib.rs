#![forbid(unsafe_code)]

//! # vurn-core
//!
//! Post-quantum cryptographic core of the VurnChat messenger.
//!
//! This crate provides a clean, high-level API for:
//! - Generating ML-KEM-1024 keypairs (post-quantum key encapsulation)
//! - Encrypting messages using ML-KEM + AES-256-GCM (hybrid encryption)
//! - Decrypting messages with authentication and integrity verification
//!
//! ## Wire format
//!
//! The encrypted package layout:
//! ```text
//! [2 bytes: ML-KEM ciphertext length (u16 LE)]
//! [N bytes: ML-KEM ciphertext (encapsulated AES key)]
//! [12 bytes: AES-GCM nonce]
//! [M bytes: AES-GCM encrypted payload + 16-byte authentication tag]
//! ```

pub mod identity;
pub mod signing;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use pbkdf2::pbkdf2_hmac_array;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

// Type aliases for MlKem1024 parameter set
type MlKemEncapsKey = EncapsulationKey<MlKem1024Params>;
type MlKemDecapsKey = DecapsulationKey<MlKem1024Params>;

/// Core cryptographic engine for VurnChat.
///
/// Provides post-quantum secure key generation, encryption, and decryption.
/// All operations are pure — no network I/O, no filesystem access.
pub struct VurnCipher;

/// An encrypted message ready for transmission.
#[derive(Debug, Clone)]
struct EncryptedPackage {
    kem_ct: Vec<u8>,
    nonce: Vec<u8>,
    payload: Vec<u8>,
}

impl VurnCipher {
    /// Generates a new ML-KEM-1024 keypair.
    ///
    /// Returns `(public_key, secret_key)` as raw byte vectors.
    /// The public key can be shared freely; the secret key must remain private.
    pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let (dk, ek) = MlKem1024::generate(&mut rng);

        let pk_bytes = ek.as_bytes().as_slice().to_vec();
        let sk_bytes = dk.as_bytes().as_slice().to_vec();

        (pk_bytes, sk_bytes)
    }

    /// Encrypts a plaintext message for the given recipient public key.
    ///
    /// Returns the encrypted package as a byte vector, suitable for
    /// transmission over any transport.
    pub fn encrypt(public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // 1. Deserialize the recipient's encapsulation key
        let ek_encoded =
            ml_kem::Encoded::<MlKemEncapsKey>::try_from(public_key)
                .map_err(|_| format!(
                    "Invalid public key: expected {} bytes, got {}",
                    std::mem::size_of::<ml_kem::Encoded::<MlKemEncapsKey>>(),
                    public_key.len()
                ))?;
        let ek = MlKemEncapsKey::from_bytes(&ek_encoded);

        // 2. Encapsulate a shared secret via ML-KEM
        let mut rng = OsRng;
        let (kem_ct, shared_key) = ek
            .encapsulate(&mut rng)
            .map_err(|_| "ML-KEM encapsulation failed".to_string())?;

        // 3. Use the shared secret as an AES-256 key
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(shared_key.as_slice());
        let cipher = Aes256Gcm::new(aes_key);

        // 4. Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 5. Encrypt the plaintext via AES-GCM
        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // 6. Serialize everything into the wire format
        let package = serialize_package(kem_ct.as_slice(), &nonce_bytes, &encrypted);

        Ok(package)
    }

    /// Decrypts an encrypted message using the recipient's secret key.
    ///
    /// Returns the original plaintext bytes. Returns an error if the
    /// package has been tampered with or is malformed.
    pub fn decrypt(secret_key: &[u8], encrypted_package: &[u8]) -> Result<Vec<u8>, String> {
        // 1. Deserialize the package
        let package = deserialize_package(encrypted_package)?;

        // 2. Deserialize the decapsulation key
        let dk_encoded =
            ml_kem::Encoded::<MlKemDecapsKey>::try_from(secret_key)
                .map_err(|_| format!(
                    "Invalid secret key: expected {} bytes, got {}",
                    std::mem::size_of::<ml_kem::Encoded::<MlKemDecapsKey>>(),
                    secret_key.len()
                ))?;
        let dk = MlKemDecapsKey::from_bytes(&dk_encoded);

        // 3. Reconstruct the ML-KEM ciphertext from the wire bytes
        // The KEM ciphertext type uses CiphertextSize for MlKem1024
        let kem_ct: ml_kem::Ciphertext<MlKem1024> =
            ml_kem::Ciphertext::<MlKem1024>::try_from(package.kem_ct.as_slice())
                .map_err(|_| "Invalid KEM ciphertext length".to_string())?;

        // 4. Decapsulate the shared secret
        let shared_key = dk
            .decapsulate(&kem_ct)
            .map_err(|_| "ML-KEM decapsulation failed (wrong key or tampered ciphertext)".to_string())?;

        // 5. Use the shared secret as an AES-256 key
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(shared_key.as_slice());
        let cipher = Aes256Gcm::new(aes_key);

        // 6. Decrypt the payload
        let nonce = Nonce::from_slice(&package.nonce);
        let plaintext = cipher
            .decrypt(nonce, package.payload.as_ref())
            .map_err(|e| format!("Decryption failed (wrong key or tampered data): {}", e))?;

        Ok(plaintext)
    }

    /// Computes a SHA-256 hash of the public key for use as a short user ID.
    ///
    /// This 32-byte hash serves as the user's identity in the network.
    /// It can be shared with contacts to receive messages.
    pub fn hash_public_key(public_key: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.finalize().to_vec()
    }

    /// Derives a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256.
    ///
    /// Iteration count adapts to target:
    /// - WASM (browser): 100,000 (~100-300ms) — browser tab is ephemeral, keys erased on close
    /// - Native (server/CLI): 600,000 (~1s) — hardware protection against offline brute-force
    #[cfg(target_arch = "wasm32")]
    pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
        pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt, 100_000)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
        pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt, 600_000)
    }

    /// Encrypts data with AES-256-GCM using a raw 32-byte key.
    ///
    /// Wire format: `[12 bytes: random nonce][encrypted payload + 16-byte GCM tag]`.
    /// Used for local storage encryption (profile, contacts).
    pub fn encrypt_symmetric(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(aes_key);

        let mut rng = OsRng;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .expect("AES-GCM encrypt should not fail");

        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);
        result
    }

    /// Computes a safety fingerprint for two public keys.
    ///
    /// Sorts both keys alphabetically (same order for both parties),
    /// concatenates them, hashes with SHA-256, and formats as
    /// 12 groups of 5 decimal digits (like Signal/Threema).
    ///
    /// Both parties will compute the same fingerprint if they
    /// have each other's genuine public keys — MITM detection.
    pub fn compute_fingerprint(my_pk: &[u8], their_pk: &[u8]) -> String {
        // Sort so both sides compute the same hash
        let (first, second) = if my_pk < their_pk {
            (my_pk, their_pk)
        } else {
            (their_pk, my_pk)
        };

        let mut hasher = Sha256::new();
        hasher.update(first);
        hasher.update(second);
        let hash = hasher.finalize();

        // Convert hash bytes to 12 groups of 5 digits
        let mut result = String::with_capacity(71); // 12*5 + 11 spaces
        let mut buf = [0u8; 2];
        for i in 0..12 {
            let idx = (i * 2) % 30;
            // Take 2 bytes, make a u16, mod 100000
            buf[0] = hash[idx];
            buf[1] = hash[idx + 1];
            let val = u16::from_be_bytes(buf) as u32 % 100_000;
            if i > 0 {
                result.push(' ');
            }
            // Pad with leading zeros to 5 digits
            result.push_str(&format!("{:05}", val));
        }
        result
    }

    /// Decrypts data that was encrypted with `encrypt_symmetric`.
    ///
    /// Returns an error if the key is wrong or the data has been tampered with.
    pub fn decrypt_symmetric(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 12 + 16 {
            return Err("Ciphertext too short".to_string());
        }

        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(aes_key);

        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let payload = &ciphertext[12..];

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}

/// Serializes the encrypted package into the wire format.
fn serialize_package(kem_ct: &[u8], nonce: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let kem_ct_len = kem_ct.len() as u16;
    let mut result = Vec::with_capacity(2 + kem_ct.len() + 12 + payload.len());

    result.extend_from_slice(&kem_ct_len.to_le_bytes());
    result.extend_from_slice(kem_ct);
    result.extend_from_slice(nonce);
    result.extend_from_slice(payload);

    result
}

/// Deserializes the encrypted package from the wire format.
fn deserialize_package(data: &[u8]) -> Result<EncryptedPackage, String> {
    if data.len() < 2 {
        return Err("Package too short: missing KEM ciphertext length".to_string());
    }

    let kem_ct_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let hdr_end = 2 + kem_ct_len;

    if data.len() < hdr_end + 12 {
        return Err("Package too short: missing nonce".to_string());
    }

    let kem_ct = data[2..hdr_end].to_vec();
    let nonce = data[hdr_end..hdr_end + 12].to_vec();
    let payload = data[hdr_end + 12..].to_vec();

    // AES-GCM payload must include at least the 16-byte authentication tag
    if payload.len() < 16 {
        return Err("Package too short: payload missing authentication tag".to_string());
    }

    Ok(EncryptedPackage {
        kem_ct,
        nonce,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end() {
        // Alice generates her keypair
        let (pk_alice, sk_alice) = VurnCipher::generate_keypair();

        // Bob encrypts a message for Alice using her public key
        let message = b"Hello, Alice! This is a secret post-quantum message.";
        let encrypted = VurnCipher::encrypt(&pk_alice, message)
            .expect("Encryption should succeed");

        // Alice decrypts the message using her secret key
        let decrypted = VurnCipher::decrypt(&sk_alice, &encrypted)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_tampered_message_fails() {
        let (pk, sk) = VurnCipher::generate_keypair();
        let message = b"Sensitive data";
        let mut encrypted = VurnCipher::encrypt(&pk, message).unwrap();

        // Tamper with the payload
        let len = encrypted.len();
        if len > 5 {
            encrypted[len - 5] ^= 0xFF;
        }

        let result = VurnCipher::decrypt(&sk, &encrypted);
        assert!(result.is_err(), "Decryption should fail on tampered messages");
    }

    #[test]
    fn test_wrong_key_fails() {
        let (pk_alice, _sk_alice) = VurnCipher::generate_keypair();
        let (_pk_eve, sk_eve) = VurnCipher::generate_keypair();

        let message = b"Secret for Alice";
        let encrypted = VurnCipher::encrypt(&pk_alice, message).unwrap();

        // Eve tries to decrypt with her own key
        let result = VurnCipher::decrypt(&sk_eve, &encrypted);
        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_empty_message() {
        let (pk, sk) = VurnCipher::generate_keypair();
        let message = b"";
        let encrypted = VurnCipher::encrypt(&pk, message).unwrap();
        let decrypted = VurnCipher::decrypt(&sk, &encrypted).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_large_message() {
        let (pk, sk) = VurnCipher::generate_keypair();
        let message = vec![0x42u8; 1024 * 100]; // 100 KB
        let encrypted = VurnCipher::encrypt(&pk, &message).unwrap();
        let decrypted = VurnCipher::decrypt(&sk, &encrypted).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_keypair_uniqueness() {
        let (pk1, sk1) = VurnCipher::generate_keypair();
        let (pk2, sk2) = VurnCipher::generate_keypair();

        assert_ne!(pk1, pk2, "Public keys should be unique");
        assert_ne!(sk1, sk2, "Secret keys should be unique");
    }

    #[test]
    fn test_invalid_key_lengths() {
        // Truncated public key should fail
        let result = VurnCipher::encrypt(b"too_short", b"hello");
        assert!(result.is_err(), "Should reject truncated public key");

        // Truncated secret key should fail
        let (pk, _sk) = VurnCipher::generate_keypair();
        let encrypted = VurnCipher::encrypt(&pk, b"hello").unwrap();
        let result = VurnCipher::decrypt(b"too_short", &encrypted);
        assert!(result.is_err(), "Should reject truncated secret key");
    }

    #[test]
    fn test_cross_communication() {
        // Alice → Bob
        let (pk_a, sk_a) = VurnCipher::generate_keypair();
        let (pk_b, sk_b) = VurnCipher::generate_keypair();

        let msg_to_bob = b"Hey Bob!";
        let encrypted = VurnCipher::encrypt(&pk_b, msg_to_bob).unwrap();
        let decrypted = VurnCipher::decrypt(&sk_b, &encrypted).unwrap();
        assert_eq!(decrypted, msg_to_bob);

        // Bob → Alice
        let msg_to_alice = b"Hey Alice!";
        let encrypted = VurnCipher::encrypt(&pk_a, msg_to_alice).unwrap();
        let decrypted = VurnCipher::decrypt(&sk_a, &encrypted).unwrap();
        assert_eq!(decrypted, msg_to_alice);
    }

    #[test]
    fn test_fingerprint() {
        let (pk_a, _) = VurnCipher::generate_keypair();
        let (pk_b, _) = VurnCipher::generate_keypair();
        let (pk_c, _) = VurnCipher::generate_keypair();

        // Both sides compute same fingerprint regardless of order
        let fp1 = VurnCipher::compute_fingerprint(&pk_a, &pk_b);
        let fp2 = VurnCipher::compute_fingerprint(&pk_b, &pk_a);
        assert_eq!(fp1, fp2, "Fingerprint must be order-independent");

        // Different keys produce different fingerprints
        let fp3 = VurnCipher::compute_fingerprint(&pk_a, &pk_c);
        assert_ne!(fp1, fp3, "Different keypairs must produce different fingerprints");

        // Format: 12 groups of 5 digits separated by spaces
        let groups: Vec<&str> = fp1.split(' ').collect();
        assert_eq!(groups.len(), 12, "Must have 12 digit groups");
        for g in &groups {
            assert_eq!(g.len(), 5, "Each group must be 5 digits");
            assert!(g.chars().all(|c| c.is_ascii_digit()), "Groups must be digits only");
        }
    }

    /// Full sender-authentication pipeline:
    /// 1. Alice signs the text with her ML-DSA key (payload inside ciphertext)
    /// 2. Alice encrypts the signed payload for Bob
    /// 3. Relay stores/forwards the opaque ciphertext
    /// 4. Bob decrypts and verifies Alice's signature with her stored key
    ///
    /// Also proves an attacker who can encrypt to Bob (anyone knowing Bob's
    /// public key) still cannot forge a message from Alice.
    #[test]
    fn test_signed_message_mailbox_roundtrip() {
        let (pk_alice, _) = VurnCipher::generate_keypair();
        let (pk_bob, sk_bob) = VurnCipher::generate_keypair();
        let (sig_pk_alice, sig_sk_alice) = crate::signing::generate_signing_keypair();
        let (_sig_pk_eve, sig_sk_eve) = crate::signing::generate_signing_keypair();

        let original = b"Authenticated message through the mailbox";

        // Alice signs and encrypts for Bob.
        let signed = crate::signing::sign_message(&sig_sk_alice, original).expect("sign");
        let encrypted = VurnCipher::encrypt(&pk_bob, &signed).expect("encrypt");

        // Mailbox frame: [alice_hash_len][alice_hash][ciphertext]
        let alice_hash = VurnCipher::hash_public_key(&pk_alice);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(alice_hash.len() as u16).to_le_bytes());
        frame.extend_from_slice(&alice_hash);
        frame.extend_from_slice(&encrypted);

        // Bob receives, decrypts, verifies against stored Alice key.
        let id_len = u16::from_le_bytes([frame[0], frame[1]]) as usize;
        let claimed_sender = &frame[2..2 + id_len];
        assert_eq!(claimed_sender, alice_hash.as_slice());
        let decrypted = VurnCipher::decrypt(&sk_bob, &frame[2 + id_len..]).expect("decrypt");
        let verified = crate::signing::verify_message(&sig_pk_alice, &decrypted).expect("verify");
        assert_eq!(verified, original);

        // Eve forges: she can encrypt to Bob but cannot sign as Alice.
        let forged = crate::signing::sign_message(&sig_sk_eve, b"I am Alice").expect("forge sign");
        let forged_ct = VurnCipher::encrypt(&pk_bob, &forged).expect("forge encrypt");
        let forged_plain = VurnCipher::decrypt(&sk_bob, &forged_ct).expect("decrypt forged");
        assert_eq!(
            crate::signing::verify_message(&sig_pk_alice, &forged_plain),
            Err(crate::signing::VerifyStatus::BadSignature),
            "Eve's message must fail verification as Alice"
        );
    }

    /// Simulates the full mailbox delivery pipeline:
    /// 1. Alice encrypts a message for Bob
    /// 2. Alice builds a wire frame: [recipient_id_len][recipient_id=bob_hash][encrypted_payload]
    /// 3. Server relays → builds forward frame: [sender_id_len][sender_id=alice_hash][encrypted_payload]
    /// 4. Bob is offline → server stores in mailbox memory
    /// 5. Bob reconnects → server builds mailbox blob: [0xFE,0xFE][count][len][forward]... padded
    /// 6. Bob's client receives blob → parses → extracts forward frames → decrypts
    ///
    /// This test validates that the ENCRYPTION survives the entire mailbox format round-trip
    /// without the server ever seeing plaintext.
    #[test]
    fn test_mailbox_roundtrip() {
        // Simulate Alice and Bob
        let (pk_alice, _sk_alice) = VurnCipher::generate_keypair();
        let (pk_bob, sk_bob) = VurnCipher::generate_keypair();

        let alice_hash = VurnCipher::hash_public_key(&pk_alice);
        let bob_hash = VurnCipher::hash_public_key(&pk_bob);

        let original_message = b"Hey Bob! This is a secret message from Alice.";

        // ── Step 1: Alice encrypts for Bob ──
        let encrypted = VurnCipher::encrypt(&pk_bob, original_message)
            .expect("Alice should encrypt for Bob");

        // ── Step 2: Build the relay frame ──
        // Client sends: [2 bytes: bob_hash_len][bob_hash bytes][encrypted payload]
        let mut relay_frame = Vec::new();
        relay_frame.extend_from_slice(&(bob_hash.len() as u16).to_le_bytes());
        relay_frame.extend_from_slice(&bob_hash);
        relay_frame.extend_from_slice(&encrypted);

        // ── Step 3: Server builds forward frame ──
        // Server parses relay_frame, extracts encrypted payload, builds forward:
        // [2 bytes: alice_hash_len][alice_hash bytes][encrypted payload]
        let id_len = u16::from_le_bytes([relay_frame[0], relay_frame[1]]) as usize;
        let payload = &relay_frame[2 + id_len..];

        let mut forward = Vec::new();
        forward.extend_from_slice(&(alice_hash.len() as u16).to_le_bytes());
        forward.extend_from_slice(&alice_hash);
        forward.extend_from_slice(payload);

        // Verify forward frame is non-empty and contains the encrypted payload
        assert!(forward.len() > alice_hash.len() + 2, "Forward frame must contain payload");

        // ── Step 4: Store in mailbox (simulate offline) ──
        let mailbox: Vec<Vec<u8>> = vec![forward];
        assert_eq!(mailbox.len(), 1, "Mailbox should contain 1 message");

        // ── Step 5: Build mailbox delivery blob (server -> client on reconnect) ──
        let mut blob = vec![0xFE, 0xFE];
        blob.extend_from_slice(&(mailbox.len() as u16).to_le_bytes());
        for msg in &mailbox {
            blob.extend_from_slice(&(msg.len() as u16).to_le_bytes());
            blob.extend_from_slice(msg);
        }

        // ── Step 6: Client parses mailbox blob (simulate on_msg handler) ──
        assert!(blob.len() >= 4, "Blob must have sentinel + count");
        assert_eq!(blob[0], 0xFE, "Must start with mailbox sentinel");
        assert_eq!(blob[1], 0xFE, "Must start with mailbox sentinel");

        let num_msgs = u16::from_le_bytes([blob[2], blob[3]]) as usize;
        assert_eq!(num_msgs, 1, "Should have 1 message in mailbox");

        let mut pos = 4usize;
        let mut received_messages = Vec::new();

        for _ in 0..num_msgs {
            assert!(pos + 2 <= blob.len(), "Position must be within blob");
            let msg_len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
            pos += 2;
            assert!(pos + msg_len <= blob.len(), "Message must fit in blob");
            let msg = &blob[pos..pos + msg_len];
            pos += msg_len;

            // Parse forward frame: [2 bytes: sender_id_len][sender_id bytes][encrypted payload]
            assert!(msg.len() >= 2, "Forward frame must have sender_id_len");
            let sender_id_len = u16::from_le_bytes([msg[0], msg[1]]) as usize;
            assert!(msg.len() >= 2 + sender_id_len, "Forward frame must have sender_id + payload");

            let sender_hex = hex::encode(&msg[2..2 + sender_id_len]);
            let encrypted_payload = &msg[2 + sender_id_len..];

            received_messages.push((sender_hex, encrypted_payload.to_vec()));
        }

        // ── Step 7: Bob decrypts each received message ──
        assert_eq!(received_messages.len(), 1, "Should have received 1 message");
        let (sender, encrypted_payload) = &received_messages[0];

        // Verify sender is Alice
        let expected_sender = hex::encode(&alice_hash);
        assert_eq!(sender, &expected_sender, "Sender should be Alice's hash");

        // Bob decrypts
        let decrypted = VurnCipher::decrypt(&sk_bob, encrypted_payload)
            .expect("Bob should decrypt mailbox message");

        assert_eq!(decrypted, original_message, "Decrypted message must match original");
    }

    /// Tests that multiple messages in a mailbox maintain correct order
    /// and all decrypt correctly.
    #[test]
    fn test_mailbox_multiple_ordering() {
        let (pk_alice, _sk_alice) = VurnCipher::generate_keypair();
        let (pk_bob, sk_bob) = VurnCipher::generate_keypair();

        let alice_hash = VurnCipher::hash_public_key(&pk_alice);
        let _bob_hash = VurnCipher::hash_public_key(&pk_bob);

        let messages: [&[u8]; 5] = [
            b"Message 1: Hello!",
            b"Message 2: How are you?",
            b"Message 3: Are you there?",
            b"Message 4: I have news!",
            b"Message 5: Call me when you can.",
        ];

        // Build mailbox with 5 messages from Alice to Bob
        let mut mailbox: Vec<Vec<u8>> = Vec::new();

        for msg in &messages {
            let encrypted = VurnCipher::encrypt(&pk_bob, msg)
                .expect("Encryption should succeed");

            // Build forward frame: [sender_id_len][sender_id][encrypted_payload]
            let mut forward = Vec::new();
            forward.extend_from_slice(&(alice_hash.len() as u16).to_le_bytes());
            forward.extend_from_slice(&alice_hash);
            forward.extend_from_slice(&encrypted);
            mailbox.push(forward);
        }

        assert_eq!(mailbox.len(), 5, "Mailbox should have 5 messages");

        // Build mailbox delivery blob
        let mut blob = vec![0xFE, 0xFE];
        blob.extend_from_slice(&(mailbox.len() as u16).to_le_bytes());
        for msg in &mailbox {
            blob.extend_from_slice(&(msg.len() as u16).to_le_bytes());
            blob.extend_from_slice(msg);
        }
        // Add padding to verify the client skips padding correctly
        let padding = 128;
        blob.resize(blob.len() + padding, 0);

        // Client parses
        assert!(blob[0] == 0xFE && blob[1] == 0xFE);
        let num_msgs = u16::from_le_bytes([blob[2], blob[3]]) as usize;
        assert_eq!(num_msgs, 5, "Should have 5 messages");

        let mut pos = 4usize;
        let mut decrypted_messages = Vec::new();

        for i in 0..num_msgs {
            let msg_len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
            pos += 2;
            let msg = &blob[pos..pos + msg_len];
            pos += msg_len;

            let sender_id_len = u16::from_le_bytes([msg[0], msg[1]]) as usize;
            let encrypted_payload = &msg[2 + sender_id_len..];

            let decrypted = VurnCipher::decrypt(&sk_bob, encrypted_payload)
                .expect(&format!("Message {} should decrypt", i));
            decrypted_messages.push(decrypted);
        }

        // Verify order and content
        for (i, decrypted) in decrypted_messages.iter().enumerate() {
            assert_eq!(
                decrypted.as_slice(),
                messages[i],
                "Message {} should match original after mailbox round-trip",
                i
            );
        }

        assert_eq!(decrypted_messages.len(), 5, "All 5 messages should be recovered");
    }

    /// Tests that messages encrypted by different senders
    /// in the same mailbox are correctly attributed.
    #[test]
    fn test_mailbox_multi_sender() {
        let (pk_alice, _sk_alice) = VurnCipher::generate_keypair();
        let (pk_bob, sk_bob) = VurnCipher::generate_keypair();
        let (pk_charlie, _) = VurnCipher::generate_keypair();

        let alice_hash = VurnCipher::hash_public_key(&pk_alice);
        let charlie_hash = VurnCipher::hash_public_key(&pk_charlie);

        // Alice sends a message to Bob
        let msg_alice = b"Hi Bob from Alice!";
        let encrypted_alice = VurnCipher::encrypt(&pk_bob, msg_alice).unwrap();
        let mut forward_alice = Vec::new();
        forward_alice.extend_from_slice(&(alice_hash.len() as u16).to_le_bytes());
        forward_alice.extend_from_slice(&alice_hash);
        forward_alice.extend_from_slice(&encrypted_alice);

        // Charlie sends a message to Bob
        let msg_charlie = b"Hey Bob, it's Charlie!";
        let encrypted_charlie = VurnCipher::encrypt(&pk_bob, msg_charlie).unwrap();
        let mut forward_charlie = Vec::new();
        forward_charlie.extend_from_slice(&(charlie_hash.len() as u16).to_le_bytes());
        forward_charlie.extend_from_slice(&charlie_hash);
        forward_charlie.extend_from_slice(&encrypted_charlie);

        // Build mailbox blob
        let mailbox = vec![forward_alice, forward_charlie];
        let mut blob = vec![0xFE, 0xFE];
        blob.extend_from_slice(&(mailbox.len() as u16).to_le_bytes());
        for msg in &mailbox {
            blob.extend_from_slice(&(msg.len() as u16).to_le_bytes());
            blob.extend_from_slice(msg);
        }

        // Bob parses the mailbox
        let num_msgs = u16::from_le_bytes([blob[2], blob[3]]) as usize;
        assert_eq!(num_msgs, 2);

        let mut pos = 4usize;
        let mut results = Vec::new();

        for _ in 0..num_msgs {
            let msg_len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
            pos += 2;
            let msg = &blob[pos..pos + msg_len];
            pos += msg_len;

            let sender_len = u16::from_le_bytes([msg[0], msg[1]]) as usize;
            let sender = hex::encode(&msg[2..2 + sender_len]);
            let payload = &msg[2 + sender_len..];

            let decrypted = VurnCipher::decrypt(&sk_bob, payload).unwrap();
            let plaintext = String::from_utf8(decrypted).unwrap();
            results.push((sender, plaintext));
        }

        // Verify sender attribution
        assert_eq!(results[0].1, "Hi Bob from Alice!");
        assert_eq!(results[1].1, "Hey Bob, it's Charlie!");

        // Alice's message should be attributed to Alice
        assert_eq!(results[0].0, hex::encode(&alice_hash));
        assert_eq!(results[1].0, hex::encode(&charlie_hash));
    }

    /// Tests that tampered mailbox messages fail decryption.
    #[test]
    fn test_mailbox_tampered_fails() {
        let (pk_alice, _) = VurnCipher::generate_keypair();
        let (pk_bob, sk_bob) = VurnCipher::generate_keypair();

        let alice_hash = VurnCipher::hash_public_key(&pk_alice);

        let msg = b"Secret message";
        let encrypted = VurnCipher::encrypt(&pk_bob, msg).unwrap();

        let mut forward = Vec::new();
        forward.extend_from_slice(&(alice_hash.len() as u16).to_le_bytes());
        forward.extend_from_slice(&alice_hash);
        forward.extend_from_slice(&encrypted);

        // Tamper with the encrypted payload inside the forward frame
        let payload_start = 2 + alice_hash.len();
        let tampered_pos = payload_start + 10;
        if forward.len() > tampered_pos {
            forward[tampered_pos] ^= 0xFF;
        }

        // Build mailbox blob
        let mailbox = vec![forward];
        let mut blob = vec![0xFE, 0xFE];
        blob.extend_from_slice(&(mailbox.len() as u16).to_le_bytes());
        for msg in &mailbox {
            blob.extend_from_slice(&(msg.len() as u16).to_le_bytes());
            blob.extend_from_slice(msg);
        }

        // Parse and try to decrypt
        let _num_msgs = u16::from_le_bytes([blob[2], blob[3]]) as usize;
        let mut pos = 4usize;

        let msg_len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
        pos += 2;
        let msg = &blob[pos..pos + msg_len];

        let sender_len = u16::from_le_bytes([msg[0], msg[1]]) as usize;
        let payload = &msg[2 + sender_len..];

        let result = VurnCipher::decrypt(&sk_bob, payload);
        assert!(result.is_err(), "Tampered mailbox message should fail decryption");
    }
}
