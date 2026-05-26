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

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use rand::{rngs::OsRng, RngCore};

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
}
