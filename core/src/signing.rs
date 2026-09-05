//! # Sender authentication with ML-DSA-87
//!
//! Post-quantum sender signatures (FIPS 204, security category 5 — the same
//! level as the ML-KEM-1024 encryption keys).
//!
//! Every message payload carries a signature made by the *sender's* ML-DSA
//! signing key, wrapped **inside** the AES-GCM encryption:
//!
//! ```text
//! outer wire frame:  [recipient/sender id][ AES-256-GCM(...) ]
//! encrypted payload: [ 2B sig len ][ 4627B ML-DSA-87 sig ][ message text ]
//! ```
//!
//! The signature covers the message text, so the relay can neither forge a
//! message from a known contact nor alter one in transit. The relay never sees
//! the signature (it is inside the ciphertext), so it adds no metadata.
//!
//! ## Key sizes (ML-DSA-87)
//!
//! | Component | Size |
//! |---|---|
//! | secret key (seed) | 32 bytes |
//! | verifying (public) key | 2592 bytes |
//! | signature | 4627 bytes |

use ml_dsa::{
    Keypair, MlDsa87, Signature as MldsaSignature, SignatureEncoding, Signer, SigningKey,
    VerifyingKey, Verifier,
};
use rand::{rngs::OsRng, RngCore};

/// ML-DSA-87 verifying (public) key size in bytes.
pub const PUBLIC_KEY_LEN: usize = 2592;
/// ML-DSA-87 signature size in bytes.
pub const SIGNATURE_LEN: usize = 4627;
/// ML-DSA secret keys are 32-byte seeds at every security level.
pub const SECRET_KEY_LEN: usize = 32;

/// Result of [`verify_message`] when the signature does not check out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    /// Payload has no signature framing (legacy / unsigned message).
    NoSignature,
    /// No verifying key was supplied (unknown sender or legacy contact).
    NoKey,
    /// Supplied verifying key has an invalid length.
    BadPublicKey,
    /// Signature is present but does not verify against the given key.
    BadSignature,
}

/// Generates a new ML-DSA-87 signing keypair.
///
/// Returns `(public_key, secret_key)`. The secret key is the compact 32-byte
/// seed; the public (verifying) key must be shared with contacts so they can
/// authenticate messages from this identity.
pub fn generate_signing_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut seed = [0u8; SECRET_KEY_LEN];
    OsRng.fill_bytes(&mut seed);
    let seed_arr: ml_dsa::Seed = seed.into();
    let signing_key = SigningKey::<MlDsa87>::from_seed(&seed_arr);
    let public_key = signing_key.verifying_key().encode();
    (public_key.as_slice().to_vec(), seed.to_vec())
}

/// Produces a signed payload from message text.
///
/// Payload layout: `[2 bytes u16 LE signature length][signature][text]`.
/// The caller then encrypts this payload for the recipient. The signature is
/// deterministic (FIPS 204 optional deterministic variant), which is safe here
/// because the surrounding ML-KEM + AES-GCM encryption adds fresh randomness.
pub fn sign_message(secret_key: &[u8], text: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != SECRET_KEY_LEN {
        return Err(format!(
            "Invalid signing secret key: expected {} bytes, got {}",
            SECRET_KEY_LEN,
            secret_key.len()
        ));
    }
    let seed_arr: ml_dsa::Seed = secret_key
        .try_into()
        .map_err(|_| "Signing secret key must be exactly 32 bytes".to_string())?;
    let signing_key = SigningKey::<MlDsa87>::from_seed(&seed_arr);
    let sig = signing_key
        .try_sign(text)
        .map_err(|e| format!("ML-DSA signing failed: {}", e))?;
    let sig_bytes = sig.to_bytes();

    let mut payload = Vec::with_capacity(2 + SIGNATURE_LEN + text.len());
    payload.extend_from_slice(&(sig_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(&sig_bytes);
    payload.extend_from_slice(text);
    Ok(payload)
}

/// Produces a **raw** ML-DSA-87 signature over `data` (no payload framing).
///
/// Used for signing fixed-format structures where the byte layout is known
/// (e.g. the signed prekey in the identity bundle), as opposed to message
/// payloads which use the framed [`sign_message`] format.
pub fn sign_raw(secret_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != SECRET_KEY_LEN {
        return Err(format!(
            "Invalid signing secret key: expected {} bytes, got {}",
            SECRET_KEY_LEN,
            secret_key.len()
        ));
    }
    let seed_arr: ml_dsa::Seed = secret_key
        .try_into()
        .map_err(|_| "Signing secret key must be exactly 32 bytes".to_string())?;
    let signing_key = SigningKey::<MlDsa87>::from_seed(&seed_arr);
    let sig = signing_key
        .try_sign(data)
        .map_err(|e| format!("ML-DSA signing failed: {}", e))?;
    Ok(sig.to_bytes().as_slice().to_vec())
}

/// Verifies a **raw** ML-DSA-87 signature (produced by [`sign_raw`]) over
/// `data`. Returns `Ok(())` on success, or a [`VerifyStatus`] describing why
/// verification failed.
pub fn verify_raw(public_key: &[u8], data: &[u8], sig: &[u8]) -> Result<(), VerifyStatus> {
    if public_key.is_empty() {
        return Err(VerifyStatus::NoKey);
    }
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(VerifyStatus::BadPublicKey);
    }
    if sig.len() != SIGNATURE_LEN {
        return Err(VerifyStatus::BadSignature);
    }
    let enc_pk = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
        .map_err(|_| VerifyStatus::BadPublicKey)?;
    let enc_sig = ml_dsa::EncodedSignature::<MlDsa87>::try_from(sig)
        .map_err(|_| VerifyStatus::BadSignature)?;
    let vk = VerifyingKey::<MlDsa87>::decode(&enc_pk);
    let signature = MldsaSignature::<MlDsa87>::decode(&enc_sig)
        .ok_or(VerifyStatus::BadSignature)?;
    vk.verify(data, &signature)
        .map_err(|_| VerifyStatus::BadSignature)
}

/// Splits a payload into `(signature, text)` if it has valid signature framing.
pub fn split_payload(payload: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if payload.len() < 2 {
        return None;
    }
    let sig_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if sig_len == 0 || 2 + sig_len > payload.len() {
        return None;
    }
    Some((payload[2..2 + sig_len].to_vec(), payload[2 + sig_len..].to_vec()))
}

/// Verifies a signed payload against the sender's verifying (public) key.
///
/// On success returns the authenticated message text. On failure returns a
/// [`VerifyStatus`] describing why:
/// - `NoSignature` — legacy unsigned payload; treat as unauthenticated.
/// - `NoKey` / `BadPublicKey` — cannot verify; treat as unauthenticated.
/// - `BadSignature` — the signature does not match the claimed sender. This is
///   strong evidence of spoofing and the message should not be trusted.
pub fn verify_message(public_key: &[u8], payload: &[u8]) -> Result<Vec<u8>, VerifyStatus> {
    let (sig_bytes, text) = split_payload(payload).ok_or(VerifyStatus::NoSignature)?;

    if public_key.is_empty() {
        return Err(VerifyStatus::NoKey);
    }
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(VerifyStatus::BadPublicKey);
    }

    // Reconstruct the typed ML-DSA types from the wire bytes.
    let enc_pk = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
        .map_err(|_| VerifyStatus::BadPublicKey)?;
    let enc_sig = ml_dsa::EncodedSignature::<MlDsa87>::try_from(sig_bytes.as_slice())
        .map_err(|_| VerifyStatus::BadSignature)?;

    let verifying_key = VerifyingKey::<MlDsa87>::decode(&enc_pk);
    let signature = MldsaSignature::<MlDsa87>::decode(&enc_sig)
        .ok_or(VerifyStatus::BadSignature)?;

    verifying_key
        .verify(text.as_slice(), &signature)
        .map_err(|_| VerifyStatus::BadSignature)?;

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_sign_verify() {
        let (pk, sk) = generate_signing_keypair();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        assert_eq!(sk.len(), SECRET_KEY_LEN);

        let text = b"Authenticated post-quantum message";
        let payload = sign_message(&sk, text).expect("sign");
        let recovered = verify_message(&pk, &payload).expect("verify");
        assert_eq!(recovered, text);
    }

    #[test]
    fn test_empty_text_roundtrip() {
        let (pk, sk) = generate_signing_keypair();
        let payload = sign_message(&sk, b"").expect("sign");
        let recovered = verify_message(&pk, &payload).expect("verify");
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_raw_sign_verify() {
        let (pk, sk) = generate_signing_keypair();
        let data = b"signed prekey binding material";

        let sig = sign_raw(&sk, data).expect("raw sign");
        assert_eq!(sig.len(), SIGNATURE_LEN, "raw signature must be exactly 4627 bytes");
        assert!(verify_raw(&pk, data, &sig).is_ok());

        // Tampered message / signature must fail.
        assert!(verify_raw(&pk, b"tampered", &sig).is_err());
        let mut bad_sig = sig.clone();
        bad_sig[10] ^= 0x01;
        assert!(verify_raw(&pk, data, &bad_sig).is_err());

        // Wrong key must fail.
        let (other_pk, _) = generate_signing_keypair();
        assert!(verify_raw(&other_pk, data, &sig).is_err());

        // Size/format validation.
        assert!(verify_raw(&pk, data, &[]).is_err());
        assert!(verify_raw(&[], data, &sig).is_err());
        assert_eq!(verify_raw(&vec![1u8], data, &sig), Err(VerifyStatus::BadPublicKey));
    }

    #[test]
    fn test_tampered_text_fails() {
        let (pk, sk) = generate_signing_keypair();
        let payload = sign_message(&sk, b"important message").expect("sign");

        // Flip a bit in the text portion (last byte)
        let mut tampered = payload.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;

        assert_eq!(
            verify_message(&pk, &tampered),
            Err(VerifyStatus::BadSignature),
            "Tampered text must fail verification"
        );
    }

    #[test]
    fn test_tampered_signature_fails() {
        let (pk, sk) = generate_signing_keypair();
        let payload = sign_message(&sk, b"important message").expect("sign");
        let (mut sig, _text) = split_payload(&payload).expect("split");
        sig[0] ^= 0x01; // corrupt the signature bytes

        let mut tampered = Vec::new();
        tampered.extend_from_slice(&(sig.len() as u16).to_le_bytes());
        tampered.extend_from_slice(&sig);
        tampered.extend_from_slice(b"important message");

        assert_eq!(
            verify_message(&pk, &tampered),
            Err(VerifyStatus::BadSignature),
            "Tampered signature must fail verification"
        );
    }

    #[test]
    fn test_wrong_key_fails() {
        let (pk_alice, sk_alice) = generate_signing_keypair();
        let (_pk_mallory, _sk_mallory) = generate_signing_keypair();
        // Mallory signs a message but claims it is from Alice.
        let payload = sign_message(&sk_alice, b"Hello Bob").expect("sign");
        let wrong_pk = generate_signing_keypair().0;

        assert_ne!(wrong_pk, pk_alice);
        assert_eq!(
            verify_message(&wrong_pk, &payload),
            Err(VerifyStatus::BadSignature),
            "Verification against a different sender key must fail"
        );
    }

    #[test]
    fn test_no_key_and_no_signature_states() {
        let (pk, sk) = generate_signing_keypair();

        // Payload without signature framing → NoSignature
        assert_eq!(
            verify_message(&pk, b"legacy plain text"),
            Err(VerifyStatus::NoSignature)
        );

        // Signed payload but empty key → NoKey
        let payload = sign_message(&sk, b"hi").expect("sign");
        assert_eq!(verify_message(&[], &payload), Err(VerifyStatus::NoKey));

        // Wrong-length key → BadPublicKey
        assert_eq!(
            verify_message(&[1u8, 2, 3], &payload),
            Err(VerifyStatus::BadPublicKey)
        );
    }

    #[test]
    fn test_deterministic_signature_same_text() {
        let (_pk, sk) = generate_signing_keypair();
        let p1 = sign_message(&sk, b"same").expect("s1");
        let p2 = sign_message(&sk, b"same").expect("s2");
        assert_eq!(p1, p2, "Deterministic signing must produce identical payloads");
    }
}
