//! # Blind Identity Management
//!
//! Zero-knowledge username registration, profile lookup, and invite links.
//!
//! The server **never learns the actual username** — only a 32-byte HMAC-based
//! search index. Profile data is encrypted with a key derived from the username,
//! so only someone who knows the exact username can decrypt it.
//!
//! ## Key properties
//!
//! - **Blind search**: Server stores `[HMAC(username) → AES-GCM(public_key)]`.
//!   It cannot recover the username from the HMAC or decrypt the profile.
//! - **Authentication via decryption**: If you know the correct username,
//!   AES-GCM authentication succeeds and you get the public key. If wrong,
//!   AES-GCM authentication fails.
//! - **No server-side verification**: The server never checks "is this the
//!   right password?" — it's purely cryptographic. The AES-GCM auth tag does
//!   the verification.
//! - **Invite links / QR codes**: Direct peer-to-peer contact addition without
//!   any server round-trip. Pack session_hash + both public keys (ML-KEM + the
//!   ML-DSA sender-verification key) into a base64url invite URL and render as
//!   QR SVG where the payload fits.
//!
//! ## Identity payload
//!
//! A Vurn identity is **two keypairs**: the ML-KEM-1024 encryption keypair and
//! an ML-DSA-87 signing keypair used to authenticate messages from this
//! identity. Everywhere a public key is shared (profile blob, invite, contact),
//! both public keys travel together as one sealed payload:
//!
//! ```text
//! [2B u16 LE kem_pk_len][ML-KEM pk][2B u16 LE sig_pk_len][ML-DSA-87 pk]
//! ```

use crate::VurnCipher;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Salt for deriving the **search index** (what the server uses as a key).
/// Different from the encryption salt so that having the search index does
/// not reveal the encryption key (though both are derived from the same username).
const VURN_SEARCH_SALT: &[u8] = b"VURN_SEARCH";

/// Salt for deriving the **profile encryption key** (what decrypts the blob).
const VURN_PROFILE_ENC_SALT: &[u8] = b"VURN_PROFILE_ENC";

/// Manages blind username registration, profile lookup, and invite links.
///
/// All operations are stateless (pure functions). The only state is the
/// server-side HashMap of `[search_index] → [encrypted_blob]`, which this
/// module does not manage directly.
pub struct BlindProfileManager;

impl BlindProfileManager {
    /// Prepares registration data for a username.
    ///
    /// Returns `(search_index, encrypted_blob)`:
    ///
    /// | Component | Size | Content |
    /// |---|---|---|
    /// | `search_index` | 32 bytes | `HMAC-SHA256(lowercase(username), "VURN_SEARCH")` |
    /// | `encrypted_blob` | variable | `AES-256-GCM(encode_identity(kem_pk, sig_pk))` keyed by `HMAC-SHA256(lowercase(username), "VURN_PROFILE_ENC")` |
    ///
    /// The caller should send both to the server. The server stores the blob
    /// at the index but cannot read it or recover the username from it.
    pub fn prepare_registration(
        username: &str,
        public_key: &[u8],
        signing_public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let normalized = username.to_lowercase();

        // ── Derive search index (sent to server as lookup key) ──
        let search_index = hmac_sha256(normalized.as_bytes(), VURN_SEARCH_SALT)?;

        // ── Derive encryption key (NEVER sent to server) ──
        let enc_key = derive_encryption_key(&normalized)?;

        // ── Encrypt the full identity (both public keys) with AES-256-GCM ──
        let identity = encode_identity(public_key, signing_public_key);
        let blob = VurnCipher::encrypt_symmetric(&enc_key, &identity);

        Ok((search_index, blob))
    }

    /// Resolves a username against an encrypted profile blob.
    ///
    /// Returns `(kem_public_key, signing_public_key)` if the username is
    /// correct. Returns an error if the username is wrong or the data is
    /// corrupted — AES-GCM authentication will fail, so the server does not
    /// need to verify anything.
    ///
    /// Since the encryption key is derived from the username, each username
    /// produces a different key. Trying username "Alice" against a blob that
    /// was registered under "Bob" will produce garbage and AES-GCM will reject it.
    pub fn resolve_profile(
        search_username: &str,
        encrypted_blob: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let normalized = search_username.to_lowercase();

        // Derive the same encryption key used during registration
        let enc_key = derive_encryption_key(&normalized)?;

        // Decrypt — if username is wrong, AES-GCM auth tag won't match
        let identity = VurnCipher::decrypt_symmetric(&enc_key, encrypted_blob)?;

        decode_identity(&identity)
    }

    /// Generates an invite link containing session hash + both public keys.
    ///
    /// Packed format:
    /// ```text
    /// [2 bytes: session_hash_len (u16 LE)]
    /// [session_hash bytes]
    /// [encode_identity payload: kem_pk + sig_pk]
    /// ```
    /// Then base64url-encoded without padding.
    ///
    /// `base_url` should be the origin of the page (e.g. `https://vurnchat.org`).
    /// The invite parameter is appended as `?invite=...`.
    ///
    /// Example output:
    /// ```text
    /// https://vurnchat.org/?invite=ZXhhbXBsZV9kYXRh...
    /// ```
    ///
    /// This link can be shared in any chat or rendered as a QR code.
    /// Scanning it adds the contact **without any server round-trip**.
    pub fn generate_invite(
        session_hash: &[u8],
        public_key: &[u8],
        signing_public_key: &[u8],
        base_url: &str,
    ) -> String {
        let identity = encode_identity(public_key, signing_public_key);
        let mut data = Vec::with_capacity(2 + session_hash.len() + identity.len());
        data.extend_from_slice(&(session_hash.len() as u16).to_le_bytes());
        data.extend_from_slice(session_hash);
        data.extend_from_slice(&identity);

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data);
        let base = base_url.trim_end_matches('/');
        format!("{}/?invite={}", base, encoded)
    }

    /// Parses an invite URL back into session hash, KEM public key, and the
    /// ML-DSA sender-verification public key.
    ///
    /// The inverse of [`generate_invite`](Self::generate_invite).
    /// Extracts the base64url data from `?invite=...`, decodes it,
    /// and unpacks the binary fields.
    ///
    /// Invites generated by the pre-signature versions of Vurn contain only the
    /// session hash + KEM key; for those, the returned signing key is empty and
    /// the contact is added as unauthenticated.
    pub fn parse_invite(invite_url: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let b64 = invite_url
            .split("?invite=")
            .nth(1)
            .ok_or_else(|| "Invalid invite URL: missing ?invite= parameter".to_string())?;

        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        if data.len() < 4 {
            return Err("Invite data too short: expected at least 4 header bytes".to_string());
        }

        // Parse session hash length
        let sh_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let offset = 2 + sh_len;

        if data.len() < offset + 2 {
            return Err("Invite data truncated: missing public key length header".to_string());
        }

        // Parse KEM public key length
        let pk_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let kem_end = offset + 2 + pk_len;

        if data.len() < kem_end {
            return Err(format!(
                "Invite data truncated: expected {} bytes for public key, got {}",
                pk_len,
                data.len() - offset - 2
            ));
        }

        let session_hash = data[2..offset].to_vec();
        let public_key = data[offset + 2..kem_end].to_vec();

        // Parse the ML-DSA signing key if present (v0.7+ invites); legacy
        // invites that predate signatures carry only the KEM key.
        let signing_public_key = if data.len() >= kem_end + 2 {
            let sig_len = u16::from_le_bytes([data[kem_end], data[kem_end + 1]]) as usize;
            if data.len() >= kem_end + 2 + sig_len {
                data[kem_end + 2..kem_end + 2 + sig_len].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok((session_hash, public_key, signing_public_key))
    }

    /// Generates an SVG QR code for the invite URL.
    ///
    /// `base_url` is passed through to [`generate_invite`](Self::generate_invite).
    /// Returns a complete `<svg>` XML string suitable for direct injection
    /// into HTML. The QR code encodes the invite URL; scanning it extracts
    /// the session hash and public key without any server round-trip.
    pub fn generate_invite_qr(
        session_hash: &[u8],
        public_key: &[u8],
        signing_public_key: &[u8],
        base_url: &str,
    ) -> Result<String, String> {
        let invite_url = Self::generate_invite(session_hash, public_key, signing_public_key, base_url);

        let code = qrcode::QrCode::new(invite_url.as_bytes())
            .map_err(|e| format!("QR code generation failed: {}", e))?;

        let svg = code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .dark_color(qrcode::render::svg::Color("#000000"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build();

        Ok(svg)
    }
}

/// Serializes an identity as `[u16 kem_len][kem_pk][u16 sig_len][sig_pk]`.
///
/// Both public keys of an identity (ML-KEM encryption + ML-DSA verification)
/// always travel together so a contact can both encrypt to, and authenticate
/// messages from, the same identity.
pub fn encode_identity(public_key: &[u8], signing_public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + public_key.len() + signing_public_key.len());
    out.extend_from_slice(&(public_key.len() as u16).to_le_bytes());
    out.extend_from_slice(public_key);
    out.extend_from_slice(&(signing_public_key.len() as u16).to_le_bytes());
    out.extend_from_slice(signing_public_key);
    out
}

/// Parses an identity payload back into `(kem_public_key, signing_public_key)`.
pub fn decode_identity(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if data.len() < 2 {
        return Err("Identity payload too short".to_string());
    }
    let kem_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let kem_end = 2 + kem_len;
    if data.len() < kem_end + 2 {
        return Err("Identity payload truncated: missing signing key header".to_string());
    }
    let sig_len = u16::from_le_bytes([data[kem_end], data[kem_end + 1]]) as usize;
    if data.len() < kem_end + 2 + sig_len {
        return Err("Identity payload truncated: signing key cut short".to_string());
    }
    Ok((
        data[2..kem_end].to_vec(),
        data[kem_end + 2..kem_end + 2 + sig_len].to_vec(),
    ))
}

/// Derives a 32-byte AES-256 encryption key from a normalized username.
///
/// Uses HMAC-SHA256 with constant salt `"VURN_PROFILE_ENC"`.
fn derive_encryption_key(normalized_username: &str) -> Result<[u8; 32], String> {
    let raw = hmac_sha256(normalized_username.as_bytes(), VURN_PROFILE_ENC_SALT)?;
    raw.as_slice()
        .try_into()
        .map_err(|_| "HMAC-SHA256 output should be exactly 32 bytes".to_string())
}

/// Computes HMAC-SHA256 of `data` keyed by `salt`.
fn hmac_sha256(data: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac =
        HmacSha256::new_from_slice(salt).map_err(|e| format!("HMAC init failed: {}", e))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VurnCipher;

    #[test]
    fn test_roundtrip_registration_resolve() {
        let username = "Alice";
        let (pk, _sk) = VurnCipher::generate_keypair();
        let (sig_pk, _sig_sk) = crate::signing::generate_signing_keypair();

        // Alice registers her username
        let (index, blob) = BlindProfileManager::prepare_registration(username, &pk, &sig_pk)
            .expect("prepare should succeed");

        // Search index is 32 bytes (SHA-256 output)
        assert_eq!(index.len(), 32, "Search index must be 32 bytes");

        // Bob resolves the username → gets BOTH public keys of Alice's identity
        let (resolved_pk, resolved_sig_pk) =
            BlindProfileManager::resolve_profile(username, &blob).expect("resolve should succeed");

        assert_eq!(resolved_pk, pk, "Resolved KEM key must match original");
        assert_eq!(
            resolved_sig_pk, sig_pk,
            "Resolved signing key must match original"
        );
    }

    #[test]
    fn test_wrong_username_fails_resolve() {
        let (pk, _sk) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();

        // Register under "Alice"
        let (_index, blob) =
            BlindProfileManager::prepare_registration("Alice", &pk, &sig_pk).expect("prepare");

        // Try to resolve with wrong username
        let result = BlindProfileManager::resolve_profile("Eve", &blob);
        assert!(
            result.is_err(),
            "Wrong username must fail AES-GCM authentication"
        );
    }

    #[test]
    fn test_case_insensitive_resolve() {
        let (pk, _sk) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();

        // Register as "Alice"
        let (_index, blob) =
            BlindProfileManager::prepare_registration("Alice", &pk, &sig_pk).expect("prepare");

        // Resolve as "alice" (lowercase)
        let (resolved, resolved_sig) =
            BlindProfileManager::resolve_profile("alice", &blob).expect("case-insensitive resolve");

        assert_eq!(resolved, pk, "Username lookup must be case-insensitive");
        assert_eq!(resolved_sig, sig_pk);
    }

    #[test]
    fn test_different_usernames_different_indices() {
        let (pk, _sk) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();

        let (index1, _) =
            BlindProfileManager::prepare_registration("Alice", &pk, &sig_pk).expect("prepare Alice");
        let (index2, _) =
            BlindProfileManager::prepare_registration("Bob", &pk, &sig_pk).expect("prepare Bob");

        assert_ne!(
            index1, index2,
            "Different usernames must produce different search indices"
        );
    }

    #[test]
    fn test_search_index_is_hmac_not_hash() {
        // Same username must produce the same search index (deterministic)
        let (pk, _sk) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();

        let (index1, _) =
            BlindProfileManager::prepare_registration("Charlie", &pk, &sig_pk).expect("1st");
        let (index2, _) =
            BlindProfileManager::prepare_registration("Charlie", &pk, &sig_pk).expect("2nd");

        assert_eq!(
            index1, index2,
            "Same username must produce the same search index"
        );
    }

    #[test]
    fn test_invite_roundtrip() {
        let (pk_alice, _) = VurnCipher::generate_keypair();
        let (sig_pk_alice, _) = crate::signing::generate_signing_keypair();
        let hash_alice = VurnCipher::hash_public_key(&pk_alice);
        let base = "https://vurnchat.org";

        // Generate invite
        let invite = BlindProfileManager::generate_invite(&hash_alice, &pk_alice, &sig_pk_alice, base);

        // Must be a valid URL
        assert!(
            invite.starts_with("https://vurnchat.org/?invite="),
            "Invite must be a proper URL"
        );
        assert!(invite.len() > 50, "Invite must contain encoded data");

        // Parse invite
        let (parsed_hash, parsed_pk, parsed_sig_pk) =
            BlindProfileManager::parse_invite(&invite).expect("parse should succeed");

        assert_eq!(parsed_hash, hash_alice, "Session hash must survive round-trip");
        assert_eq!(parsed_pk, pk_alice, "KEM public key must survive round-trip");
        assert_eq!(
            parsed_sig_pk, sig_pk_alice,
            "Signing public key must survive round-trip"
        );
    }

    #[test]
    fn test_invite_tampered_fails() {
        let (pk, _) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();
        let hash = VurnCipher::hash_public_key(&pk);
        let base = "https://vurnchat.org";

        let invite = BlindProfileManager::generate_invite(&hash, &pk, &sig_pk, base);

        // Parse original to get reference
        let (orig_hash, orig_pk, orig_sig_pk) =
            BlindProfileManager::parse_invite(&invite).expect("original should parse");

        // Replace a character with an INVALID base64 character (invalid URL char)
        // URL_SAFE_NO_PAD uses: A-Z, a-z, 0-9, -, _
        // '!' is not a valid base64 character, so decode will FAIL
        let tampered = invite.replacen('A', "!", 1);
        if tampered != invite {
            // If replace succeeded, expect parse error
            let result = BlindProfileManager::parse_invite(&tampered);
            assert!(result.is_err(), "Tampered invite with invalid base64 char must fail");
        } else {
            // No 'A' in the invite string, try with 'a'
            let tampered = invite.replacen('a', "!", 1);
            let result = BlindProfileManager::parse_invite(&tampered);
            assert!(result.is_err(), "Tampered invite with invalid base64 char must fail");
        }

        // Also verify that replacing a valid base64 char with another valid one
        // produces DIFFERENT data (not a parse error)
        let modified = invite.replacen('A', "B", 1);
        if modified != invite {
            if let Ok((mod_hash, mod_pk, mod_sig_pk)) = BlindProfileManager::parse_invite(&modified) {
                // If it parsed, the data must be different from the original
                assert!(
                    mod_hash != orig_hash || mod_pk != orig_pk || mod_sig_pk != orig_sig_pk,
                    "Modified invite must produce different data"
                );
            }
        }
    }

    #[test]
    fn test_invite_without_server_roundtrip() {
        // This test verifies the key property: invite links contain everything
        // needed to add a contact WITHOUT a server request.
        let (pk_alice, sk_alice) = VurnCipher::generate_keypair();
        let (sig_pk_alice, _sig_sk_alice) = crate::signing::generate_signing_keypair();
        let (sig_pk_bob, sig_sk_bob) = crate::signing::generate_signing_keypair();
        let hash_alice = VurnCipher::hash_public_key(&pk_alice);

        // Alice sends invite → Bob receives (no server involved)
        let invite =
            BlindProfileManager::generate_invite(&hash_alice, &pk_alice, &sig_pk_alice, "https://vurnchat.org");

        // Bob gets the invite URL (e.g., scanned from QR or pasted in chat)
        let (received_hash, received_pk, received_sig_pk) =
            BlindProfileManager::parse_invite(&invite).expect("Bob parses invite");

        assert_eq!(received_hash, hash_alice, "Bob gets Alice's session hash");
        assert_eq!(received_pk, pk_alice, "Bob gets Alice's KEM key");
        assert_eq!(received_sig_pk, sig_pk_alice, "Bob gets Alice's signing key");

        // Bob sends an AUTHENTICATED message to Alice using both keys from the invite
        let msg = b"Hi Alice! No server needed to find you.";
        let payload = crate::signing::sign_message(&sig_sk_bob, msg).expect("Bob signs");
        let encrypted = VurnCipher::encrypt(&received_pk, &payload)
            .expect("Bob encrypts for Alice");

        // Alice decrypts with her own secret key (received via invite)
        let decrypted = VurnCipher::decrypt(&sk_alice, &encrypted)
            .expect("Alice decrypts the message Bob sent");

        // Alice verifies Bob's sender signature using Bob's key from the invite
        let verified = crate::signing::verify_message(&sig_pk_bob, &decrypted)
            .expect("Alice verifies Bob's signature");
        assert_eq!(verified, msg, "Alice gets the correct plaintext");
    }

    #[test]
    fn test_legacy_invite_without_signing_key() {
        // Invites created before sender signatures carried only session hash + KEM key.
        // Parsing must succeed with an empty signing key so the contact can be
        // added as unauthenticated instead of failing outright.
        let (pk, _) = VurnCipher::generate_keypair();
        let hash = VurnCipher::hash_public_key(&pk);

        let mut data = Vec::new();
        data.extend_from_slice(&(hash.len() as u16).to_le_bytes());
        data.extend_from_slice(&hash);
        data.extend_from_slice(&(pk.len() as u16).to_le_bytes());
        data.extend_from_slice(&pk);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data);
        let invite = format!("https://vurnchat.org/?invite={}", encoded);

        let (parsed_hash, parsed_pk, parsed_sig_pk) =
            BlindProfileManager::parse_invite(&invite).expect("legacy invite must parse");
        assert_eq!(parsed_hash, hash);
        assert_eq!(parsed_pk, pk);
        assert!(parsed_sig_pk.is_empty(), "Legacy invite has no signing key");
    }

    #[test]
    fn test_identity_encode_decode_roundtrip() {
        let (pk, _) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();

        let enc = encode_identity(&pk, &sig_pk);
        let (dec_pk, dec_sig) = decode_identity(&enc).expect("decode");
        assert_eq!(dec_pk, pk);
        assert_eq!(dec_sig, sig_pk);

        assert!(decode_identity(&pk).is_err(), "Bare KEM key is not a valid identity");
        assert!(decode_identity(&[]).is_err());
    }

    #[test]
    fn test_invite_qr_small_payload_generates_svg() {
        // Real ML-DSA-87 + ML-KEM keys make the invite URL longer than a QR code
        // can hold, so generation fails gracefully. Small payloads must still work.
        let hash = vec![7u8; 32];
        let pk = vec![1u8, 2, 3];
        let sig_pk = vec![4u8, 5, 6];

        let svg = BlindProfileManager::generate_invite_qr(&hash, &pk, &sig_pk, "https://vurnchat.org")
            .expect("Small invite QR should succeed");
        assert!(svg.contains("<svg"), "QR must contain an SVG element");
        assert!(svg.contains("</svg>"), "SVG must close properly");
        assert!(svg.len() > 500);
    }

    #[test]
    fn test_invite_qr_real_keys_too_long() {
        // Full-size identity (KEM 1568 B + ML-DSA-87 2592 B) cannot fit in a QR
        // code; the function must report an error rather than panic.
        let (pk, _) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();
        let hash = VurnCipher::hash_public_key(&pk);

        let result = BlindProfileManager::generate_invite_qr(&hash, &pk, &sig_pk, "https://vurnchat.org");
        assert!(
            result.is_err(),
            "Full-size PQ identity must exceed QR capacity and report an error"
        );
    }

    #[test]
    fn test_different_usernames_different_blobs_same_key() {
        let (pk, _sk) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();

        // Same public key, different usernames → different blobs
        let (_, blob1) =
            BlindProfileManager::prepare_registration("Alice", &pk, &sig_pk).expect("Alice");
        let (_, blob2) =
            BlindProfileManager::prepare_registration("Bob", &pk, &sig_pk).expect("Bob");

        assert_ne!(
            blob1, blob2,
            "Different usernames must produce different encrypted blobs"
        );
    }

    #[test]
    fn test_parse_invite_invalid_url() {
        let result = BlindProfileManager::parse_invite("not-a-url");
        assert!(
            result.is_err(),
            "Invalid URL must fail parsing"
        );

        let result = BlindProfileManager::parse_invite("https://vurnchat.org/");
        assert!(
            result.is_err(),
            "URL without ?invite= must fail"
        );

        let result = BlindProfileManager::parse_invite("https://vurnchat.org/?invite=");
        // Empty invite param → base64 decode of empty string
        // The base64 crate returns an empty Vec on decode(""), which fails
        // our length check (data.len() < 4)
        assert!(result.is_err(), "Empty invite must fail");
    }
}
