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
//!   any server round-trip. Pack session_hash + public_key into a base64url
//!   invite URL and render as QR SVG.

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
    /// | `encrypted_blob` | variable | `AES-256-GCM(public_key)` keyed by `HMAC-SHA256(lowercase(username), "VURN_PROFILE_ENC")` |
    ///
    /// The caller should send both to the server. The server stores the blob
    /// at the index but cannot read it or recover the username from it.
    pub fn prepare_registration(
        username: &str,
        public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let normalized = username.to_lowercase();

        // ── Derive search index (sent to server as lookup key) ──
        let search_index = hmac_sha256(normalized.as_bytes(), VURN_SEARCH_SALT)?;

        // ── Derive encryption key (NEVER sent to server) ──
        let enc_key = derive_encryption_key(&normalized)?;

        // ── Encrypt public key with AES-256-GCM ──
        let blob = VurnCipher::encrypt_symmetric(&enc_key, public_key);

        Ok((search_index, blob))
    }

    /// Resolves a username against an encrypted profile blob.
    ///
    /// Returns the public key if the username is correct. Returns an error
    /// if the username is wrong or the data is corrupted — AES-GCM
    /// authentication will fail, so the server does not need to verify
    /// anything.
    ///
    /// Since the encryption key is derived from the username, each username
    /// produces a different key. Trying username "Alice" against a blob that
    /// was registered under "Bob" will produce garbage and AES-GCM will reject it.
    pub fn resolve_profile(
        search_username: &str,
        encrypted_blob: &[u8],
    ) -> Result<Vec<u8>, String> {
        let normalized = search_username.to_lowercase();

        // Derive the same encryption key used during registration
        let enc_key = derive_encryption_key(&normalized)?;

        // Decrypt — if username is wrong, AES-GCM auth tag won't match
        let public_key = VurnCipher::decrypt_symmetric(&enc_key, encrypted_blob)?;

        Ok(public_key)
    }

    /// Generates an invite link containing session hash + public key.
    ///
    /// Packed format:
    /// ```text
    /// [2 bytes: session_hash_len (u16 LE)]
    /// [session_hash bytes]
    /// [2 bytes: public_key_len (u16 LE)]
    /// [public_key bytes]
    /// ```
    /// Then base64url-encoded without padding.
    ///
    /// Example output:
    /// ```text
    /// https://vurnchat.org/?invite=ZXhhbXBsZV9kYXRh...
    /// ```
    ///
    /// This link can be shared in any chat or rendered as a QR code.
    /// Scanning it adds the contact **without any server round-trip**.
    pub fn generate_invite(session_hash: &[u8], public_key: &[u8]) -> String {
        let mut data = Vec::with_capacity(4 + session_hash.len() + public_key.len());
        data.extend_from_slice(&(session_hash.len() as u16).to_le_bytes());
        data.extend_from_slice(session_hash);
        data.extend_from_slice(&(public_key.len() as u16).to_le_bytes());
        data.extend_from_slice(public_key);

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data);
        format!("https://vurnchat.org/?invite={}", encoded)
    }

    /// Parses an invite URL back into session hash and public key.
    ///
    /// The inverse of [`generate_invite`](Self::generate_invite).
    /// Extracts the base64url data from `?invite=...`, decodes it,
    /// and unpacks the binary fields.
    pub fn parse_invite(invite_url: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
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

        // Parse public key length
        let pk_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let total = offset + 2 + pk_len;

        if data.len() < total {
            return Err(format!(
                "Invite data truncated: expected {} bytes for public key, got {}",
                pk_len,
                data.len() - offset - 2
            ));
        }

        let session_hash = data[2..offset].to_vec();
        let public_key = data[offset + 2..total].to_vec();

        Ok((session_hash, public_key))
    }

    /// Generates an SVG QR code for the invite URL.
    ///
    /// Returns a complete `<svg>` XML string suitable for direct injection
    /// into HTML. The QR code encodes the invite URL; scanning it extracts
    /// the session hash and public key without any server round-trip.
    pub fn generate_invite_qr(session_hash: &[u8], public_key: &[u8]) -> Result<String, String> {
        let invite_url = Self::generate_invite(session_hash, public_key);

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

        // Alice registers her username
        let (index, blob) =
            BlindProfileManager::prepare_registration(username, &pk).expect("prepare should succeed");

        // Search index is 32 bytes (SHA-256 output)
        assert_eq!(index.len(), 32, "Search index must be 32 bytes");

        // Bob resolves the username
        let resolved_pk =
            BlindProfileManager::resolve_profile(username, &blob).expect("resolve should succeed");

        assert_eq!(resolved_pk, pk, "Resolved public key must match original");
    }

    #[test]
    fn test_wrong_username_fails_resolve() {
        let (pk, _sk) = VurnCipher::generate_keypair();

        // Register under "Alice"
        let (_index, blob) =
            BlindProfileManager::prepare_registration("Alice", &pk).expect("prepare");

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

        // Register as "Alice"
        let (_index, blob) =
            BlindProfileManager::prepare_registration("Alice", &pk).expect("prepare");

        // Resolve as "alice" (lowercase)
        let resolved =
            BlindProfileManager::resolve_profile("alice", &blob).expect("case-insensitive resolve");

        assert_eq!(resolved, pk, "Username lookup must be case-insensitive");
    }

    #[test]
    fn test_different_usernames_different_indices() {
        let (pk, _sk) = VurnCipher::generate_keypair();

        let (index1, _) =
            BlindProfileManager::prepare_registration("Alice", &pk).expect("prepare Alice");
        let (index2, _) =
            BlindProfileManager::prepare_registration("Bob", &pk).expect("prepare Bob");

        assert_ne!(
            index1, index2,
            "Different usernames must produce different search indices"
        );
    }

    #[test]
    fn test_search_index_is_hmac_not_hash() {
        // Same username must produce the same search index (deterministic)
        let (pk, _sk) = VurnCipher::generate_keypair();

        let (index1, _) =
            BlindProfileManager::prepare_registration("Charlie", &pk).expect("1st");
        let (index2, _) =
            BlindProfileManager::prepare_registration("Charlie", &pk).expect("2nd");

        assert_eq!(
            index1, index2,
            "Same username must produce the same search index"
        );
    }

    #[test]
    fn test_invite_roundtrip() {
        let (pk_alice, _) = VurnCipher::generate_keypair();
        let hash_alice = VurnCipher::hash_public_key(&pk_alice);

        // Generate invite
        let invite = BlindProfileManager::generate_invite(&hash_alice, &pk_alice);

        // Must be a valid URL
        assert!(
            invite.starts_with("https://vurnchat.org/?invite="),
            "Invite must be a proper URL"
        );
        assert!(invite.len() > 50, "Invite must contain encoded data");

        // Parse invite
        let (parsed_hash, parsed_pk) =
            BlindProfileManager::parse_invite(&invite).expect("parse should succeed");

        assert_eq!(parsed_hash, hash_alice, "Session hash must survive round-trip");
        assert_eq!(parsed_pk, pk_alice, "Public key must survive round-trip");
    }

    #[test]
    fn test_invite_tampered_fails() {
        let (pk, _) = VurnCipher::generate_keypair();
        let hash = VurnCipher::hash_public_key(&pk);

        let invite = BlindProfileManager::generate_invite(&hash, &pk);

        // Parse original to get reference
        let (orig_hash, orig_pk) =
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
            if let Ok((mod_hash, mod_pk)) = BlindProfileManager::parse_invite(&modified) {
                // If it parsed, the data must be different from the original
                assert!(
                    mod_hash != orig_hash || mod_pk != orig_pk,
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
        let hash_alice = VurnCipher::hash_public_key(&pk_alice);

        // Alice sends invite → Bob receives (no server involved)
        let invite = BlindProfileManager::generate_invite(&hash_alice, &pk_alice);

        // Bob gets the invite URL (e.g., scanned from QR or pasted in chat)
        let (received_hash, received_pk) =
            BlindProfileManager::parse_invite(&invite).expect("Bob parses invite");

        assert_eq!(received_hash, hash_alice, "Bob gets Alice's session hash");
        assert_eq!(received_pk, pk_alice, "Bob gets Alice's public key");

        // Bob encrypts a message for Alice using Alice's public key
        let msg = b"Hi Alice! No server needed to find you.";
        let encrypted = VurnCipher::encrypt(&received_pk, msg)
            .expect("Bob encrypts for Alice");

        // Alice decrypts with her own secret key (received via invite)
        let decrypted = VurnCipher::decrypt(&sk_alice, &encrypted)
            .expect("Alice decrypts the message Bob sent");

        assert_eq!(decrypted, msg, "Alice gets the correct plaintext");
    }

    #[test]
    fn test_invite_qr_generates_svg() {
        let (pk, _) = VurnCipher::generate_keypair();
        let hash = VurnCipher::hash_public_key(&pk);

        let svg = BlindProfileManager::generate_invite_qr(&hash, &pk)
            .expect("QR generation should succeed");

        // Must be valid SVG — qrcode crate may include XML declaration
        // before the <svg> element, so check for svg tag more flexibly
        assert!(svg.contains("<svg"), "QR must contain an SVG element, got: {:.100}", svg);
        assert!(svg.contains("xmlns"), "SVG must have xmlns attribute");
        assert!(svg.contains("</svg>"), "SVG must close properly");
        assert!(svg.len() > 500, "QR SVG should have substantial content, got {} bytes", svg.len());
    }

    #[test]
    fn test_different_usernames_different_blobs_same_key() {
        let (pk, _sk) = VurnCipher::generate_keypair();

        // Same public key, different usernames → different blobs
        let (_, blob1) =
            BlindProfileManager::prepare_registration("Alice", &pk).expect("Alice");
        let (_, blob2) =
            BlindProfileManager::prepare_registration("Bob", &pk).expect("Bob");

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
