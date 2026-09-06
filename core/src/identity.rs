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

use crate::{signing, VurnCipher};
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

// ── v0.9 identity bundle (forward-secrecy bootstrap material) ────────

/// Wire-format version byte of the v0.9 identity bundle.
const IDENTITY_V9_VERSION: u8 = 0x09;

/// X25519 public key size.
const X25519_PK_LEN: usize = 32;
/// ML-KEM-1024 public key size (matches `ratchet::KEM_PK_LEN`).
const KEM_PK_LEN: usize = 1568;

/// Full public identity of a user, as carried by the v0.9 profile blob,
/// invite links, and contact records. Everything needed to bootstrap a
/// ratchet session with this identity (see `RATCHET.md` §1):
///
/// | Key | Algorithm | Purpose |
/// |---|---|---|
/// | `ik_kem` | ML-KEM-1024 static pk | legacy compatibility; second KEM input to bootstrap |
/// | `ik_x`   | X25519 static pk | DH identity for the bootstrap + ratchet root |
/// | `sig_pk` | ML-DSA-87 pk | sender authentication (v0.7) |
/// | `spk_kem` | ML-KEM-1024 signed prekey pk | PQXDH-lite KEM input for session init |
/// | `spk_x`   | X25519 signed prekey pk | X3DH-lite DH input for session init |
/// | `spk_sig` | ML-DSA-87 signature over `spk_kem ‖ spk_x` | binds the prekey to the identity |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBundle {
    pub ik_kem: Vec<u8>,
    pub ik_x: Vec<u8>,
    pub sig_pk: Vec<u8>,
    pub spk_kem: Vec<u8>,
    pub spk_x: Vec<u8>,
    pub spk_sig: Vec<u8>,
}

impl IdentityBundle {
    /// Whether two bundles represent the **same identity**: identical static
    /// identity keys (`ik_kem`, `ik_x`, `sig_pk`). The signed prekey is
    /// *rotatable* and may legitimately differ between two bundles of the
    /// same user (RATCHET.md §1), so it is excluded from the comparison.
    pub fn same_identity(&self, other: &IdentityBundle) -> bool {
        self.ik_kem == other.ik_kem && self.ik_x == other.ik_x && self.sig_pk == other.sig_pk
    }

    /// Serializes the bundle. All component sizes are fixed by the algorithm
    /// constants, so the wire format needs no per-field length prefixes:
    ///
    /// ```text
    /// [1B version 0x09]
    /// [1568B ik_kem][32B ik_x][2592B sig_pk]
    /// [1568B spk_kem][32B spk_x][4627B spk_sig]
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 * KEM_PK_LEN + 2 * X25519_PK_LEN + 2592 + 4627);
        out.push(IDENTITY_V9_VERSION);
        out.extend_from_slice(&self.ik_kem);
        out.extend_from_slice(&self.ik_x);
        out.extend_from_slice(&self.sig_pk);
        out.extend_from_slice(&self.spk_kem);
        out.extend_from_slice(&self.spk_x);
        out.extend_from_slice(&self.spk_sig);
        out
    }

    /// Parses a v0.9 bundle. Legacy v0.7 payloads (KEM + signing key only)
    /// are also accepted — the prekey fields come back empty — so a profile
    /// or invite from an older client degrades to "no prekey" instead of
    /// failing outright (Stage C decides how to treat that).
    pub fn decode(data: &[u8]) -> Result<IdentityBundle, String> {
        if data.is_empty() || data[0] != IDENTITY_V9_VERSION {
            // Legacy v0.7 identity: [2B kem_len][kem][2B sig_len][sig].
            let (ik_kem, sig_pk) = decode_identity(data)?;
            return Ok(IdentityBundle {
                ik_kem,
                ik_x: Vec::new(),
                sig_pk,
                spk_kem: Vec::new(),
                spk_x: Vec::new(),
                spk_sig: Vec::new(),
            });
        }

        let need = 1 + 2 * KEM_PK_LEN + 2 * X25519_PK_LEN + signing::PUBLIC_KEY_LEN
            + signing::SIGNATURE_LEN;
        if data.len() < need {
            return Err(format!(
                "v0.9 identity truncated: expected {} bytes, got {}",
                need,
                data.len()
            ));
        }
        let mut p = 1;
        let mut take = |n: usize| -> &[u8] {
            let s = &data[p..p + n];
            p += n;
            s
        };
        let ik_kem = take(KEM_PK_LEN).to_vec();
        let ik_x = take(X25519_PK_LEN).to_vec();
        let sig_pk = take(signing::PUBLIC_KEY_LEN).to_vec();
        let spk_kem = take(KEM_PK_LEN).to_vec();
        let spk_x = take(X25519_PK_LEN).to_vec();
        let spk_sig = take(signing::SIGNATURE_LEN).to_vec();
        Ok(IdentityBundle {
            ik_kem,
            ik_x,
            sig_pk,
            spk_kem,
            spk_x,
            spk_sig,
        })
    }

    /// True when the bundle carries all v0.9 material (X25519 identity +
    /// signed prekey + prekey signature). Legacy v0.7-derived bundles are
    /// incomplete.
    pub fn is_v9(&self) -> bool {
        !self.ik_x.is_empty()
            && !self.spk_kem.is_empty()
            && !self.spk_x.is_empty()
            && !self.spk_sig.is_empty()
    }

    /// Verifies the prekey signature against the identity signing key:
    /// `spk_sig` must be a valid ML-DSA signature by `sig_pk` over
    /// `spk_kem ‖ spk_x`. This is what prevents an attacker from substituting
    /// their own prekey into a victim's profile.
    pub fn verify_prekey(&self) -> Result<(), String> {
        if !self.is_v9() {
            return Err("identity has no signed prekey".to_string());
        }
        let mut to_sign = Vec::with_capacity(self.spk_kem.len() + self.spk_x.len());
        to_sign.extend_from_slice(&self.spk_kem);
        to_sign.extend_from_slice(&self.spk_x);
        signing::verify_raw(&self.sig_pk, &to_sign, &self.spk_sig)
            .map_err(|_| "signed prekey signature does not verify".to_string())
    }
}

/// Generates a fresh signed-prekey pair for the given identity keys and
/// returns the full v0.9 bundle.
///
/// The signed prekey is **rotatable**: call this again on re-registration or
/// prekey rotation and re-publish the bundle. The signature binds the new
/// prekey to the (unchanged) identity signing key.
pub fn build_identity_bundle(
    ik_kem: Vec<u8>,
    ik_x: Vec<u8>,
    sig_pk: Vec<u8>,
    sig_sk: &[u8],
) -> Result<IdentityBundle, String> {
    let (spk_kem, _spk_kem_sk) = VurnCipher::generate_keypair();
    let (spk_x_bytes, _spk_x_sk) = crate::ratchet::x25519_keypair();
    let spk_x = spk_x_bytes.to_vec();

    let mut to_sign = Vec::with_capacity(spk_kem.len() + spk_x.len());
    to_sign.extend_from_slice(&spk_kem);
    to_sign.extend_from_slice(&spk_x);
    // The signature covers the raw prekey pair; it is carried in the bundle
    // as a raw ML-DSA signature (no payload framing).
    let spk_sig = signing::sign_raw(sig_sk, &to_sign)?;

    Ok(IdentityBundle {
        ik_kem,
        ik_x,
        sig_pk,
        spk_kem,
        spk_x,
        spk_sig,
    })
}

/// Result of rotating a signed prekey: the new public bundle **plus** the
/// new secret halves (so the client can persist them for responder-side
/// decapsulation of future inits).
pub struct RotatedPrekey {
    /// The new public bundle with the fresh signed prekey.
    pub bundle: IdentityBundle,
    /// Fresh ML-KEM-1024 signed-prekey secret key.
    pub spk_kem_sk: Vec<u8>,
    /// Fresh X25519 signed-prekey secret key.
    pub spk_x_sk: Vec<u8>,
}

/// Rotates the signed prekey of an existing identity: the static identity
/// keys (`ik_kem`, `ik_x`, `sig_pk`) are unchanged, a fresh `spk_kem`/`spk_x`
/// pair is generated and bound to the identity by a new `spk_sig` from the
/// *same* identity ML-DSA key. Callers re-publish the returned bundle (e.g.
/// via the server's profile-update opcode) and keep the previous prekey
/// secrets until in-flight sessions that used them are closed.
pub fn rotate_signed_prekey(
    ik_kem: Vec<u8>,
    ik_x: Vec<u8>,
    sig_pk: Vec<u8>,
    sig_sk: &[u8],
) -> Result<RotatedPrekey, String> {
    let (spk_kem, spk_kem_sk) = VurnCipher::generate_keypair();
    let (spk_x, spk_x_sk) = crate::ratchet::x25519_keypair();

    let mut to_sign = Vec::with_capacity(spk_kem.len() + spk_x.len());
    to_sign.extend_from_slice(&spk_kem);
    to_sign.extend_from_slice(&spk_x);
    let spk_sig = signing::sign_raw(sig_sk, &to_sign)?;

    Ok(RotatedPrekey {
        bundle: IdentityBundle {
            ik_kem,
            ik_x,
            sig_pk,
            spk_kem: spk_kem.to_vec(),
            spk_x: spk_x.to_vec(),
            spk_sig,
        },
        spk_kem_sk,
        spk_x_sk: spk_x_sk.to_vec(),
    })
}

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

    /// Prepares a **v0.9** registration: the profile blob carries the full
    /// identity bundle (ML-KEM + X25519 identity, ML-DSA signing key, signed
    /// prekey pair + signature), so a resolver can bootstrap a ratchet
    /// session from the username alone. Same blind-search properties as
    /// [`prepare_registration`](Self::prepare_registration).
    pub fn prepare_registration_v9(
        username: &str,
        bundle: &IdentityBundle,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let normalized = username.to_lowercase();
        let search_index = hmac_sha256(normalized.as_bytes(), VURN_SEARCH_SALT)?;
        let enc_key = derive_encryption_key(&normalized)?;
        let blob = VurnCipher::encrypt_symmetric(&enc_key, &bundle.encode());
        Ok((search_index, blob))
    }

    /// Resolves a **v0.9** profile blob into an [`IdentityBundle`]. Blobs
    /// registered by older clients (v0.7: KEM + signing key only) resolve too,
    /// with the prekey fields empty — Stage C decides how to treat a contact
    /// that cannot bootstrap a ratchet.
    pub fn resolve_profile_v9(
        search_username: &str,
        encrypted_blob: &[u8],
    ) -> Result<IdentityBundle, String> {
        let normalized = search_username.to_lowercase();
        let enc_key = derive_encryption_key(&normalized)?;
        let identity = VurnCipher::decrypt_symmetric(&enc_key, encrypted_blob)?;
        IdentityBundle::decode(&identity)
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

    /// Generates a **v0.9** invite: the packed data carries the full identity
    /// bundle instead of just the KEM + signing keys, so the invitee can
    /// bootstrap a ratchet session directly from the link.
    pub fn generate_invite_v9(
        session_hash: &[u8],
        bundle: &IdentityBundle,
        base_url: &str,
    ) -> String {
        let identity = bundle.encode();
        let mut data = Vec::with_capacity(2 + session_hash.len() + identity.len());
        data.extend_from_slice(&(session_hash.len() as u16).to_le_bytes());
        data.extend_from_slice(session_hash);
        data.extend_from_slice(&identity);

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data);
        let base = base_url.trim_end_matches('/');
        format!("{}/?invite={}", base, encoded)
    }

    /// Parses a **v0.9** invite URL into `(session_hash, IdentityBundle)`.
    /// Legacy v0.7 invites (KEM + signing key only, or even pre-signature
    /// KEM-only) parse into a bundle with empty prekey/identity fields.
    pub fn parse_invite_v9(invite_url: &str) -> Result<(Vec<u8>, IdentityBundle), String> {
        let (session_hash, identity) = Self::parse_invite_raw(invite_url)?;
        let bundle = IdentityBundle::decode(&identity)?;
        Ok((session_hash, bundle))
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
        let (session_hash, identity) = Self::parse_invite_raw(invite_url)?;
        match decode_identity(&identity) {
            Ok((public_key, signing_public_key)) => {
                Ok((session_hash, public_key, signing_public_key))
            }
            Err(_) if identity.len() >= 2 => {
                // Pre-signature legacy invite: bare KEM key only
                // ([2B kem_len][kem_pk]). Degrade to an unauthenticated
                // contact instead of failing outright.
                let kem_len = u16::from_le_bytes([identity[0], identity[1]]) as usize;
                if identity.len() == 2 + kem_len {
                    Ok((session_hash, identity[2..].to_vec(), Vec::new()))
                } else {
                    Err("Identity payload truncated: missing signing key header".to_string())
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Base64-decodes an invite URL and splits it into `(session_hash,
    /// identity_payload)` without interpreting the identity format.
    fn parse_invite_raw(invite_url: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
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

        let sh_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let offset = 2 + sh_len;
        if data.len() < offset + 2 {
            return Err("Invite data truncated: missing identity payload".to_string());
        }

        Ok((data[2..offset].to_vec(), data[offset..].to_vec()))
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

    // ── v0.9 identity bundle ────────────────────────────────────────────

    fn v9_bundle() -> (IdentityBundle, Vec<u8>) {
        // Returns the bundle plus the identity signing secret key.
        let (ik_kem, _) = VurnCipher::generate_keypair();
        let (ik_x, _) = crate::ratchet::x25519_keypair();
        let (sig_pk, sig_sk) = crate::signing::generate_signing_keypair();
        let bundle = build_identity_bundle(ik_kem, ik_x.to_vec(), sig_pk, &sig_sk).unwrap();
        (bundle, sig_sk)
    }

    #[test]
    fn test_v9_bundle_encode_decode_roundtrip() {
        let (bundle, _sig_sk) = v9_bundle();
        assert!(bundle.is_v9(), "built bundle must be a full v0.9 identity");
        assert_eq!(bundle.ik_x.len(), 32, "X25519 identity key must be 32 bytes");
        assert_eq!(bundle.spk_kem.len(), KEM_PK_LEN);
        assert_eq!(bundle.spk_x.len(), 32);

        let bytes = bundle.encode();
        let decoded = IdentityBundle::decode(&bytes).expect("decode roundtrip");
        assert_eq!(decoded, bundle);
        assert!(decoded.is_v9());
        assert!(decoded.verify_prekey().is_ok(), "roundtripped prekey must verify");
    }

    #[test]
    fn test_v9_bundle_prekey_signature_binds() {
        let (bundle, _) = v9_bundle();
        assert!(bundle.verify_prekey().is_ok());

        // Tampering with the prekey (e.g. an attacker swapping in their own
        // prekey in a profile) must break the signature check.
        let mut evil = bundle.clone();
        let (evil_kem, _) = VurnCipher::generate_keypair();
        evil.spk_kem = evil_kem;
        assert!(evil.verify_prekey().is_err(), "swapped prekey must fail verification");

        let mut evil_x = bundle.clone();
        let (evil_x_pk, _) = crate::ratchet::x25519_keypair();
        evil_x.spk_x = evil_x_pk.to_vec();
        assert!(evil_x.verify_prekey().is_err(), "swapped X25519 prekey must fail");
    }

    #[test]
    fn test_v9_bundle_rejects_truncation() {
        let (bundle, _) = v9_bundle();
        let bytes = bundle.encode();
        assert!(IdentityBundle::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(IdentityBundle::decode(&[]).is_err());
    }

    #[test]
    fn test_v9_bundle_decodes_legacy_v07_payload() {
        // A v0.7 identity payload (KEM + ML-DSA key, no v0.9 magic) must
        // decode into a bundle with empty prekey fields.
        let (ik_kem, _) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();
        let legacy = encode_identity(&ik_kem, &sig_pk);

        let bundle = IdentityBundle::decode(&legacy).expect("legacy payload must decode");
        assert_eq!(bundle.ik_kem, ik_kem);
        assert_eq!(bundle.sig_pk, sig_pk);
        assert!(!bundle.is_v9(), "legacy-derived bundle must be marked incomplete");
        assert!(bundle.verify_prekey().is_err());
    }

    #[test]
    fn test_v9_registration_resolve_roundtrip() {
        let (bundle, _) = v9_bundle();
        let (index, blob) =
            BlindProfileManager::prepare_registration_v9("Bob", &bundle).expect("register v9");
        assert_eq!(index.len(), 32);

        let resolved =
            BlindProfileManager::resolve_profile_v9("bob", &blob).expect("resolve v9");
        assert_eq!(resolved, bundle);
        assert!(resolved.verify_prekey().is_ok());

        // Wrong username must fail (AES-GCM auth).
        assert!(BlindProfileManager::resolve_profile_v9("Eve", &blob).is_err());
    }

    #[test]
    fn test_v9_resolve_legacy_blob() {
        // Blobs registered by a v0.7 client (plain KEM + sig keys) must
        // resolve through the v9 API into an incomplete bundle.
        let (pk, _) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();
        let (_index, blob) =
            BlindProfileManager::prepare_registration("Carol", &pk, &sig_pk).expect("legacy register");

        let resolved =
            BlindProfileManager::resolve_profile_v9("Carol", &blob).expect("v9 resolve of legacy blob");
        assert_eq!(resolved.ik_kem, pk);
        assert_eq!(resolved.sig_pk, sig_pk);
        assert!(!resolved.is_v9());
    }

    #[test]
    fn test_v9_invite_roundtrip() {
        let (bundle, _) = v9_bundle();
        let hash = vec![0x42u8; 32];
        let invite =
            BlindProfileManager::generate_invite_v9(&hash, &bundle, "https://vurnchat.org");
        assert!(invite.starts_with("https://vurnchat.org/?invite="));

        let (parsed_hash, parsed_bundle) =
            BlindProfileManager::parse_invite_v9(&invite).expect("parse v9 invite");
        assert_eq!(parsed_hash, hash);
        assert_eq!(parsed_bundle, bundle);
        assert!(parsed_bundle.verify_prekey().is_ok());
    }

    #[test]
    fn test_v9_parse_legacy_invite() {
        // v0.7 invite (KEM + sig keys inside) must parse via the v9 API into
        // an incomplete bundle.
        let (pk, _) = VurnCipher::generate_keypair();
        let (sig_pk, _) = crate::signing::generate_signing_keypair();
        let hash = VurnCipher::hash_public_key(&pk);
        let invite = BlindProfileManager::generate_invite(&hash, &pk, &sig_pk, "https://vurnchat.org");

        let (parsed_hash, bundle) =
            BlindProfileManager::parse_invite_v9(&invite).expect("v9 parse of legacy invite");
        assert_eq!(parsed_hash, hash);
        assert_eq!(bundle.ik_kem, pk);
        assert_eq!(bundle.sig_pk, sig_pk);
        assert!(!bundle.is_v9());
    }

    // ── Prekey rotation ────────────────────────────────────────────────

    #[test]
    fn test_rotate_prekey_keeps_identity_and_binds() {
        // Rotation replaces the prekey but keeps ik_kem/ik_x/sig_pk and the
        // new prekey is bound to the *same* identity signing key.
        let (bundle, sig_sk) = v9_bundle();
        let old_bundle = bundle.clone();

        let rotated = rotate_signed_prekey(
            bundle.ik_kem.clone(),
            bundle.ik_x.clone(),
            bundle.sig_pk.clone(),
            &sig_sk,
        )
        .expect("rotate");

        // Same identity, different prekey.
        assert!(bundle.same_identity(&rotated.bundle));
        assert_eq!(bundle.sig_pk, rotated.bundle.sig_pk);
        assert_eq!(bundle.ik_x, rotated.bundle.ik_x);
        assert_eq!(bundle.ik_kem, rotated.bundle.ik_kem);
        assert_ne!(bundle.spk_kem, rotated.bundle.spk_kem, "prekey must change");
        assert_ne!(bundle.spk_x, rotated.bundle.spk_x, "prekey must change");
        assert_ne!(bundle.spk_sig, rotated.bundle.spk_sig);

        // New prekey verifies against the unchanged identity key.
        assert!(rotated.bundle.verify_prekey().is_ok());
        assert!(rotated.bundle.is_v9());

        // Secret halves returned for responder persistence.
        assert_eq!(rotated.spk_kem_sk.len(), crate::ratchet::KEM_SK_LEN);
        assert_eq!(rotated.spk_x_sk.len(), 32);

        // Old bundle's prekey still verifies (it was validly signed before),
        // and the two bundles are distinct encodings of the same identity.
        assert!(old_bundle.verify_prekey().is_ok());
        assert_ne!(bundle.encode(), rotated.bundle.encode());
    }

    #[test]
    fn test_same_identity_ignores_prekey() {
        let (bundle, sig_sk) = v9_bundle();
        let rotated = rotate_signed_prekey(
            bundle.ik_kem.clone(),
            bundle.ik_x.clone(),
            bundle.sig_pk.clone(),
            &sig_sk,
        )
        .unwrap();

        assert!(bundle.same_identity(&rotated.bundle));

        // A different identity must NOT compare equal.
        let (other, _) = v9_bundle();
        assert!(!bundle.same_identity(&other));

        // Rotated bundle still routes to the same identity hash (ik_kem unchanged).
        assert_eq!(
            VurnCipher::hash_public_key(&bundle.ik_kem),
            VurnCipher::hash_public_key(&rotated.bundle.ik_kem)
        );
    }

    #[test]
    fn test_rotated_bundle_resolves_under_same_username() {
        // The rotation flow re-publishes the *new* bundle under the same
        // username; a resolver must get the rotated prekey, still bound to
        // the same identity.
        let (bundle, sig_sk) = v9_bundle();
        let rotated = rotate_signed_prekey(
            bundle.ik_kem.clone(),
            bundle.ik_x.clone(),
            bundle.sig_pk.clone(),
            &sig_sk,
        )
        .unwrap();

        let (_idx1, _blob1) =
            BlindProfileManager::prepare_registration_v9("PrekeyBob", &bundle).unwrap();
        let (_idx2, blob2) =
            BlindProfileManager::prepare_registration_v9("PrekeyBob", &rotated.bundle).unwrap();
        // Same username → same search index, different blob.
        assert_eq!(idx_to_hex(&_idx1), idx_to_hex(&_idx2));

        let resolved =
            BlindProfileManager::resolve_profile_v9("PrekeyBob", &blob2).expect("resolve");
        assert_eq!(resolved, rotated.bundle);
        assert!(resolved.verify_prekey().is_ok());
        assert!(bundle.same_identity(&resolved));
    }

    fn idx_to_hex(idx: &[u8]) -> String {
        idx.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
