//! # PQXDH-lite session bootstrap (RATCHET.md §5)
//!
//! Establishes the shared root key and session id for a hybrid ratchet
//! session from a peer's v0.9 [`IdentityBundle`], with no server-side state.
//!
//! The initiator (Alice) mixes three X25519 DH values and two fresh ML-KEM
//! encapsulations into the root:
//!
//! ```text
//! dh1  = X25519(ik_x_A, spk_x_B)   (static → signed prekey)
//! dh2  = X25519(ek_x_A, ik_x_B)    (ephemeral → static)
//! dh3  = X25519(ek_x_A, spk_x_B)   (ephemeral → signed prekey)
//! kem1 = KEM.Encaps(spk_kem_B)     (fresh PQ secret to the signed prekey)
//! kem2 = KEM.Encaps(ik_kem_B)      (fresh PQ secret to the static key)
//! root = HKDF-SHA256(dh1 ‖ dh2 ‖ dh3 ‖ kem1 ‖ kem2, info = "vurn-init")
//! ```
//!
//! The responder reproduces the identical value with its secret keys and the
//! ciphertexts carried in the init envelope. The order of the five inputs is
//! pinned here and must never change (both sides concatenate in the same
//! order).
//!
//! The session id is `SHA-256` of the two X25519 identity public keys in
//! sorted (lexicographic) order, so both sides derive the same value
//! regardless of who initiates. It is bound into every AEAD header by the
//! ratchet engine.
//!
//! ## Init envelope (wire format)
//!
//! The first message of a session travels as:
//!
//! ```text
//! [2B bundle_len][bundle (IdentityBundle::encode)] [1568B ct_spk] [1568B ct_ik] [ratchet package]
//! ```
//!
//! `ct_spk` / `ct_ik` are the encapsulations produced by
//! [`initiator_bootstrap`]; the package is the ratchet engine's output for
//! the first plaintext message.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::identity::IdentityBundle;
use crate::ratchet::{kem_decapsulate, kem_encapsulate, x25519_shared, KEM_CT_LEN};

type HmacSha256 = Hmac<Sha256>;

/// HKDF info string for the bootstrap root (pinned in RATCHET.md §5).
pub const INIT_INFO: &[u8] = b"vurn-init";

fn hmac256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// HKDF-SHA256 (RFC 5869) with an empty salt and a single 32-byte output
/// block (the bootstrap root).
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC(salt = "", ikm)
    let prk = hmac256(&[], ikm);
    // Expand (T1): OKM = HMAC(PRK, info ‖ 0x01)
    let mut data = Vec::with_capacity(info.len() + 1);
    data.extend_from_slice(info);
    data.push(0x01);
    hmac256(&prk, &data)
}

/// Session id: SHA-256 of the two static X25519 identity keys in sorted
/// order — identical on both sides, independent of who initiates.
fn session_id_from(a_ik_x: &[u8], b_ik_x: &[u8]) -> [u8; 32] {
    let (first, second) = if a_ik_x <= b_ik_x {
        (a_ik_x, b_ik_x)
    } else {
        (b_ik_x, a_ik_x)
    };
    let mut h = Sha256::new();
    h.update(first);
    h.update(second);
    h.finalize().into()
}

fn arr32(v: &[u8]) -> Result<[u8; 32], String> {
    v.try_into().map_err(|_| "expected 32-byte key".to_string())
}

/// Output of the initiator-side bootstrap: everything needed to start the
/// ratchet session and to build the init envelope for the wire.
pub struct InitiatorOutput {
    /// Shared root key for [`crate::ratchet::SessionStart`].
    pub root: [u8; 32],
    /// Shared session id (bound into every AEAD header).
    pub session_id: [u8; 32],
    /// Encapsulation to the peer's signed-prekey KEM key (travels in the init).
    pub ct_spk: Vec<u8>,
    /// Encapsulation to the peer's static KEM key (travels in the init).
    pub ct_ik: Vec<u8>,
}

/// Computes the bootstrap root and session id from the **initiator** side.
///
/// `ik_x` is the initiator's static X25519 identity keypair, `ek_x` her
/// fresh ephemeral X25519 keypair (its public half is advertised in the
/// first ratchet package header), and `peer` the responder's v0.9 bundle
/// (from a username lookup or invite — its prekey signature is verified
/// here).
pub fn initiator_bootstrap(
    ik_x: ([u8; 32], [u8; 32]),
    ek_x: ([u8; 32], [u8; 32]),
    peer: &IdentityBundle,
) -> Result<InitiatorOutput, String> {
    if !peer.is_v9() {
        return Err("peer identity has no signed prekey — cannot bootstrap a ratchet".to_string());
    }
    peer.verify_prekey()?;

    let spk_x = arr32(&peer.spk_x)?;
    let ik_x_peer = arr32(&peer.ik_x)?;
    let dh1 = x25519_shared(&ik_x.1, &spk_x).map_err(|e| format!("dh1: {:?}", e))?;
    let dh2 = x25519_shared(&ek_x.1, &ik_x_peer).map_err(|e| format!("dh2: {:?}", e))?;
    let dh3 = x25519_shared(&ek_x.1, &spk_x).map_err(|e| format!("dh3: {:?}", e))?;
    let (ct_spk, ss_spk) = kem_encapsulate(&peer.spk_kem).map_err(|e| format!("kem1: {:?}", e))?;
    let (ct_ik, ss_ik) = kem_encapsulate(&peer.ik_kem).map_err(|e| format!("kem2: {:?}", e))?;

    let mut ikm = Vec::with_capacity(32 * 3 + ss_spk.len() + ss_ik.len());
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    ikm.extend_from_slice(&ss_spk);
    ikm.extend_from_slice(&ss_ik);

    let root = hkdf_sha256(&ikm, INIT_INFO);
    let session_id = session_id_from(&ik_x.0, &peer.ik_x);
    Ok(InitiatorOutput {
        root,
        session_id,
        ct_spk,
        ct_ik,
    })
}

/// Computes the bootstrap root and session id from the **responder** side.
///
/// `ik_x` is the responder's static X25519 identity keypair, `spk_x` his
/// signed-prekey X25519 keypair, `ik_kem_sk` / `spk_kem_sk` the secret keys
/// for the KEM ciphertexts, `peer` the *sender's* bundle (from the init
/// envelope, or from the stored contact record when they match), and
/// `ek_x_pub` the sender's ephemeral public key (extracted from the first
/// ratchet package header via [`crate::ratchet::package_sender_key`]).
pub fn responder_bootstrap(
    ik_x: ([u8; 32], [u8; 32]),
    spk_x: ([u8; 32], [u8; 32]),
    ik_kem_sk: &[u8],
    spk_kem_sk: &[u8],
    peer: &IdentityBundle,
    ek_x_pub: &[u8; 32],
    ct_spk: &[u8],
    ct_ik: &[u8],
) -> Result<([u8; 32], [u8; 32]), String> {
    if !peer.is_v9() {
        return Err("sender identity has no signed prekey".to_string());
    }
    peer.verify_prekey()?;

    let peer_ik_x = arr32(&peer.ik_x)?;
    // Same concatenation order as the initiator: dh1 ‖ dh2 ‖ dh3 ‖ kem1 ‖ kem2.
    let dh1 = x25519_shared(&spk_x.1, &peer_ik_x).map_err(|e| format!("dh1: {:?}", e))?;
    let dh2 = x25519_shared(&ik_x.1, ek_x_pub).map_err(|e| format!("dh2: {:?}", e))?;
    let dh3 = x25519_shared(&spk_x.1, ek_x_pub).map_err(|e| format!("dh3: {:?}", e))?;
    let ss_spk = kem_decapsulate(spk_kem_sk, ct_spk).map_err(|e| format!("kem1: {:?}", e))?;
    let ss_ik = kem_decapsulate(ik_kem_sk, ct_ik).map_err(|e| format!("kem2: {:?}", e))?;

    let mut ikm = Vec::with_capacity(32 * 3 + ss_spk.len() + ss_ik.len());
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    ikm.extend_from_slice(&ss_spk);
    ikm.extend_from_slice(&ss_ik);

    let root = hkdf_sha256(&ikm, INIT_INFO);
    let session_id = session_id_from(&peer.ik_x, &ik_x.0);
    Ok((root, session_id))
}

// ── Init envelope framing ────────────────────────────────────────────

/// Builds the init envelope for the wire: sender bundle + the two KEM
/// ciphertexts + the first ratchet package. The client prefixes a one-byte
/// message-type tag (0x03 = ratchet init) before putting this on the relay.
pub fn build_init_envelope(
    bundle: &IdentityBundle,
    ct_spk: &[u8],
    ct_ik: &[u8],
    package: &[u8],
) -> Vec<u8> {
    let enc = bundle.encode();
    let mut out = Vec::with_capacity(2 + enc.len() + ct_spk.len() + ct_ik.len() + package.len());
    out.extend_from_slice(&(enc.len() as u16).to_le_bytes());
    out.extend_from_slice(&enc);
    out.extend_from_slice(ct_spk);
    out.extend_from_slice(ct_ik);
    out.extend_from_slice(package);
    out
}

/// A parsed init envelope.
pub struct ParsedInit {
    /// The sender's identity bundle (TOFU material for unknown senders).
    pub bundle: IdentityBundle,
    /// Encapsulation to *our* signed-prekey KEM key.
    pub ct_spk: Vec<u8>,
    /// Encapsulation to *our* static KEM key.
    pub ct_ik: Vec<u8>,
    /// The first ratchet package (header ‖ AEAD ciphertext).
    pub package: Vec<u8>,
}

/// Parses an init envelope produced by [`build_init_envelope`].
pub fn parse_init_envelope(data: &[u8]) -> Result<ParsedInit, String> {
    if data.len() < 2 {
        return Err("init envelope truncated".to_string());
    }
    let bundle_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2usize;
    if data.len() < pos + bundle_len {
        return Err("init envelope truncated (bundle)".to_string());
    }
    let bundle = IdentityBundle::decode(&data[pos..pos + bundle_len])?;
    pos += bundle_len;
    if data.len() < pos + KEM_CT_LEN * 2 {
        return Err("init envelope truncated (kem ciphertexts)".to_string());
    }
    let ct_spk = data[pos..pos + KEM_CT_LEN].to_vec();
    pos += KEM_CT_LEN;
    let ct_ik = data[pos..pos + KEM_CT_LEN].to_vec();
    pos += KEM_CT_LEN;
    let package = data[pos..].to_vec();
    if package.is_empty() {
        return Err("init envelope missing ratchet package".to_string());
    }
    Ok(ParsedInit {
        bundle,
        ct_spk,
        ct_ik,
        package,
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::{
        package_sender_key, x25519_keypair, Session, SessionStart, KEM_PK_LEN, KEM_SK_LEN,
    };
    use crate::VurnCipher;

    /// A full v0.9 identity for one party (public bundle + secret keys).
    struct TestIdentity {
        bundle: IdentityBundle,
        ik_x: ([u8; 32], [u8; 32]),
        spk_x: ([u8; 32], [u8; 32]),
        spk_kem_sk: Vec<u8>,
        ik_kem_sk: Vec<u8>,
    }

    fn make_identity() -> TestIdentity {
        let (ik_kem_pk, ik_kem_sk) = VurnCipher::generate_keypair();
        let (ik_x_pub, ik_x_sk) = x25519_keypair();
        let (sig_pk, sig_sk) = crate::signing::generate_signing_keypair();
        let (spk_kem_pk, spk_kem_sk) = VurnCipher::generate_keypair();
        let (spk_x_pub, spk_x_sk) = x25519_keypair();
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&spk_kem_pk);
        to_sign.extend_from_slice(&spk_x_pub);
        let spk_sig = crate::signing::sign_raw(&sig_sk, &to_sign).unwrap();
        let bundle = IdentityBundle {
            ik_kem: ik_kem_pk,
            ik_x: ik_x_pub.to_vec(),
            sig_pk,
            spk_kem: spk_kem_pk,
            spk_x: spk_x_pub.to_vec(),
            spk_sig,
        };
        TestIdentity {
            bundle,
            ik_x: (ik_x_pub, ik_x_sk),
            spk_x: (spk_x_pub, spk_x_sk),
            spk_kem_sk,
            ik_kem_sk,
        }
    }

    /// Full two-party flow: Alice bootstraps, starts the initiator session,
    /// encrypts; Bob parses the envelope, bootstraps, starts the responder
    /// session, decrypts; then ping-pong continues.
    #[test]
    fn test_two_party_bootstrap_and_session() {
        let alice = make_identity();
        let bob = make_identity();

        // Alice initiates.
        let ek_x = x25519_keypair();
        let (ek_kem_pk, ek_kem_sk) = VurnCipher::generate_keypair();
        let init = initiator_bootstrap(alice.ik_x, ek_x, &bob.bundle).unwrap();
        let mut a_sess = Session::start_alice(SessionStart {
            root: init.root,
            session_id: init.session_id,
            our_dh: ek_x,
            peer_dh: Some(arr32(&bob.bundle.spk_x).unwrap()),
            our_kem: Some((ek_kem_pk, ek_kem_sk)),
        });

        let m1_plain = b"hello bob, this is the first ratchet message".to_vec();
        let m1_pkg = a_sess.encrypt(&m1_plain).unwrap();

        // Envelope over the wire.
        let env = build_init_envelope(&alice.bundle, &init.ct_spk, &init.ct_ik, &m1_pkg);
        let parsed = parse_init_envelope(&env).unwrap();
        assert_eq!(parsed.bundle, alice.bundle);
        assert_eq!(parsed.package, m1_pkg);

        // Bob receives.
        let ek_x_pub = package_sender_key(&parsed.package).unwrap();
        let (root, session_id) = responder_bootstrap(
            bob.ik_x,
            bob.spk_x,
            &bob.ik_kem_sk,
            &bob.spk_kem_sk,
            &parsed.bundle,
            &ek_x_pub,
            &parsed.ct_spk,
            &parsed.ct_ik,
        )
        .unwrap();
        assert_eq!(root, init.root);
        assert_eq!(session_id, init.session_id);

        let mut b_sess = Session::start_bob(SessionStart {
            root,
            session_id,
            our_dh: bob.spk_x,
            peer_dh: None,
            our_kem: None,
        });
        let got = b_sess.decrypt(&parsed.package).unwrap();
        assert_eq!(got, m1_plain);

        // Bob replies; Alice decrypts (crossed to a new chain both ways).
        let m2_plain = b"got it alice!".to_vec();
        let m2_pkg = b_sess.encrypt(&m2_plain).unwrap();
        let got2 = a_sess.decrypt(&m2_pkg).unwrap();
        assert_eq!(got2, m2_plain);

        let m3_plain = b"and a third from alice".to_vec();
        let m3_pkg = a_sess.encrypt(&m3_plain).unwrap();
        let got3 = b_sess.decrypt(&m3_pkg).unwrap();
        assert_eq!(got3, m3_plain);

        // Sessions serialize/restore mid-flow.
        let a_bytes = a_sess.to_bytes();
        let mut a2 = Session::from_bytes(&a_bytes).unwrap();
        let m4_plain = b"after reload".to_vec();
        let m4_pkg = a2.encrypt(&m4_plain).unwrap();
        let got4 = b_sess.decrypt(&m4_pkg).unwrap();
        assert_eq!(got4, m4_plain);
    }

    /// A tampered KEM ciphertext must produce a different root → the AEAD
    /// fails (an active MITM that swaps the envelope cannot decrypt without
    /// the encapsulated secrets).
    #[test]
    fn test_tampered_init_fails() {
        let alice = make_identity();
        let bob = make_identity();

        let ek_x = x25519_keypair();
        let init = initiator_bootstrap(alice.ik_x, ek_x, &bob.bundle).unwrap();
        let (ek_kem_pk, ek_kem_sk) = VurnCipher::generate_keypair();
        let mut a_sess = Session::start_alice(SessionStart {
            root: init.root,
            session_id: init.session_id,
            our_dh: ek_x,
            peer_dh: Some(arr32(&bob.bundle.spk_x).unwrap()),
            our_kem: Some((ek_kem_pk, ek_kem_sk)),
        });
        let m1_pkg = a_sess.encrypt(b"first").unwrap();
        let mut env = build_init_envelope(&alice.bundle, &init.ct_spk, &init.ct_ik, &m1_pkg);
        // Flip one byte in the spk ciphertext.
        let n = env.len();
        env[n - m1_pkg.len() - KEM_CT_LEN] ^= 0x01;

        let parsed = parse_init_envelope(&env).unwrap();
        let ek_x_pub = package_sender_key(&parsed.package).unwrap();
        let (root, _sid) = responder_bootstrap(
            bob.ik_x,
            bob.spk_x,
            &bob.ik_kem_sk,
            &bob.spk_kem_sk,
            &parsed.bundle,
            &ek_x_pub,
            &parsed.ct_spk,
            &parsed.ct_ik,
        )
        .unwrap();
        assert_ne!(root, init.root);

        let mut b_sess = Session::start_bob(SessionStart {
            root,
            session_id: init.session_id,
            our_dh: bob.spk_x,
            peer_dh: None,
            our_kem: None,
        });
        assert!(b_sess.decrypt(&parsed.package).is_err());
    }

    /// Session id is independent of who initiates (both orders give the same
    /// value for the same pair of identities).
    #[test]
    fn test_session_id_order_independent() {
        let alice = make_identity();
        let bob = make_identity();
        let a = session_id_from(&alice.ik_x.0, &bob.bundle.ik_x);
        let b = session_id_from(&bob.bundle.ik_x, &alice.ik_x.0);
        assert_eq!(a, b);
    }

    #[test]
    fn test_kem_constants_consistency() {
        // The bootstrap relies on these sizes being exact.
        assert_eq!(KEM_CT_LEN, 1568);
        assert_eq!(KEM_PK_LEN, 1568);
        assert_eq!(KEM_SK_LEN, 3168);
        // Envelope layout sanity: bundle + 2 KEM ciphertexts + package.
        let alice = make_identity();
        let bob = make_identity();
        let ek_x = x25519_keypair();
        let init = initiator_bootstrap(alice.ik_x, ek_x, &bob.bundle).unwrap();
        let env = build_init_envelope(&alice.bundle, &init.ct_spk, &init.ct_ik, b"pkg");
        assert_eq!(env.len(), 2 + alice.bundle.encode().len() + KEM_CT_LEN * 2 + 3);
    }
}