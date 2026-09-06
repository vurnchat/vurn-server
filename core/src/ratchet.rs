//! # Hybrid Ratchet engine (Stage A of the v0.9 forward-secrecy work)
//!
//! Self-contained, pure in-memory ratchet used by the messenger for
//! forward secrecy. See `RATCHET.md` (repo root) for the full protocol
//! spec and security analysis.
//!
//! Two layers:
//! - **X25519 double ratchet** (Signal structure): per-direction HMAC key
//!   chains, root key advanced by a DH ratchet each time the peer opens a
//!   new sending chain. Provides classical FS + post-compromise security.
//! - **ML-KEM-1024 mixing**: every message the sender can protect carries a
//!   fresh KEM encapsulation to the peer's currently advertised ML-KEM
//!   ratchet key; the resulting secret is mixed into the AEAD key.
//!
//! ## Delivery model
//!
//! The relay delivers messages per conversation in order, exactly once
//! (server-side watermark + Sled drain, v0.6.6), but the engine no longer
//! *relies* on it: a **skipped-message-key store** (Signal `MKSK`) lets a
//! receiver derive and retain message keys for the messages it jumps over
//! (within [`MAX_SKIP`] of a gap, keyed by the sending chain's DH key and
//! message number). Out-of-order messages — including stragglers of a
//! chain the peer already advanced past — decrypt from the store instead of
//! erroring, and loss only costs the lost messages themselves. A number
//! that is neither the expected next nor in the store stays a hard
//! `Err(OutOfOrder)` (duplicate/replay).
//!
//! ## Package layout
//!
//! ```text
//! msg := header ‖ AEAD-ciphertext
//! header :=
//!   1B  version (0x0A)
//!   1B  flags: 0x01 always (dh_pub), 0x02 kem advertisement,
//!              0x04 kem ciphertext present
//!   4B  pn (u32 LE, previous sending-chain length)
//!   4B  n (u32 LE, sending-chain message number)
//!   32B dh_pub         (sender's current X25519 ratchet public key)
//!   [1568B kem_pk]     (if 0x02 — sender advertises a fresh ML-KEM key)
//!   [1568B kem_ct]     (if 0x04 — fresh encapsulation to peer's kem_pk)
//! ```
//! AEAD: AES-256-GCM; AAD = `session_id ‖ header`. Keys are derived from
//! chain message keys and the per-message KEM secret (see KDF section).

use aes_gcm::{
    aead::{self, Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

type HmacSha256 = Hmac<Sha256>;
type MlKemEncapsKey = EncapsulationKey<MlKem1024Params>;
type MlKemDecapsKey = DecapsulationKey<MlKem1024Params>;

/// KEM public key size (ML-KEM-1024).
pub const KEM_PK_LEN: usize = 1568;
/// KEM secret key size.
pub const KEM_SK_LEN: usize = 3168;
/// KEM ciphertext size.
pub const KEM_CT_LEN: usize = 1568;

/// Wire package version (every message header). Unchanged by the message-key
/// store — the wire format is identical.
const PKG_VERSION: u8 = 0x0A;
/// Serialized *session-state* version. 0x0B adds the skipped-message-key
/// store; 0x0A (legacy) is still accepted by `from_bytes` (empty store).
const SESSION_VERSION: u8 = 0x0B;
/// Maximum gap the store will bridge in one skip (Signal `MAX_SKIP`). A
/// larger gap is treated as out of order / malicious rather than forcing a
/// multi-thousand-step key derivation.
pub const MAX_SKIP: u32 = 1000;
/// Hard cap on stored skipped message keys per session (32 bytes each).
/// Bounds memory for an attacker that drives many skips; legitimate
/// conversations stay far below it.
pub const MAX_SKIPPED_TOTAL: usize = 2000;
const FLAG_DH: u8 = 0x01;
const FLAG_KEM_PK: u8 = 0x02;
const FLAG_KEM_CT: u8 = 0x04;

// KDF domain-separation labels (pinned in RATCHET.md §2).
//
// Direction separation is *implicit*: sending and receiving chains are
// distinct chain keys seeded from different DH outputs, so the per-step KDF
// is identical for both directions — otherwise the sender and receiver would
// derive different message keys from the same chain key.
const LBL_MK: u8 = 0x01; // HMAC(ck, 0x01) — message key
const LBL_CK: u8 = 0x02; // HMAC(ck, 0x02) — next chain key
const LBL_RK: u8 = 0x03; // HMAC(rk, 0x03 ‖ dh_out) — new root key
const LBL_CK_SEED: u8 = 0x04; // HMAC(rk, 0x04 ‖ dh_out) — new chain seed
const LBL_KEM_MIX: u8 = 0x05; // HMAC(dh_mk, 0x05 ‖ kem_ss) — PQ mixing
const LBL_EK: u8 = 0x06; // HMAC(mk, 0x06) — AEAD key
const LBL_NONCE: u8 = 0x07; // HMAC(mk, 0x07)[0..12] — AEAD nonce

/// Why a message could not be decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    Malformed,
    /// Message number is neither the expected next number for its chain nor
    /// present in the skipped-message-key store (duplicate, replay, or a
    /// gap beyond [`MAX_SKIP`]).
    OutOfOrder,
    /// No session state / missing sending chain for this role yet.
    NoState,
    /// AEAD authentication failed (wrong key, tampering, wrong KEM key).
    AuthFailed,
}

// ── KDF helpers ─────────────────────────────────────────────────────

fn hmac256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// One step of a symmetric message chain. Returns the message key and the
/// advanced chain key.
fn chain_step(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = hmac256(ck, &[LBL_MK]);
    let next = hmac256(ck, &[LBL_CK]);
    (mk, next)
}

/// Root step (DH ratchet): advance root key and derive a fresh chain seed.
fn root_step(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut d1 = Vec::with_capacity(33);
    d1.push(LBL_RK);
    d1.extend_from_slice(dh_out);
    let new_rk = hmac256(rk, &d1);

    let mut d2 = Vec::with_capacity(33);
    d2.push(LBL_CK_SEED);
    d2.extend_from_slice(dh_out);
    let ck = hmac256(rk, &d2);
    (new_rk, ck)
}

/// Mix the per-message KEM secret into the DH-derived message key.
fn mix_kem(dh_mk: &[u8; 32], kem_ss: Option<&[u8]>) -> [u8; 32] {
    match kem_ss {
        Some(ss) => {
            let mut data = Vec::with_capacity(33);
            data.push(LBL_KEM_MIX);
            data.extend_from_slice(ss);
            hmac256(dh_mk, &data)
        }
        None => *dh_mk,
    }
}

/// AEAD key + nonce derived from a final message key.
fn aead_key(final_mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let ek = hmac256(final_mk, &[LBL_EK]);
    let n = hmac256(final_mk, &[LBL_NONCE]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&n[..12]);
    (ek, nonce)
}

// ── X25519 helpers ──────────────────────────────────────────────────

/// X25519 shared secret (RFC 7748). Exposed for the PQXDH-lite bootstrap.
pub fn x25519_shared(sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], DecryptError> {
    let secret = XStaticSecret::from(*sk);
    let public = XPublicKey::from(*pk);
    let ss = secret.diffie_hellman(&public);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_bytes());
    Ok(out)
}

/// Generates a fresh X25519 ratchet keypair as raw `(public, secret)` bytes.
pub fn x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let sk = XStaticSecret::random_from_rng(OsRng);
    let pk = XPublicKey::from(&sk);
    (pk.to_bytes(), sk.to_bytes())
}

// ── ML-KEM helpers ──────────────────────────────────────────────────

fn kem_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let (dk, ek) = MlKem1024::generate(&mut rng);
    (
        ek.as_bytes().as_slice().to_vec(),
        dk.as_bytes().as_slice().to_vec(),
    )
}

/// ML-KEM-1024 encapsulation to a public key. Returns `(ciphertext, secret)`.
pub fn kem_encapsulate(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DecryptError> {
    if pk.len() != KEM_PK_LEN {
        return Err(DecryptError::Malformed);
    }
    let encoded =
        ml_kem::Encoded::<MlKemEncapsKey>::try_from(pk).map_err(|_| DecryptError::Malformed)?;
    let ek = MlKemEncapsKey::from_bytes(&encoded);
    let mut rng = OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| DecryptError::Malformed)?;
    Ok((ct.as_slice().to_vec(), ss.as_slice().to_vec()))
}

/// ML-KEM-1024 decapsulation with a secret key. Returns the shared secret.
pub fn kem_decapsulate(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if sk.len() != KEM_SK_LEN || ct.len() != KEM_CT_LEN {
        return Err(DecryptError::Malformed);
    }
    let encoded =
        ml_kem::Encoded::<MlKemDecapsKey>::try_from(sk).map_err(|_| DecryptError::Malformed)?;
    let dk = MlKemDecapsKey::from_bytes(&encoded);
    let kem_ct: ml_kem::Ciphertext<MlKem1024> =
        ml_kem::Ciphertext::<MlKem1024>::try_from(ct)
            .map_err(|_| DecryptError::Malformed)?;
    let ss = dk
        .decapsulate(&kem_ct)
        .map_err(|_| DecryptError::AuthFailed)?;
    Ok(ss.as_slice().to_vec())
}

// ── Session state ───────────────────────────────────────────────────

/// An advertised ML-KEM ratchet keypair (public sent to peer, secret kept
/// until rotated).
#[derive(Clone, Debug)]
pub struct AdvertisedKem {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

/// The hybrid ratchet session for one contact pair.
#[derive(Clone, Debug)]
pub struct Session {
    pub session_id: [u8; 32],
    pub rk: [u8; 32],
    /// Our current X25519 ratchet keypair.
    pub dh_s: ([u8; 32], [u8; 32]),
    /// Peer's current X25519 ratchet public key.
    pub dh_r: Option<[u8; 32]>,
    pub ck_s: Option<[u8; 32]>,
    pub ck_r: Option<[u8; 32]>,
    pub n_s: u32,
    pub n_r: u32,
    /// Length of our previous sending chain (validates the peer's first
    /// message of a new chain, Signal-style `pn`).
    pub pn: u32,
    /// Our advertised ML-KEM ratchet keys, newest first (≤ 2).
    pub kem_advertised: Vec<AdvertisedKem>,
    /// Peer's latest advertised ML-KEM ratchet public key.
    pub kem_peer: Option<Vec<u8>>,
    /// Set when we must advertise a fresh ML-KEM key on the next send.
    advertise_kem_next: bool,
    /// Skipped-message-key store (Signal `MKSK`): message keys derived when
    /// we jumped over a message of a receiving chain, keyed by the *peer's*
    /// sending-chain ratchet key (`dh_pub` in the message header) and the
    /// message number. Lets out-of-order and delayed messages decrypt
    /// without erroring. Serialized with the session state.
    pub skipped: BTreeMap<([u8; 32], u32), [u8; 32]>,
    /// True once the receiving chain for the peer's first message has been
    /// derived. The initiator derives it in [`Session::start_alice`]; the
    /// responder derives it on first decrypt, when the initiator's ephemeral
    /// key is finally visible in the inbound header.
    initialized: bool,
}

/// Raw material needed to start a session on one side (stage-B bootstrap
/// produces `root` and the initial keys from the identity bundle).
pub struct SessionStart {
    /// Shared session root established by the bootstrap (PQXDH-lite SK).
    pub root: [u8; 32],
    /// Caller-supplied session identifier: must be identical on both sides
    /// (it is bound into every AEAD header). With a single-device profile the
    /// natural value is `sha256(ik_kem_a ‖ ik_kem_b)`.
    pub session_id: [u8; 32],
    /// Our initial X25519 ratchet keypair: initiator = X3DH ephemeral,
    /// responder = signed-prekey pair.
    pub our_dh: ([u8; 32], [u8; 32]),
    /// Peer's initial X25519 ratchet public key (initiator: peer signed
    /// prekey; responder: None — learned from the first inbound message).
    pub peer_dh: Option<[u8; 32]>,
    /// Our initial advertised ML-KEM ratchet keypair (initiator only).
    pub our_kem: Option<(Vec<u8>, Vec<u8>)>,
}

impl Session {
    /// Starts the *initiator* side of a session. The initiator knows the
    /// responder's signed prekey (`peer_dh`) up front and derives the shared
    /// initial root + first sending chain immediately (RatchetInitAlice). The
    /// responder derives the identical receiving chain lazily on first
    /// decrypt, when the initiator's ephemeral key finally appears in the
    /// inbound header.
    pub fn start_alice(start: SessionStart) -> Session {
        let mut sess = Session {
            session_id: start.session_id,
            rk: start.root,
            dh_s: start.our_dh,
            dh_r: start.peer_dh,
            ck_s: None,
            ck_r: None,
            n_s: 0,
            n_r: 0,
            pn: 0,
            kem_advertised: Vec::new(),
            kem_peer: None,
            advertise_kem_next: true,
            skipped: BTreeMap::new(),
            initialized: true, // nothing to receive from the responder yet, but init is done
        };
        // First sending chain: DH between our session-start (X3DH ephemeral)
        // key and the responder's signed prekey. This is the initiator's
        // first sending chain — its seed doubles as the shared secret the
        // responder will reproduce on first decrypt.
        let peer = sess.dh_r.expect("initiator needs a peer ratchet key");
        let dh = x25519_shared(&sess.dh_s.1, &peer).expect("x25519");
        let (rk, ck) = root_step(&sess.rk, &dh);
        sess.rk = rk;
        sess.ck_s = Some(ck);
        sess.pn = 0;
        sess.n_s = 0;
        // The initiator's first advertised ML-KEM ratchet keypair travels in
        // the init message; keep the secret so the peer's very first reply
        // can be decapsulated.
        if let Some((pk, sk)) = start.our_kem {
            sess.kem_advertised.push(AdvertisedKem { pk, sk });
        }
        sess
    }

    /// Starts the *responder* side of a session (RatchetInitBob). No DH chain
    /// can be derived yet — the initiator's ephemeral key only appears in the
    /// first inbound header — but the responder's *KEM* ratchet key must
    /// exist from the start: the initiator encapsulates to it from her very
    /// first message. The responder advertises a fresh KEM key when it opens
    /// its own sending chain. Sending before the first receive is impossible
    /// (`encrypt` returns `NoState`); decrypt derives the receiving chain
    /// lazily.
    pub fn start_bob(start: SessionStart) -> Session {
        let (kem_pk, kem_sk) = kem_keypair();
        Session {
            session_id: start.session_id,
            rk: start.root,
            dh_s: start.our_dh,
            dh_r: None,
            ck_s: None,
            ck_r: None,
            n_s: 0,
            n_r: 0,
            pn: 0,
            kem_advertised: vec![AdvertisedKem { pk: kem_pk, sk: kem_sk }],
            kem_peer: None,
            advertise_kem_next: true,
            skipped: BTreeMap::new(),
            initialized: false,
        }
    }

    /// Receiving-chain initialization (RatchetInitBob half, run lazily on the
    /// responder's first decrypt). `peer_dh` is the *first sender's*
    /// session-start key (initiator: her ephemeral key). The DH is
    /// symmetric, so the responder reproduces exactly the root step and chain
    /// seed the initiator derived for her first sending chain. No new peer
    /// chain is opened — the incoming message is part of the chain just
    /// derived, so `dh_r` is set to `peer_dh` to suppress a spurious ratchet.
    fn derive_initial_receive_chain(&mut self, peer_dh: [u8; 32]) -> Result<(), DecryptError> {
        let dh = x25519_shared(&self.dh_s.1, &peer_dh)?;
        let (rk, ck_r) = root_step(&self.rk, &dh);
        self.rk = rk;
        self.ck_r = Some(ck_r);
        self.n_r = 0;
        self.dh_r = Some(peer_dh);
        self.initialized = true;
        Ok(())
    }

    /// Opens a fresh sending chain if none is open (spec: deferred ratchet
    /// key generation). The sending chain is always derived against the
    /// peer's *current* ratchet key (`dh_r`), using a freshly generated
    /// keypair whose public half is advertised in the next header.
    fn open_send_chain(&mut self) {
        if self.ck_s.is_some() {
            return;
        }
        let peer_dh = match self.dh_r {
            Some(pk) => pk,
            None => return, // no peer key yet: cannot open a chain (NoState from caller)
        };
        self.dh_s = x25519_keypair();
        self.advertise_kem_next = true;
        if let Ok(dh) = x25519_shared(&self.dh_s.1, &peer_dh) {
            let (rk2, ck_s) = root_step(&self.rk, &dh);
            self.rk = rk2;
            self.ck_s = Some(ck_s);
            self.n_s = 0;
            // pn was set when the previous chain was closed (ratchet) or at
            // session start (0); unchanged here.
        }
    }

    /// Encrypts `plaintext` and returns a package for the wire.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        self.open_send_chain();
        let ck = self.ck_s.as_ref().ok_or(DecryptError::NoState)?;
        let (mk, next) = chain_step(ck);
        self.ck_s = Some(next);
        let n = self.n_s;
        self.n_s += 1;
        // `pn` = length of our previous sending chain, fixed when the peer
        // opened a new chain and we ratcheted; unchanged across messages of
        // the current chain.
        let pn = self.pn;

        let mut flags = FLAG_DH;
        let mut kem_pk: Option<Vec<u8>> = None;
        if self.advertise_kem_next {
            let (pk, sk) = kem_keypair();
            self.kem_advertised.insert(0, AdvertisedKem { pk: pk.clone(), sk });
            self.kem_advertised.truncate(2);
            kem_pk = Some(pk);
            flags |= FLAG_KEM_PK;
            self.advertise_kem_next = false;
        }

        let mut kem_ct: Option<Vec<u8>> = None;
        let mut kem_ss: Option<Vec<u8>> = None;
        if let Some(peer_pk) = self.kem_peer.clone() {
            let (ct, ss) = kem_encapsulate(&peer_pk)?;
            kem_ct = Some(ct);
            kem_ss = Some(ss);
            flags |= FLAG_KEM_CT;
        }

        let header = build_header(flags, pn, n, &self.dh_s.0, kem_pk.as_deref(), kem_ct.as_deref());
        let final_mk = mix_kem(&mk, kem_ss.as_deref());
        let ct = aead_encrypt(&self.session_id, &header, &final_mk, plaintext)?;

        let mut out = header;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Derives and stores message keys for messages `[n_r, until)` of the
    /// *current* receiving chain (Signal `SkipMessageKeys`), so that messages
    /// which arrive late still decrypt from the skipped-message-key store.
    ///
    /// Called with `until = pn` when the peer opens a new chain (pn is the
    /// length of the chain we were receiving — anything we have not consumed
    /// was lost in transit and its keys are retained) and with `until = n`
    /// when a gap opens inside the current chain. Advances `n_r` so the next
    /// in-order message is `until`. A gap wider than [`MAX_SKIP`], or a gap
    /// that would push the store past [`MAX_SKIPPED_TOTAL`], is a hard
    /// `OutOfOrder` rejected *up front, before any state changes* — it caps
    /// the work and memory a hostile relay can force without risking a
    /// partially-advanced chain.
    fn skip_to(&mut self, until: u32) -> Result<(), DecryptError> {
        if until <= self.n_r {
            return Ok(());
        }
        if until - self.n_r > MAX_SKIP {
            return Err(DecryptError::OutOfOrder);
        }
        // Store capacity is checked up front so a rejection is atomic: a
        // partial skip (keys inserted, `n_r` advanced, chain key not) would
        // leave the receiving chain inconsistent and brick the session.
        if self.skipped.len() + (until - self.n_r) as usize > MAX_SKIPPED_TOTAL {
            return Err(DecryptError::OutOfOrder);
        }
        // No receiving chain open for this peer key yet (e.g. a new chain
        // arrives before we ever received the previous one): nothing to
        // derive, nothing to store — but the chain switch itself is fine.
        let dh = match self.dh_r {
            Some(d) => d,
            None => return Ok(()),
        };
        let mut ck = match self.ck_r {
            Some(c) => c,
            None => return Ok(()),
        };
        while self.n_r < until {
            let (mk, next) = chain_step(&ck);
            self.skipped.insert((dh, self.n_r), mk);
            ck = next;
            self.n_r += 1;
        }
        self.ck_r = Some(ck);
        Ok(())
    }

    /// Tries to open the AEAD with a message key: decapsulate the header KEM
    /// ciphertext with our advertised KEM secrets (newest first), mixing each
    /// candidate into the key, and fall back to no KEM (messages sent before
    /// the peer learned any advertised key, or encapsulations to a KEM key we
    /// rotated away — then AEAD fails).
    fn open_aead(
        &self,
        header: &[u8],
        ct: &[u8],
        kem_ct: Option<&[u8]>,
        mk: &[u8; 32],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut candidates: Vec<Option<Vec<u8>>> = Vec::new();
        if let Some(kem_ct) = kem_ct {
            let mut any_ok = false;
            for adv in &self.kem_advertised {
                if let Ok(ss) = kem_decapsulate(&adv.sk, kem_ct) {
                    candidates.push(Some(ss));
                    any_ok = true;
                }
            }
            if !any_ok {
                // The peer encapsulated to a KEM key we rotated away (more
                // than one full turn stale): fall through and let AEAD fail.
                candidates.push(None);
            }
        } else {
            candidates.push(None);
        }
        for ss in candidates {
            let final_mk = mix_kem(mk, ss.as_deref());
            if let Ok(pt) = aead_decrypt(&self.session_id, header, &final_mk, ct) {
                return Ok(pt);
            }
        }
        Err(DecryptError::AuthFailed)
    }

    /// Decrypts a package. Ratchets state forward on new peer ratchet keys.
    ///
    /// Order handling: a message whose number is the expected next for its
    /// chain decrypts in place (skipping over any gap first and retaining the
    /// skipped message keys); a message whose key is already in the
    /// skipped-message-key store (a straggler of the current chain or of a
    /// chain the peer already advanced past) decrypts from the store without
    /// touching ratchet state; anything else — duplicate, replay, or a gap
    /// beyond [`MAX_SKIP`] — is `Err(OutOfOrder)`.
    pub fn decrypt(&mut self, package: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let (flags, pn, n, dh_pub, kem_pk, kem_ct, rest) = parse_header(package)?;
        let ct = rest;
        let header = &package[..package.len() - ct.len()];

        // Skipped-message-key store: a message that is not the expected next
        // message of its chain but whose key we retained when we jumped over
        // it. Decrypt from the store without disturbing ratchet state. The
        // entry is removed only on a successful open, so a garbage replay
        // cannot burn a genuine message's key.
        let store_key = (dh_pub, n);
        if self.skipped.contains_key(&store_key) {
            let mk = self.skipped[&store_key];
            let pt = self.open_aead(header, ct, kem_ct.as_deref(), &mk)?;
            self.skipped.remove(&store_key);
            return Ok(pt);
        }

        // Responder, very first inbound message: the header finally reveals
        // the initiator's session-start (ephemeral) key. Derive the shared
        // initial root + first receiving chain exactly as the initiator did.
        if !self.initialized {
            self.derive_initial_receive_chain(dh_pub)?;
        }

        let new_chain = self.dh_r.map_or(true, |cur| cur != dh_pub);
        if new_chain {
            // Peer opened a new sending chain. `pn` is the length of their
            // previous sending chain — the chain we were receiving. It can
            // never be smaller than what we consumed; if it is larger, the
            // tail was lost in transit: retain its keys (stragglers will
            // decrypt later) and ratchet.
            if pn < self.n_r {
                return Err(DecryptError::OutOfOrder);
            }
            self.skip_to(pn)?;
            self.ratchet(dh_pub)?;
        } else if n > self.n_r {
            // Gap inside the current chain: derive + retain the skipped keys.
            self.skip_to(n)?;
        } else if n < self.n_r {
            // Same chain, already past: either a genuine straggler (its key
            // would have been in the store — checked above) or a replay.
            return Err(DecryptError::OutOfOrder);
        }
        let ck = self.ck_r.as_ref().ok_or(DecryptError::NoState)?;
        let (mk, next) = chain_step(ck);
        self.ck_r = Some(next);
        self.n_r += 1;

        let plaintext = self.open_aead(header, ct, kem_ct.as_deref(), &mk)?;

        // Record the peer's newly advertised KEM ratchet key, if any.
        // (Only on the in-order path — a straggler advertisement must not
        // regress our view to an older KEM key.)
        if let Some(kem_pk) = kem_pk {
            self.kem_peer = Some(kem_pk);
        }
        let _ = flags;
        Ok(plaintext)
    }

    /// Full DH ratchet step, run when the peer opens a new sending chain with
    /// a fresh ratchet key:
    ///
    /// 1. Receive chain: `dh = X25519(our current dh_s.sk, peer_dh)`; advance
    ///    the root key and seed a fresh receiving chain.
    /// 2. Adopt the peer's key and *clear* the sending chain: per the spec,
    ///    the fresh ratchet keypair and sending chain are only generated when
    ///    the next message is actually sent (`encrypt` → `open_send_chain`).
    ///    `pn` for that next chain is recorded now as the length of our
    ///    previous sending chain, so the peer can verify it consumed every
    ///    message of that chain before accepting the next one.
    fn ratchet(&mut self, peer_dh: [u8; 32]) -> Result<(), DecryptError> {
        // 1. Receiving chain from the peer's new ratchet key.
        let dh1 = x25519_shared(&self.dh_s.1, &peer_dh)?;
        let (rk1, ck_r) = root_step(&self.rk, &dh1);
        self.rk = rk1;
        self.ck_r = Some(ck_r);
        self.n_r = 0;
        self.dh_r = Some(peer_dh);

        // 2. Defer the new sending chain to the next encrypt. `pn` for that
        //    next chain = the length of the chain we just closed (our own
        //    send counter), so the peer can verify it consumed all messages
        //    of that chain before accepting the next one.
        self.pn = self.n_s;
        self.ck_s = None;
        Ok(())
    }

    /// Serializes the session for encrypted persistence. The first byte is
    /// [`SESSION_VERSION`] (0x0B); sessions written by older builds (0x0A,
    /// without the skipped-message-key store) are accepted by `from_bytes`
    /// with an empty store. The *wire* package version is unchanged.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SESSION_VERSION);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.rk);
        out.extend_from_slice(&self.dh_s.0);
        out.extend_from_slice(&self.dh_s.1);
        match &self.dh_r {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(v);
            }
            None => out.push(0),
        }
        write_opt_ck(&mut out, &self.ck_s);
        write_opt_ck(&mut out, &self.ck_r);
        out.extend_from_slice(&self.n_s.to_le_bytes());
        out.extend_from_slice(&self.n_r.to_le_bytes());
        out.extend_from_slice(&self.pn.to_le_bytes());
        match &self.kem_peer {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&(v.len() as u16).to_le_bytes());
                out.extend_from_slice(v);
            }
            None => out.push(0),
        }
        out.push(self.kem_advertised.len() as u8);
        for adv in &self.kem_advertised {
            out.extend_from_slice(&(adv.pk.len() as u16).to_le_bytes());
            out.extend_from_slice(&adv.pk);
            out.extend_from_slice(&(adv.sk.len() as u16).to_le_bytes());
            out.extend_from_slice(&adv.sk);
        }
        out.push(self.advertise_kem_next as u8);
        out.push(self.initialized as u8);
        // Skipped-message-key store (0x0B only): count then (dh 32B, n u32,
        // mk 32B) per entry.
        out.extend_from_slice(&(self.skipped.len() as u32).to_le_bytes());
        for ((dh, n), mk) in &self.skipped {
            out.extend_from_slice(dh);
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(mk);
        }
        out
    }

    /// Restores a session from [`Session::to_bytes`]. Accepts both the
    /// current version (0x0B, with the skipped-message-key store) and the
    /// legacy 0x0A format (empty store) so a rolling upgrade keeps sessions.
    pub fn from_bytes(data: &[u8]) -> Result<Session, String> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Result<&[u8], String> {
            if data.len() < p + n {
                return Err("session bytes truncated".into());
            }
            let s = &data[p..p + n];
            p += n;
            Ok(s)
        };
        let ver = take(1)?[0];
        if ver != SESSION_VERSION && ver != PKG_VERSION {
            return Err(format!("unsupported session version {}", ver));
        }
        let arr32 = |s: &[u8]| -> Result<[u8; 32], String> {
            s.try_into().map_err(|_| "bad length".to_string())
        };
        let session_id = arr32(take(32)?)?;
        let rk = arr32(take(32)?)?;
        let dh_s = (arr32(take(32)?)?, arr32(take(32)?)?);
        let dh_r = if take(1)?[0] == 1 {
            Some(arr32(take(32)?)?)
        } else {
            None
        };
        let mut read_opt_ck = || -> Result<Option<[u8; 32]>, String> {
            let mark = take(1)?[0];
            if mark == 0 {
                Ok(None)
            } else {
                Ok(Some(arr32(take(32)?)?))
            }
        };
        let ck_s = read_opt_ck()?;
        let ck_r = read_opt_ck()?;
        let n_s = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let n_r = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let pn = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let kem_peer = if take(1)?[0] == 1 {
            let len = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
            Some(take(len)?.to_vec())
        } else {
            None
        };
        let n_kem = take(1)?[0] as usize;
        let mut kem_advertised = Vec::with_capacity(n_kem.min(2));
        for _ in 0..n_kem {
            let plen = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
            let pk = take(plen)?.to_vec();
            let slen = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
            let sk = take(slen)?.to_vec();
            kem_advertised.push(AdvertisedKem { pk, sk });
        }
        let advertise_kem_next = take(1)?[0] != 0;
        let initialized = take(1)?[0] != 0;
        let mut skipped = BTreeMap::new();
        if ver == SESSION_VERSION {
            let n_skip = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
            if n_skip > MAX_SKIPPED_TOTAL {
                return Err("session skipped-key count out of bounds".into());
            }
            for _ in 0..n_skip {
                let dh = arr32(take(32)?)?;
                let n = u32::from_le_bytes(take(4)?.try_into().unwrap());
                let mk = arr32(take(32)?)?;
                skipped.insert((dh, n), mk);
            }
        }
        Ok(Session {
            session_id,
            rk,
            dh_s,
            dh_r,
            ck_s,
            ck_r,
            n_s,
            n_r,
            pn,
            kem_advertised,
            kem_peer,
            advertise_kem_next,
            skipped,
            initialized,
        })
    }
}

// ── header / AEAD helpers ───────────────────────────────────────────

fn build_header(
    flags: u8,
    pn: u32,
    n: u32,
    dh_pub: &[u8; 32],
    kem_pk: Option<&[u8]>,
    kem_ct: Option<&[u8]>,
) -> Vec<u8> {
    let mut h = Vec::with_capacity(42 + 1568 + 1568);
    h.push(PKG_VERSION);
    h.push(flags);
    h.extend_from_slice(&pn.to_le_bytes());
    h.extend_from_slice(&n.to_le_bytes());
    h.extend_from_slice(dh_pub);
    if let Some(pk) = kem_pk {
        h.extend_from_slice(pk);
    }
    if let Some(ct) = kem_ct {
        h.extend_from_slice(ct);
    }
    h
}

#[allow(clippy::type_complexity)]
fn parse_header(
    pkg: &[u8],
) -> Result<(u8, u32, u32, [u8; 32], Option<Vec<u8>>, Option<Vec<u8>>, &[u8]), DecryptError> {
    if pkg.len() < 42 + 16 {
        return Err(DecryptError::Malformed);
    }
    if pkg[0] != PKG_VERSION {
        return Err(DecryptError::Malformed);
    }
    let flags = pkg[1];
    if flags & FLAG_DH == 0 {
        return Err(DecryptError::Malformed);
    }
    let pn = u32::from_le_bytes([pkg[2], pkg[3], pkg[4], pkg[5]]);
    let n = u32::from_le_bytes([pkg[6], pkg[7], pkg[8], pkg[9]]);
    let mut dh_pub = [0u8; 32];
    dh_pub.copy_from_slice(&pkg[10..42]);
    let mut pos = 42usize;
    let mut kem_pk = None;
    if flags & FLAG_KEM_PK != 0 {
        if pkg.len() < pos + KEM_PK_LEN {
            return Err(DecryptError::Malformed);
        }
        kem_pk = Some(pkg[pos..pos + KEM_PK_LEN].to_vec());
        pos += KEM_PK_LEN;
    }
    let mut kem_ct = None;
    if flags & FLAG_KEM_CT != 0 {
        if pkg.len() < pos + KEM_CT_LEN {
            return Err(DecryptError::Malformed);
        }
        kem_ct = Some(pkg[pos..pos + KEM_CT_LEN].to_vec());
        pos += KEM_CT_LEN;
    }
    Ok((flags, pn, n, dh_pub, kem_pk, kem_ct, &pkg[pos..]))
}

/// Returns the sender's current X25519 ratchet public key carried in a
/// package header. The responder's PQXDH-lite bootstrap needs it (it is the
/// initiator's ephemeral key) to compute the DH values that reproduce the
/// initiator's root.
pub fn package_sender_key(package: &[u8]) -> Option<[u8; 32]> {
    let (_, _, _, dh_pub, _, _, _) = parse_header(package).ok()?;
    Some(dh_pub)
}

fn aead_encrypt(
    session_id: &[u8; 32],
    header: &[u8],
    final_mk: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let (ek, nonce) = aead_key(final_mk);
    let cipher = Aes256Gcm::new_from_slice(&ek).map_err(|_| DecryptError::NoState)?;
    let mut aad = Vec::with_capacity(32 + header.len());
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(header);
    cipher
        .encrypt(Nonce::from_slice(&nonce), aead::Payload { msg: plaintext, aad: &aad })
        .map_err(|_| DecryptError::AuthFailed)
}

fn aead_decrypt(
    session_id: &[u8; 32],
    header: &[u8],
    final_mk: &[u8; 32],
    ct: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let (ek, nonce) = aead_key(final_mk);
    let cipher = Aes256Gcm::new_from_slice(&ek).map_err(|_| DecryptError::NoState)?;
    let mut aad = Vec::with_capacity(32 + header.len());
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(header);
    cipher
        .decrypt(Nonce::from_slice(&nonce), aead::Payload { msg: ct, aad: &aad })
        .map_err(|_| DecryptError::AuthFailed)
}

fn write_opt_ck(out: &mut Vec<u8>, ck: &Option<[u8; 32]>) {
    match ck {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(v);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
fn random32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds matching start material for both sides of a conversation.
    /// Alice is the session initiator (has Bob's prekey, advertises her own
    /// fresh KEM key); Bob is the responder (learns Alice's keys from the
    /// first inbound message).
    fn fixture() -> (Session, Session) {
        let root = random32();
        let session_id = random32();
        let (ek_a, sk_a) = x25519_keypair();
        let (spk_b_pk, spk_b_sk) = x25519_keypair();
        let (kem_a_pk, kem_a_sk) = kem_keypair();

        let alice = Session::start_alice(SessionStart {
            root,
            session_id,
            our_dh: (ek_a, sk_a),
            peer_dh: Some(spk_b_pk),
            our_kem: Some((kem_a_pk, kem_a_sk)),
        });
        let bob = Session::start_bob(SessionStart {
            root,
            session_id,
            our_dh: (spk_b_pk, spk_b_sk),
            peer_dh: None,
            our_kem: None,
        });
        (alice, bob)
    }

    #[test]
    fn test_basic_ping_pong() {
        let (mut alice, mut bob) = fixture();

        // Alice sends 2 while Bob is "offline" (delivered together on connect).
        let a1 = alice.encrypt(b"hi bob 1").unwrap();
        let a2 = alice.encrypt(b"hi bob 2").unwrap();
        assert_eq!(bob.decrypt(&a1).unwrap(), b"hi bob 1");
        assert_eq!(bob.decrypt(&a2).unwrap(), b"hi bob 2");

        // Bob replies 3.
        let b1 = bob.encrypt(b"hi alice 1").unwrap();
        let b2 = bob.encrypt(b"hi alice 2").unwrap();
        let b3 = bob.encrypt(b"hi alice 3").unwrap();
        assert_eq!(alice.decrypt(&b1).unwrap(), b"hi alice 1");
        assert_eq!(alice.decrypt(&b2).unwrap(), b"hi alice 2");
        assert_eq!(alice.decrypt(&b3).unwrap(), b"hi alice 3");

        // Bob stays offline for a long burst from Alice.
        let burst: Vec<Vec<u8>> = (0..20)
            .map(|i| alice.encrypt(format!("a{}", i).as_bytes()).unwrap())
            .collect();
        for (i, m) in burst.iter().enumerate() {
            let want = format!("a{}", i);
            assert_eq!(bob.decrypt(m).unwrap(), want.as_bytes());
        }

        // Conversation continues both ways.
        let b4 = bob.encrypt(b"still here").unwrap();
        assert_eq!(alice.decrypt(&b4).unwrap(), b"still here");
        let a_final = alice.encrypt(b"me too").unwrap();
        assert_eq!(bob.decrypt(&a_final).unwrap(), b"me too");
    }

    #[test]
    fn test_distinct_ciphertexts_and_no_replay() {
        let (mut alice, mut bob) = fixture();
        let m1 = alice.encrypt(b"same").unwrap();
        let m2 = alice.encrypt(b"same").unwrap();
        assert_ne!(m1, m2, "same plaintext must not produce identical packages");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"same");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"same");
        // Replay of an already-consumed package must be rejected.
        assert_eq!(bob.decrypt(&m1).unwrap_err(), DecryptError::OutOfOrder);
    }

    #[test]
    fn test_tamper_fails() {
        let (mut alice, mut bob) = fixture();
        let mut m = alice.encrypt(b"important").unwrap();
        let last = m.len() - 1;
        m[last] ^= 0xFF;
        assert_eq!(bob.decrypt(&m).unwrap_err(), DecryptError::AuthFailed);

        // Tampering with the message number in the header must also fail
        // loudly. The second package carries n = 1; flipping the low byte
        // makes it n = 0, which is already behind the receiving chain — a
        // replay shape → OutOfOrder (and the AEAD would fail anyway).
        let mut m2 = alice.encrypt(b"header tamper").unwrap();
        let hdr_n = 6; // first byte of the `n` field
        m2[hdr_n] ^= 0x01;
        assert_eq!(bob.decrypt(&m2).unwrap_err(), DecryptError::OutOfOrder);
    }

    #[test]
    fn test_replay_rejected_after_consumption() {
        let (mut alice, mut bob) = fixture();
        // Establish the session with a few alternations.
        for _ in 0..3 {
            let m = alice.encrypt(b"a").unwrap();
            assert_eq!(bob.decrypt(&m).unwrap(), b"a");
            let r = bob.encrypt(b"b").unwrap();
            assert_eq!(alice.decrypt(&r).unwrap(), b"b");
        }

        // A single multi-message turn from Alice (same DH key, n = 0, 1, 2).
        let m1 = alice.encrypt(b"first").unwrap();
        let m2 = alice.encrypt(b"second").unwrap();
        let m3 = alice.encrypt(b"third").unwrap();
        // In-order delivery always succeeds.
        assert_eq!(bob.decrypt(&m1).unwrap(), b"first");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"second");
        assert_eq!(bob.decrypt(&m3).unwrap(), b"third");

        // Replays are rejected.
        assert_eq!(bob.decrypt(&m1).unwrap_err(), DecryptError::OutOfOrder);
        assert_eq!(bob.decrypt(&m2).unwrap_err(), DecryptError::OutOfOrder);
    }

    #[test]
    fn test_persistence_roundtrip() {
        let (mut alice, mut bob) = fixture();
        let a1 = alice.encrypt(b"persist me").unwrap();
        assert_eq!(bob.decrypt(&a1).unwrap(), b"persist me");

        // Serialize both mid-conversation and restore (e.g. tab reload).
        let alice_bytes = alice.to_bytes();
        let bob_bytes = bob.to_bytes();
        let mut alice2 = Session::from_bytes(&alice_bytes).unwrap();
        let mut bob2 = Session::from_bytes(&bob_bytes).unwrap();

        let b1 = bob2.encrypt(b"reply after restore").unwrap();
        assert_eq!(alice2.decrypt(&b1).unwrap(), b"reply after restore");
        let a2 = alice2.encrypt(b"and again").unwrap();
        assert_eq!(bob2.decrypt(&a2).unwrap(), b"and again");

        // Tampered or truncated serialization must be rejected, not panic.
        assert!(Session::from_bytes(&alice_bytes[..alice_bytes.len() - 3]).is_err());
        let mut corrupt = alice_bytes.clone();
        corrupt[0] = 0xFF;
        assert!(Session::from_bytes(&corrupt).is_err());
    }

    #[test]
    fn test_forward_secrecy_old_state_cannot_read_new() {
        let (mut alice, mut bob) = fixture();

        // A few full rounds so both sides are firmly mid-ratchet.
        for _ in 0..4 {
            let m = alice.encrypt(b"ping").unwrap();
            assert_eq!(bob.decrypt(&m).unwrap(), b"ping");
            let r = bob.encrypt(b"pong").unwrap();
            assert_eq!(alice.decrypt(&r).unwrap(), b"pong");
        }

        // Attacker captures Bob's *current* state.
        let stolen = bob.to_bytes();
        let mut attacker = Session::from_bytes(&stolen).unwrap();

        // The conversation continues normally: Alice speaks, Bob replies
        // (ratcheting his DH forward), Alice speaks again, Bob replies again.
        let m1 = alice.encrypt(b"post-theft a1 SECRET").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"post-theft a1 SECRET");
        let r1 = bob.encrypt(b"post-theft b1").unwrap();
        assert_eq!(alice.decrypt(&r1).unwrap(), b"post-theft b1");
        let m2 = alice.encrypt(b"post-theft a2 SECRET").unwrap();
        assert_eq!(bob.decrypt(&m2).unwrap(), b"post-theft a2 SECRET");
        let r2 = bob.encrypt(b"post-theft b2").unwrap();
        assert_eq!(alice.decrypt(&r2).unwrap(), b"post-theft b2");

        // What the stolen state can read: `m1` was sent before Bob rotated
        // his ratchet key, so it sits in the very chain the thief captured —
        // decryptable. That is inherent to the double ratchet (the key was
        // current at capture time); what matters for forward secrecy is what
        // comes after Bob advances.
        assert_eq!(attacker.decrypt(&m1).unwrap(), b"post-theft a1 SECRET");

        // `m2` is sent after Bob's reply rotated his DH ratchet key. Deriving
        // its chain requires the DH secret Bob generated after the capture;
        // the stolen state cannot follow, so this — and every later message
        // in the conversation — is sealed.
        assert!(
            attacker.decrypt(&m2).is_err(),
            "state stolen before Bob's ratchet advance cannot decrypt post-advance messages"
        );
    }

    /// Sustained pseudo-random two-way traffic with variable-length turns,
    /// burst-style offline delivery, and a mid-conversation persistence
    /// checkpoint on both sides. Any chain-state accounting bug (message
    /// numbers, pn, DH/KEM rotation) surfaces here.
    #[test]
    fn test_sustained_traffic_stress() {
        let (mut alice, mut bob) = fixture();

        let step = |n: u64| -> Vec<u8> {
            // Deterministic pseudo-random bytes for message content.
            let mut b = Vec::with_capacity(48);
            let mut x = n.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0xDEADBEEF);
            for _ in 0..48 {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                b.push(b'A' + ((x >> 33) % 89) as u8);
            }
            b
        };

        let mut n = 0u64;
        for round in 0..40u64 {
            let msgs = 1 + (round * 7 % 5) as usize; // 1..=5 messages per turn
            if round % 2 == 0 {
                for _ in 0..msgs {
                    n += 1;
                    let pt = step(n);
                    let pkg = alice.encrypt(&pt).unwrap();
                    assert_eq!(bob.decrypt(&pkg).unwrap(), pt, "round {} alice->bob", round);
                }
            } else {
                for _ in 0..msgs {
                    n += 1;
                    let pt = step(n);
                    let pkg = bob.encrypt(&pt).unwrap();
                    assert_eq!(alice.decrypt(&pkg).unwrap(), pt, "round {} bob->alice", round);
                }
            }

            // Persistence checkpoint mid-conversation (e.g. both tabs reload).
            if round == 20 {
                alice = Session::from_bytes(&alice.to_bytes()).unwrap();
                bob = Session::from_bytes(&bob.to_bytes()).unwrap();
            }
        }
    }

    // ── Skipped-message-key store (out-of-order / loss survival) ────────

    /// A burst from Alice, delivered to Bob in scrambled order: every
    /// message must decrypt, exactly once, regardless of arrival order.
    #[test]
    fn test_out_of_order_within_chain_recovers() {
        let (mut alice, mut bob) = fixture();
        let pkgs: Vec<Vec<u8>> = (0..6)
            .map(|i| alice.encrypt(format!("reorder-{}", i).as_bytes()).unwrap())
            .collect();
        let mut got = Vec::new();
        for i in [2usize, 0, 4, 1, 3, 5] {
            got.push(bob.decrypt(&pkgs[i]).unwrap());
        }
        for (i, pt) in got.iter().enumerate() {
            assert_eq!(*pt, format!("reorder-{}", [2usize, 0, 4, 1, 3, 5][i]).as_bytes());
        }
        // Everything was consumed exactly once: replays are all rejected.
        for (i, pkg) in pkgs.iter().enumerate() {
            assert_eq!(
                bob.decrypt(pkg).unwrap_err(),
                DecryptError::OutOfOrder,
                "replay of message {} must be rejected",
                i
            );
        }
        // The conversation continues normally afterwards.
        let a = alice.encrypt(b"after reorder").unwrap();
        assert_eq!(bob.decrypt(&a).unwrap(), b"after reorder");
    }

    /// A duplicate delivery of a message that we skipped over but have not
    /// decrypted yet must not be confused with the genuine copy: only the
    /// authentic ciphertext opens, and the store entry survives a failed
    /// attempt so a later genuine copy still decrypts.
    #[test]
    fn test_store_entry_survives_failed_open() {
        let (mut alice, mut bob) = fixture();
        let m0 = alice.encrypt(b"zero").unwrap();
        let m1 = alice.encrypt(b"one").unwrap();
        // Deliver m1 first: the engine skips over message 0, retaining its
        // key. Then a FORGED attempt to burn message 0's key with garbage
        // ciphertext must fail without deleting the genuine key.
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
        assert_eq!(bob.skipped.len(), 1);
        let mut forged = m0.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert_eq!(bob.decrypt(&forged).unwrap_err(), DecryptError::AuthFailed);
        // The genuine m0 still decrypts afterwards.
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        assert!(bob.skipped.is_empty());
        // And a replay of the now-consumed m0 is rejected.
        assert_eq!(bob.decrypt(&m0).unwrap_err(), DecryptError::OutOfOrder);
    }

    /// Message keys retained by skipping must survive a serialize/restore
    /// round-trip, and legacy 0x0A session bytes (written before the store
    /// existed) must still load with an empty store.
    #[test]
    fn test_skipped_store_persists_across_restore() {
        let (mut alice, mut bob) = fixture();
        let m0 = alice.encrypt(b"persist-0").unwrap();
        let m1 = alice.encrypt(b"persist-1").unwrap();
        let m2 = alice.encrypt(b"persist-2").unwrap();
        // m0 in order; m2 arrives next, skipping (and storing the key for) m1.
        assert_eq!(bob.decrypt(&m0).unwrap(), b"persist-0");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"persist-2");
        assert_eq!(bob.skipped.len(), 1);

        // Restore from bytes: the stored key must survive.
        let mut bob2 = Session::from_bytes(&bob.to_bytes()).unwrap();
        assert_eq!(bob2.skipped.len(), 1);
        assert_eq!(bob2.decrypt(&m1).unwrap(), b"persist-1");

        // Simulate a pre-0x0B session blob: same bytes, legacy version byte
        // and no trailing skipped section → loads with an empty store.
        let mut legacy = bob.to_bytes();
        let cut = legacy.len() - 4; // drop the 4-byte skipped count
        legacy.truncate(cut);
        legacy[0] = 0x0A;
        let bob_legacy = Session::from_bytes(&legacy).unwrap();
        assert!(bob_legacy.skipped.is_empty());

        // A legacy-restored session keeps working in order.
        let m3 = alice.encrypt(b"persist-3").unwrap();
        assert_eq!(bob2.decrypt(&m3).unwrap(), b"persist-3");
    }

    /// A gap wider than `MAX_SKIP` is a hard error and must not advance the
    /// receiving chain or store keys — the next genuine in-order message
    /// still decrypts.
    #[test]
    fn test_gap_beyond_max_skip_rejected_without_state_damage() {
        let (mut alice, mut bob) = fixture();
        // Encrypt MAX_SKIP + 3 messages on one chain (indices/message numbers
        // 0..=MAX_SKIP+2, so a package with number MAX_SKIP+2 exists).
        let pkgs: Vec<Vec<u8>> = (0..MAX_SKIP + 3)
            .map(|i| alice.encrypt(format!("bulk-{}", i).as_bytes()).unwrap())
            .collect();
        assert_eq!(bob.decrypt(&pkgs[0]).unwrap(), b"bulk-0");
        // n_r = 1; message MAX_SKIP+2 opens a gap of MAX_SKIP+1 > MAX_SKIP.
        let over = (MAX_SKIP + 2) as usize;
        assert_eq!(
            bob.decrypt(&pkgs[over]).unwrap_err(),
            DecryptError::OutOfOrder
        );
        // No keys were stored by the rejected jump and the chain was not
        // advanced: the very next message decrypts in order.
        assert!(bob.skipped.is_empty());
        assert_eq!(bob.decrypt(&pkgs[1]).unwrap(), b"bulk-1");
    }

    /// Loss + recovery across a chain switch: Alice sends three messages on
    /// chain A1; Bob only receives the first (the other two are lost in
    /// transit). Bob replies (opening his own chain), Alice replies, opening
    /// chain A2 whose header reports `pn = 3` — larger than Bob's `n_r = 1`.
    /// Bob must retain the keys for the two lost A1 messages, ratchet, and
    /// decrypt Alice's A2 message; when the two lost A1 messages finally
    /// arrive they decrypt from the store.
    #[test]
    fn test_lost_tail_across_chain_switch_recovers() {
        let (mut alice, mut bob) = fixture();

        // Alice sends 3 on chain A1; Bob receives only the first.
        let a0 = alice.encrypt(b"a0").unwrap();
        let a1 = alice.encrypt(b"a1").unwrap();
        let a2 = alice.encrypt(b"a2").unwrap();
        assert_eq!(bob.decrypt(&a0).unwrap(), b"a0"); // n_r = 1 on A1

        // Bob replies (chain B1); Alice receives it (ratchets).
        let b0 = bob.encrypt(b"b0").unwrap();
        assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");

        // Alice replies → opens chain A2 (pn = 3, her A1 length).
        let a3 = alice.encrypt(b"a3 on A2").unwrap();
        // Bob: new chain, pn 3 > n_r 1 → retain A1 keys 1..2, ratchet, decrypt.
        assert_eq!(bob.decrypt(&a3).unwrap(), b"a3 on A2");
        assert_eq!(bob.skipped.len(), 2);

        // The two lost A1 messages finally arrive → decrypt from the store.
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
        assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");
        assert!(bob.skipped.is_empty());

        // Replays of consumed messages are rejected.
        assert_eq!(bob.decrypt(&a0).unwrap_err(), DecryptError::OutOfOrder);
        assert_eq!(bob.decrypt(&a1).unwrap_err(), DecryptError::OutOfOrder);

        // The conversation continues on A2.
        let a4 = alice.encrypt(b"a4").unwrap();
        assert_eq!(bob.decrypt(&a4).unwrap(), b"a4");
    }

    /// Filling the skipped store to its cap must not corrupt chain state when
    /// the *next* gap would overflow it: the whole gap is rejected up front
    /// (no partial advance of `n_r`, no stray store entries, chain key
    /// untouched), and the missing in-order message still decrypts.
    #[test]
    fn test_store_capacity_rejected_atomically() {
        let (mut alice, mut bob) = fixture();

        // Deliver messages 0, 2, 4, …, 3998: each even message opens a
        // one-message gap whose key is retained, so the store fills to
        // MAX_SKIPPED_TOTAL - 1 = 1999 keys and n_r = 3999.
        let total = MAX_SKIPPED_TOTAL - 1;
        let last_even = 2 * total; // 3998
        let pkgs: Vec<Vec<u8>> = (0..=last_even + 3)
            .map(|i| alice.encrypt(format!("cap-{}", i).as_bytes()).unwrap())
            .collect();
        assert_eq!(bob.decrypt(&pkgs[0]).unwrap(), b"cap-0");
        for k in 1..=total {
            let idx = 2 * k; // message number 2k
            assert_eq!(
                bob.decrypt(&pkgs[idx]).unwrap(),
                format!("cap-{}", idx).as_bytes()
            );
        }
        assert_eq!(bob.skipped.len(), total);
        assert_eq!(bob.n_r, last_even as u32 + 1);

        // Message 4001 opens a gap of 2: 2001 keys would be needed, over the
        // cap. Rejected with no state change at all.
        let (n_r_before, store_before, ck_before) = (bob.n_r, bob.skipped.len(), bob.ck_r);
        assert_eq!(
            bob.decrypt(&pkgs[last_even + 3]).unwrap_err(),
            DecryptError::OutOfOrder
        );
        assert_eq!((bob.n_r, bob.skipped.len()), (n_r_before, store_before));
        assert_eq!(bob.ck_r, ck_before);

        // The chain is consistent: the next in-order message (3999) decrypts,
        // and a retained straggler (3997) decrypts from the store and is
        // removed — the store was never damaged by the rejected gap.
        assert_eq!(
            bob.decrypt(&pkgs[last_even + 1]).unwrap(),
            format!("cap-{}", last_even + 1).as_bytes()
        );
        assert_eq!(
            bob.decrypt(&pkgs[last_even - 1]).unwrap(),
            format!("cap-{}", last_even - 1).as_bytes()
        );
        assert_eq!(bob.skipped.len(), total - 1);
    }
}
