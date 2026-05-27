<p align="center">
  <img src="https://img.shields.io/badge/Rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"/>
  <img src="https://img.shields.io/badge/WASM-%23654FF0.svg?style=for-the-badge&logo=webassembly&logoColor=white" alt="WebAssembly"/>
  <img src="https://img.shields.io/badge/Post--Quantum-NIST%20FIPS%20203-00d4aa?style=for-the-badge" alt="NIST FIPS 203"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-%2300a86b.svg?style=for-the-badge" alt="AES-256"/>
  <img src="https://img.shields.io/badge/ML--KEM--1024-Kyber-7b2ff7?style=for-the-badge" alt="ML-KEM-1024"/>
  <img src="https://img.shields.io/badge/Zero--Trust-DhtEnvelope-2dd4bf?style=for-the-badge" alt="Zero-Trust DhtEnvelope"/>
  <img src="https://img.shields.io/badge/libp2p-P2P-2dd4bf?style=for-the-badge" alt="libp2p P2P"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blue?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/unsafe-forbidden-red?style=flat-square" alt="Forbid Unsafe"/>
  <img src="https://img.shields.io/badge/memory-zero--knowledge--server-222?style=flat-square" alt="Zero-Knowledge Server"/>
  <img src="https://img.shields.io/badge/crypto-in--memory%20only-important?style=flat-square" alt="In-Memory Only"/>
</p>

<h1 align="center">🔐 VurnChat</h1>

<p align="center">
  <strong>Post-Quantum Encrypted P2P Messenger<br>Quantum-resistant. Fully distributed. Blind server.</strong>
</p>

<p align="center">
  <sub>Built entirely in Rust — from cryptography to browser UI —<br>compiled to WebAssembly for the client,<br>backed by a distributed P2P network with Kademlia DHT.</sub>
</p>

---

## 🧬 What is VurnChat?

VurnChat is a **quantum-resistant instant messenger** with a fully distributed P2P backbone.
Every message is encrypted with **ML-KEM-1024** (NIST FIPS 203) + **AES-256-GCM**.

Messages are delivered through a **Kademlia DHT** — there is no central server.
Each node acts as both a router and a mailbox for offline recipients.
The server never sees plaintext, never learns who is talking to whom,
and stores no history beyond what the DHT distributes.

> **Threat model:** Resistant to *harvest-now-decrypt-later* attacks.
> Even an adversary with a large-scale quantum computer recording all your
> network traffic today cannot decrypt your messages tomorrow.

---

## 🏗 Architecture

### Overview

```
┌──────────────────────┐         ┌──────────────────────┐        ┌──────────────────────┐
│     Browser Tab A    │         │   P2P Node A          │        │   P2P Node B          │
│     ────────────     │  ws://  │   ────────────        │  P2P   │   ────────────        │
│                      │ ◄─────► │                       │ ◄─────►│                       │
│  ┌─────────────────┐ │         │  ┌─────────────────┐  │ libp2p │  ┌─────────────────┐  │
│  │   vurn-web       │ │         │  │ Kademlia DHT    │  │ Noise  │  │ Kademlia DHT    │  │
│  │   Leptos + WASM  │ │         │  │ GossipSub       │  │ TCP    │  │ GossipSub       │  │
│  │                  │ │         │  │ Identify/Ping   │  │        │  │ Identify/Ping   │  │
│  │  ┌─────────────┐ │ │         │  │ Relay / DCUtR   │  │        │  │ Relay / DCUtR   │  │
│  │  │ vurn-core    │ │ │         │  │ (NAT traversal) │  │        │  │ (NAT traversal) │  │
│  │  │ ML-KEM-1024  │ │ │         │  │                 │  │        │  │                 │  │
│  │  │ AES-256-GCM  │ │ │         │  │ MailboxManager  │  │        │  │ MailboxManager  │  │
│  │  │ SHA-256      │ │ │         │  │ (Sled backup)   │  │        │  │ (Sled backup)   │  │
│  │  └─────────────┘ │ │         │  └─────────────────┘  │        │  └─────────────────┘  │
│  └─────────────────┘  │         │                       │        │                       │
│                       │         │  Health: /health       │        │  Health: /health       │
│  WS auto-reconnect    │         │  Rate limiting: 10/s   │        │  Rate limiting: 10/s   │
│  (exponential backoff)│         │  DHT profiles (vup_)   │        │  DHT profiles (vup_)   │
│  Pending msg queue    │         │  Peer store persisted  │        │  Peer store persisted  │
│  Reconnect banner UI  │         │                       │        │                       │
│                       │         │  WS Gateway (:9000)    │        │  WS Gateway (:9001)    │
└───────────────────────┘         └──────────────────────┘        └──────────────────────┘
```

### Communication Flow

1. **Realtime delivery (online):** GossipSub topic = hex(user_hash)
   - WS → local delivery check → GossipSub publish → recipient receives in <1s
   - Also falls through to DHT mailbox (persistent backup)
2. **Offline delivery:** Sequential DHT mailbox (vmb_<hash>_<seq>)
   - Signed DhtEnvelope stored at `Quorum::Majority`
   - Retrieved on reconnect via parallel window probing
3. **Profile discovery:** DHT profile store (vup_<search_index>)
   - TOCTOU-safe: last-write-wins, blob is AES-GCM encrypted
   - 10s timeout on lookups

### Three crates, one workspace

| Crate | Role | Tech |
|-------|------|------|
| **`vurn-core`** | Cryptographic engine (no `unsafe`) | `ml-kem`, `aes-gcm`, `sha2`, `hmac`, `pbkdf2` |
| **`vurn-server`** | P2P node + WS gateway + mailbox | `libp2p`, `axum`, `tokio`, `sled`, `ed25519-dalek`, `rustls` |
| **`vurn-web`** | Browser UI (WASM) | `leptos`, `wasm-bindgen`, `web-sys`, `rexie` (IndexedDB) |

---

## 📦 P2P Mailbox — Zero-Trust Design

### DhtEnvelope (Cryptographic Integrity)

Every Kademlia record in the mailbox is wrapped in a **signed envelope**:

```
DhtEnvelope {
    payload,       // E2E encrypted (ML-KEM + AES-GCM) — opaque to P2P layer
    seq,           // Monotonic sequence number (1-based)
    sender_pubkey, // Sender's Ed25519 public key (32 bytes)
    signature,     // Ed25519(verify_buffer)
}

verify_buffer = payload || seq(8-byte LE) || recipient_hash(32 bytes)
```

The signature covers **recipient_hash** — a message intended for Alice cannot be
verified by Bob (recipient binding). Combined with Ed25519, this provides:
- ✅ **Payload integrity** — tampering is detected
- ✅ **Origin authentication** — only the holder of the signing key can store
- ✅ **Seq ordering** — replay with wrong seq fails verification
- ✅ **Recipient binding** — message intended for a different user is rejected

### Sequential Keys (No Index Key)

Messages are stored at deterministic keys — **no index key in the DHT**:

```
vmb_<recipient_hash>_00000000000000000001  →  DhtEnvelope (message #1)
vmb_<recipient_hash>_00000000000000000002  →  DhtEnvelope (message #2)
...
```

The index is maintained **in memory** (`HashMap<Vec<u8>, u64>`) on each node.
On restart, the node **speculatively probes** the DHT in parallel windows.

### Parallel Window Probing

Instead of probing seq 1, 2, 3... sequentially (O(n) round-trips), the node fires
`WINDOW_SIZE=10` parallel `get_record` calls. If all 10 exist, it advances to the
next window. If any seq is missing, a gap is detected and `index = seq - 1`.

```
Window 1:  get_record(seq 1..10)  →  all found, advance
Window 2:  get_record(seq 11..20) →  seq 15 missing → gap! index = 14
```

Each `FinishedWithNoAdditionalRecord` is matched to its exact seq via
**`QueryId`** (from `OutboundQueryProgressed`) — eliminates the race where
out-of-order responses caused false gap detection with the old `Vec::remove(0)`.

### State Machine

```
                        ┌──────────────┐
           ┌──────────► │    Idle      │ ◄──────────┐
           │            └──────┬───────┘            │
           │                   │                    │
           │        MailboxStore/Retrieve           │
           │           (no in-memory index)         │
           │                   │                    │
           │                   ▼                    │
           │            ┌──────────────┐           │
           │  30s       │ FetchingIndex│  30s       │
           │  timeout   │              │  timeout   │
           │  ┌──────── │ (window=10)  │ ───────────┘
           │  │         └──────┬───────┘
           │  │                │ gap found
           │  │                ▼
           │  │         ┌──────────────┐
           │  │ 30s     │CollectingMsgs│
           │  └──────── │              │
           │   (partial │ (seq 1..N)   │
           │   results) └──────┬───────┘
           │                   │ all collected
           └───────────────────┘
```

### Store Flow

1. **Fast path** — hash is in `mailbox_indices` HashMap:
   - Create `DhtEnvelope` with `seq = index + 1`
   - Sign with Ed25519 signing key
   - `put_record(vmb_<hash>_<seq>, envelope_bytes)` with `Quorum::Majority`
   - Update in-memory index
   - **No index key written to DHT** — in-memory only

2. **Lazy path** — hash not in HashMap (after restart):
   - Enter `FetchingIndex` with parallel window probing
   - On gap found → `resume_pending_command` with discovered index

### Retrieve Flow

1. **Fast path** — hash is in HashMap:
   - If `index == 0` → emit empty
   - Else → `start_collecting_messages(kademlia, user_hash, index)`

2. **Lazy path** — hash not in HashMap:
   - Same `FetchingIndex` probing as Store
   - On gap found → resume as `CollectingMessages` (sequential collection)

Both paths share the same helper (`store_signed_envelope`, `start_collecting_messages`, `emit_empty_mailbox`).

### Timeouts

Both `FetchingIndex` and `CollectingMessages` have **30-second deadlines**:

| State | Timeout behaviour |
|-------|------------------|
| `FetchingIndex` | Reset to `Idle` (no messages lost — pending command is dropped) |
| `CollectingMessages` | Emit partial results via `try_send(MailboxRetrieved)` + reset to `Idle` |

---

## 🔐 Cryptographic Design

### Key Generation

```
OsRng (system entropy: /dev/urandom or crypto.getRandomValues)
  │
  └─► MlKem1024::generate()
        │
        ├─► EncapsulationKey  (~1,568 bytes) — PUBLIC: share freely
        └─► DecapsulationKey  (~3,168 bytes) — SECRET: never leaves your device
```

- **ML-KEM-1024** is NIST FIPS 203, a lattice-based key encapsulation mechanism
  believed to be secure against both classical and quantum adversaries.
- All secret key material is wiped from memory on `drop()` via `zeroize`.
- `#![forbid(unsafe_code)]` in `vurn-core` — the crypto path contains **zero unsafe Rust**.

### Wire Format

```
┌───────────────┬──────────────────────┬──────────────┬───────────────────────────┐
│   2 bytes     │     N bytes (~1568)  │   12 bytes   │       M bytes             │
│  kem_ct_len   │   ML-KEM ciphertext  │  AES nonce   │  AES-GCM(payload + tag)   │
│  (u16 LE)     │  (encapsulated key)  │  (random)    │  (encrypted + auth tag)    │
└───────────────┴──────────────────────┴──────────────┴───────────────────────────┘
```

### Guarantees

- **IND-CCA2 security** via ML-KEM
- **Authenticated encryption** via AES-GCM — tampering is detected
- **Fresh key per message** — AES key is never reused
- **Post-quantum** — lattice-based, resistant to quantum cryptanalysis

### Local Storage Encryption

Encrypted profiles, contacts, and messages are stored in IndexedDB
(web-client) or Sled (server), encrypted with AES-256-GCM using a
key derived via PBKDF2-HMAC-SHA256 (100k iterations in WASM,
600k on native).

---

## 🌐 P2P Network Layer

### Node Discovery

Nodes discover each other via:
- **Identify protocol** — automatic peer info exchange on connection
- **Kademlia RoutingUpdated** events — routing table gossip
- **Manual `--bootstrap`** — initial peer to join the network
- **Persistent peer store** — addresses saved to Sled, re-dialed on startup (batched 5/500ms)

### NAT Traversal

Nodes behind NAT can be reached via:
- **libp2p relay** — relay behaviour active on all nodes
- **DCUtR** — direct connection upgrade through relay (hole-punching)
- **Graceful fallback** — if direct connection fails, relay transparently forwards

### Peer Reconnect

On `ConnectionClosed`, each peer gets its own exponential backoff:
```
1s → 2s → 4s → 8s → 16s → 32s → 60s (cap)
```
- Per-peer: `HashMap<PeerId, (attempt_count, Instant)>`
- Reconnect tick every 10s checks each peer's backoff
- `ConnectionEstablished` resets the counter

### Distributed Profiles (DHT)

Usernames are stored in the DHT under `vup_<search_index>` keys:
- **Register**: lookup → if free → store (TOCTOU race: last-write-wins)
- **Lookup**: `get_record` with 10s timeout, response via oneshot channel
- **Update**: overwrite (DHT has no auth — blob is AES-GCM encrypted)
- **Unregister**: not supported in DHT mode (data is immutable once written)

### Realtime Delivery (GossipSub)

When both users are online, messages bypass the DHT mailbox:
- On WS connect: subscribe to GossipSub topic = hex(user_hash)
- On message send: local delivery check → GossipSub publish to remote
- Always falls through to DHT mailbox (persistent backup)
- Topic routing: event handler decodes topic → routes to connected WS client

### Local Backup (Sled)

Every message is backed up to a **Sled embedded database** with seq-based dedup:
- Keys: `[user_hash(32) || seq(8 BE)]` — same seq always overwrites same key
- On restart: Sled seeds in-memory index, skipping speculative probing
- Peer addresses also persisted in Sled for cross-restart re-dial

---

## 📡 Server: `vurn-server`

### Quick Start

```bash
# WS mode (development)
cargo run -p vurn-server

# Custom port
cargo run -p vurn-server -- --port 8080

# WSS mode (TLS, production)
cargo run -p vurn-server -- --cert cert.pem --key key.pem --port 443

# Join a P2P network
cargo run -p vurn-server -- --bootstrap /ip4/1.2.3.4/tcp/9001

# Custom P2P listen address
cargo run -p vurn-server -- --listen-p2p /ip4/0.0.0.0/tcp/9002
```

### Options

```
VurnChat P2P Node v2

Usage:
  vurn-server [OPTIONS]

Options:
  --port <PORT>         WS/WSS gateway port (default: 9000)
  --listen-p2p <ADDR>   P2P listen addr (default: /ip4/0.0.0.0/tcp/0)
  --bootstrap <ADDR>    Bootstrap P2P node (repeatable)
  --cert <FILE>         TLS certificate (enables WSS)
  --key <FILE>          TLS private key  (enables WSS)
  --help, -h            Show this help

Examples:
  vurn-server
  vurn-server --port 8080
  vurn-server --listen-p2p /ip4/0.0.0.0/tcp/9002
  vurn-server --cert cert.pem --key key.pem --port 443
  vurn-server --bootstrap /ip4/1.2.3.4/tcp/9001
```

### Health Endpoint

```
GET /health  →  200 OK          (P2P connected)
GET /health  →  503 Unavailable  (P2P not connected)
```

The `p2p_connected` flag is set on `PeerDiscovered` and `ListeningOn` events.

### Rate Limiting

Per-client token bucket on WS operations:

| Operation  | Rate | Scope |
|-----------|------|-------|
| Mailbox store | 10/s | Per WS client |
| Profile lookup | 1/s | Per WS client |
| All others | unlimited | |

Rate limiters are created on WS connect and removed on disconnect.

### What the Server Does NOT Know

| Property | Status |
|----------|--------|
| Message contents | ❌ Encrypted end-to-end, server is blind |
| Sender/recipient identity | ❌ Opaque hashes only |
| Username | ❌ BlindIdentity — HMAC-based, never sees plaintext |
| Key material | ❌ Never transmitted over wire |
| Ed25519 signing key | ❌ Generated per-node, never leaves P2P layer |

---

## 🌐 Web Client (`vurn-web`)

### Tech Stack

- **Leptos 0.6** — reactive Rust UI framework (CSR)
- **wasm-bindgen** — Rust ↔ JavaScript bridge
- **Trunk** — WASM bundler
- **`rexie`** — IndexedDB wrapper for encrypted local persistence

### Features

- **Post-quantum key generation** — ML-KEM-1024 in the browser
- **Blind username registration** — HMAC-based, server never knows the username
- **Invite links + QR codes** — P2P contact addition without server round-trip
- **Safety numbers** — 12×5-digit fingerprint, Signal-style verification
- **Encrypted profiles** — master password derived via PBKDF2, stored in IndexedDB
- **Password strength meter** — SVG progress border + requirement checklist
- **WS auto-reconnect** — exponential backoff (1s → 2s → 4s → … → 30s cap)
- **Message queue** — messages sent while offline are queued, flushed on reconnect
- **Reconnect banner** — gold warning bar showing "Reconnecting in Xs…"
- **Zero traces** — close the tab, everything is erased from RAM

### Build

```bash
cd web-client
trunk serve --port 8080
```

---

## 🧪 Testing

```bash
# Core cryptography (24+ tests)
cargo test -p vurn-core

# P2P integration (same-node + cross-node DHT + profile DHT + envelope crypto)
cargo test -p vurn-server --test p2p_test -- --test-threads=1 --nocapture

# Check everything compiles
cargo check --workspace
cargo check --target wasm32-unknown-unknown -p vurn-web

# DHT key helpers + envelope unit tests
cargo test -p vurn-server -- dht
```

---

## 📁 Project Structure

```
VurnChat/
├── Cargo.toml                    # Workspace root
├── README.md                     # ← You are here
├── .gitignore
├── install.sh                    # Quick-start install script
│
├── core/                         # vurn-core: cryptographic engine
│   ├── Cargo.toml                # ml-kem, aes-gcm, sha2, hmac, pbkdf2
│   └── src/
│       ├── lib.rs                # VurnCipher: generate_keypair, encrypt, decrypt, fingerprint
│       └── identity.rs           # BlindProfileManager: blind registration, invite links, QR
│
├── server/                       # vurn-server: P2P node + WS gateway
│   ├── Cargo.toml                # libp2p, axum, tokio, sled, ed25519-dalek, bincode, rustls
│   ├── tests/
│   │   └── p2p_test.rs           # P2P integration tests (same-node + cross-node + profile)
│   └── src/
│       ├── main.rs               # CLI args, TLS, graceful shutdown, P2P event handler
│       ├── lib.rs                # Re-exports for integration tests
│       ├── ws.rs                 # WS gateway: health, rate limiting, GossipSub, mailbox, profiles
│       ├── mailbox.rs            # MailboxManager: Sled backup with seq-based dedup
│       └── p2p/
│           ├── mod.rs            # Module re-exports
│           ├── node.rs           # P2PNode: libp2p Swarm, state machine, parallel probing,
│           │                     #   peer reconnect, GossipSub, relay+dcutr, profile queries
│           └── dht.rs            # DhtEnvelope, key format (vmb_/vup_), sign/verify, serialization
│
└── web-client/                   # vurn-web: browser client (WASM)
    ├── Cargo.toml                # leptos, wasm-bindgen, web-sys, rexie
    ├── index.html                # Trunk entry point
    ├── style.css                 # Telegram-inspired dark theme UI
    └── src/
        ├── lib.rs                # #[wasm_bindgen(start)] → mount_to_body(App)
        ├── app.rs                # App component: login → connect → chat + WS auto-reconnect
        ├── login.rs              # Master password creation/unlock
        ├── sidebar.rs            # Contact list, resize, identity section
        ├── compose.rs            # Message input with auto-resize
        ├── modals.rs             # Profile, safety numbers, invite, add contact modals
        └── storage.rs            # IndexedDB: encrypted profile, contacts, messages
```

---

## 🛡️ Security Model

| Property | Implementation |
|----------|---------------|
| **Encryption** | ML-KEM-1024 + AES-256-GCM (hybrid) |
| **Authentication** | GCM authentication tag (16 bytes) |
| **Key exchange** | ML-KEM encapsulation per message |
| **Post-quantum** | Lattice-based (NIST FIPS 203) |
| **Forward secrecy** | Ephemeral shared key per message |
| **Transport** | TLS/WSS (optional), libp2p Noise (always) |
| **Username privacy** | BlindIdentity — HMAC + AES-GCM, server never sees plaintext |
| **Mailbox integrity** | DhtEnvelope — Ed25519 signatures on every record |
| **Server knowledge** | Zero — opaque hashes only |
| **Local persistence** | IndexedDB (browser), Sled (server), both AES-256-GCM encrypted |
| **Randomness** | OS entropy (`/dev/urandom` / `crypto.getRandomValues`) |
| **Memory safety** | Rust + `#![forbid(unsafe_code)]` in core |
| **Key zeroization** | `zeroize` crate — memory wiped on drop |

---

## ✅ Implemented Features (Post-Refactor Roadmap)

### Phase 1 — Reliability ✅
- [x] **WS auto-reconnect** — exponential backoff, message queue for offline retry, reconnection banner
- [x] **P2P reconnect** — automatic re-dial on connection loss with per-peer exponential backoff
- [x] **DHT store retry** — `Quorum::Majority` for mailbox and profile operations
- [x] **Sled dedup** — `(user_hash, seq)` as key, deduplicate on retrieval
- [x] **Persistent Ed25519 key** — _not yet persisted_ (regenerated on restart)

### Phase 2 — Distribution ✅
- [x] **Distributed profiles** — `vup_<search_index>` keys in DHT with oneshot lookups
- [x] **GossipSub for realtime** — online delivery via GossipSub, DHT as persistent fallback
- [x] **NAT traversal** — libp2p relay + dcutr + hole-punching configured
- [x] **Persistent peer store** — peer addresses saved to Sled, re-dialed on startup (batched 5/500ms)

### Phase 3 — Production ✅
- [x] **Rate limiting** — per-client token bucket (10/s store, 1/s lookup) on WS operations
- [x] **Health endpoint** (`GET /health`) — returns 200/503 based on P2P connection state
- [x] **Graceful shutdown** — both SIGTERM and SIGINT handled, server drains connections
- [ ] **Docker image** — _planned_ (deferred: curl|sh install is lighter)
- [ ] **Public bootstrap nodes** — _planned_ (needs infrastructure)

### Phase 4 — Mobile & Advanced
- [ ] **Push notifications** — APNs/FCM relay for mobile delivery
- [ ] **Mobile WASM** — PWA + service worker for offline support
- [ ] **Disappearing messages** — expiring DHT records
- [ ] **Group chats** — MLS (Message Layer Security) over GossipSub
- [ ] **Audio/video calls** — WebRTC signalling over libp2p

---

## 🔬 Architecture Decisions

### Why sequential probing instead of an index key?

Removing the `vmb_<hash>_index` key eliminates a **write amplification** problem:
every `MailboxStore` required two DHT writes (index + data). Now it's one write
with speculative probing on restart. For heavy users (1000+ messages), probing
is 10× faster with parallel windows.

### Why DhtEnvelope instead of libp2p record signing?

libp2p records have built-in signatures, but they don't cover the recipient hash.
DhtEnvelope extends the verify buffer to include `recipient_hash`, providing
**recipient binding** — a message stored by Alice for Bob cannot be verified by Eve,
even if she knows the sender's public key.

### Why in-memory HashMap for indices?

The index only changes when a message is stored (rare per-user: ~1 write/second).
Storing it in DHT added latency and write amplification. In-memory is fast and
safe — on restart, speculative probing reconstructs it in ~1-3 seconds.

### Why always DHT fallback for GossipSub?

GossipSub provides realtime delivery for online users, but DHT mailbox serves as
persistent storage. Even if the recipient is online, storing in DHT ensures the
message survives node restarts and network partitions. The overhead is one
additional DHT `put_record` per message.

### Why last-write-wins for DHT profiles?

DHT has no built-in consensus or auth. Encrypted blobs under `vup_<search_index>`
are last-write-wins. Since the blob is AES-GCM encrypted with the sender's key,
only the legitimate owner can create a valid blob. The TOCTOU race window
(lookup → store) is small (~10s) and acceptable for username registration.

---

## 📜 License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

---

<p align="center">
  <sub>
    Built with ❤️ and Rust. <br>
    No JavaScript was harmed in the making of this messenger.<br>
    <code>#![forbid(unsafe_code)]</code>
  </sub>
</p>
