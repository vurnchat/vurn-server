<p align="center">
  <img src="https://img.shields.io/badge/Rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"/>
  <img src="https://img.shields.io/badge/WASM-%23654FF0.svg?style=for-the-badge&logo=webassembly&logoColor=white" alt="WebAssembly"/>
  <img src="https://img.shields.io/badge/Post--Quantum-NIST%20FIPS%20203-00d4aa?style=for-the-badge" alt="NIST FIPS 203"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-%2300a86b.svg?style=for-the-badge" alt="AES-256"/>
  <img src="https://img.shields.io/badge/ML--KEM--1024-Kyber-7b2ff7?style=for-the-badge" alt="ML-KEM-1024"/>
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
│  │  ┌─────────────┐ │ │         │  │                 │  │        │  │                 │  │
│  │  │ vurn-core    │ │ │         │  │ MailboxManager  │  │        │  │ MailboxManager  │  │
│  │  │ ML-KEM-1024  │ │ │         │  │ (Sled backup)   │  │        │  │ (Sled backup)   │  │
│  │  │ AES-256-GCM  │ │ │         │  └─────────────────┘  │        │  └─────────────────┘  │
│  │  │ SHA-256      │ │ │         │                       │        │                       │
│  │  └─────────────┘ │ │         │  WS Gateway (:9000)    │        │  WS Gateway (:9001)    │
│  └─────────────────┘  │         └──────────────────────┘        └──────────────────────┘
│                       │
│  Keys in RAM only     │
└───────────────────────┘
```

### Three crates, one workspace

| Crate | Role | Tech |
|-------|------|------|
| **`vurn-core`** | Cryptographic engine | `ml-kem`, `aes-gcm`, `sha2`, `hmac`, `pbkdf2` |
| **`vurn-server`** | P2P node + WS gateway | `libp2p`, `axum`, `tokio`, `sled`, `rustls` |
| **`vurn-web`** | Browser client (WASM) | `leptos`, `wasm-bindgen`, `web-sys`, `rexie` |

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

### Mailbox: Sequential DHT Keys

Kademlia stores **one value per key**. To support multiple offline messages,
VurnChat uses sequential key composition:

```
vmb_<recipient_hash>_index  →  u64 (current message count)
vmb_<recipient_hash>_00001  →  message #1
vmb_<recipient_hash>_00002  →  message #2
...
```

**Store flow:**
1. Read an **in-memory** `HashMap<Vec<u8>, u64>` index (synchronous, no DHT round-trip)
2. Increment → `put_record` at `vmb_<hash>_<seq>`
3. Update in-memory index
4. Best-effort `put_record` at `vmb_<hash>_index` (DHT hint for other nodes)

**Retrieve flow (DHT state machine):**
1. `get_record` for `vmb_<hash>_index` → get count
2. For `seq = 1..=count`: `get_record` for each `vmb_<hash>_<seq>`
3. Collect all messages → emit `MailboxRetrieved` event

### Local Backup

Every message is backed up to a **Sled embedded database** before DHT storage.
If the DHT is unavailable or `QuorumFailed`, messages are not lost.

### Privacy

Messages are delivered **only** to the matching `user_hash` in the WS gateway —
not broadcast to all connected clients (critical privacy fix).

### Profiles Are Local (Not Distributed)

Username registrations (`blind_profiles`) live in **each node's local memory**,
not in the DHT. Registering a username on Node A does not make it visible
on Node B. Profile distribution across the P2P network is a future enhancement.
For cross-node discovery, use **invite links** (direct P2P contact addition)
or ensure both users connect to the same node.

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
  --key <FILE>          TLS private key (enables WSS)
  --help, -h            Show this help

Examples:
  vurn-server
  vurn-server --port 8080
  vurn-server --listen-p2p /ip4/0.0.0.0/tcp/9002
  vurn-server --cert cert.pem --key key.pem --port 443
  vurn-server --bootstrap /ip4/1.2.3.4/tcp/9001
```

### What the Server Does NOT Know

| Property | Status |
|----------|--------|
| Message contents | ❌ Encrypted end-to-end, server is blind |
| Sender/recipient identity | ❌ Opaque hashes only, meaningless without key material |
| Username | ❌ BlindIdentity — HMAC-based, server never sees plaintext |
| Message history (Sled) | ❌ Local backup, node-specific |
| Key material | ❌ Never transmitted over the wire |

### What Exists (and Why)

| Data | Where | Purpose |
|------|-------|---------|
| DHT records | Kademlia (global) | Offline mailbox — any node can retrieve |
| Sled backup | Each node (local) | Durability if DHT is unavailable |
| Blind profiles | Node memory (local) | Username → public key lookup (NOT in DHT) |
| Client data | IndexedDB (browser) | Encrypted contacts, messages, profile |

---

## 🌐 Web Client (`vurn-web`)

### Tech Stack

- **Leptos 0.6** — reactive Rust UI framework (CSR)
- **wasm-bindgen** — Rust ↔ JavaScript bridge
- **Trunk** — WASM bundler
- **`getrandom` (js feature)** — `crypto.getRandomValues()` in browser
- **`rexie`** — IndexedDB wrapper for encrypted local persistence

### Features

- **Post-quantum key generation** — ML-KEM-1024 in the browser
- **Blind username registration** — HMAC-based, server never knows the username
- **Invite links + QR codes** — P2P contact addition without server round-trip
- **Safety numbers** — 12×5-digit fingerprint, Signal-style verification
- **Encrypted profiles** — master password derived via PBKDF2, stored in IndexedDB
- **Zero traces** — close the tab, everything is erased from RAM

### Build

```bash
cd web-client
trunk serve --port 8080
```

---

## 🧪 Testing

```bash
# Core cryptography (24 tests)
cargo test -p vurn-core

# P2P integration (same-node + cross-node DHT)
cargo test -p vurn-server --test p2p_test -- --test-threads=1 --nocapture

# Check everything compiles
cargo check --workspace
cargo check --target wasm32-unknown-unknown -p vurn-web
```

---

## 📁 Project Structure

```
VurnChat/
├── Cargo.toml                    # Workspace root
├── README.md                     # ← You are here
├── .gitignore
│
├── core/                         # vurn-core: cryptographic engine
│   ├── Cargo.toml                # ml-kem, aes-gcm, sha2, hmac, pbkdf2
│   └── src/
│       ├── lib.rs                # VurnCipher: generate_keypair, encrypt, decrypt, fingerprint
│       └── identity.rs           # BlindProfileManager: blind registration, invite links
│
├── server/                       # vurn-server: P2P node + WS gateway
│   ├── Cargo.toml                # libp2p, axum, tokio, sled, rustls
│   ├── tests/
│   │   └── p2p_test.rs           # P2P integration tests (same-node + cross-node)
│   └── src/
│       ├── main.rs               # CLI args, event handler, TLS, graceful shutdown
│       ├── lib.rs                # Re-exports for integration tests
│       ├── ws.rs                 # WebSocket gateway: registration, relay, mailbox
│       ├── mailbox.rs            # MailboxManager: Sled backup, dedup
│       └── p2p/
│           ├── mod.rs            # Module re-exports
│           ├── node.rs           # P2PNode: libp2p Swarm, state machine, commands
│           └── dht.rs            # Sequential key format, encode/decode helpers
│
└── web-client/                   # vurn-web: browser client (WASM)
    ├── Cargo.toml                # leptos, wasm-bindgen, web-sys, rexie
    ├── index.html                # Trunk entry point
    ├── style.css                 # Dark theme UI
    └── src/
        ├── lib.rs                # #[wasm_bindgen(start)] → mount_to_body(App)
        ├── app.rs                # App component: login → connect → chat
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
| **Transport** | TLS/WSS (optional), libp2p Noise |
| **Username privacy** | BlindIdentity — HMAC + AES-GCM, server never sees plaintext |
| **Server knowledge** | Zero — opaque hashes only |
| **Local persistence** | IndexedDB (browser), Sled (server), both encrypted |
| **Randomness** | OS entropy (`/dev/urandom` / `crypto.getRandomValues`) |
| **Memory safety** | Rust + `#![forbid(unsafe_code)]` |
| **Key zeroization** | `zeroize` crate — memory wiped on drop |

---

## 🔮 Roadmap

### Phase 1 — Security
- [ ] **DHT аутентификация** — подписывать MailboxStore ed25519 ключом, верифицировать при retrieve
- [ ] **Seed in-memory index из DHT** — при старте ноды читать `vmb_<hash>_index` для восстановления счётчика
- [ ] **Rate limiting** — ограничить частоту DHT и WS операций на клиента

### Phase 2 — Reliability
- [ ] **P2P reconnect** — автопереподключение при обрыве P2P соединения
- [ ] **WS auto-reconnect** — клиент переподключается при `onclose`/`onerror`
- [ ] **NAT Traversal** — libp2p relay + dcutr + hole-punching
- [ ] **Graceful shutdown P2P** — дожидаться завершения P2P event loop

### Phase 3 — Production
- [ ] **Dockerfile** + docker-compose
- [ ] **Health endpoint** (`GET /health`)
- [ ] **Persistent peer store** — восстановление routing table после рестарта
- [ ] **Mobile clients** — iOS/Android через uniffi bindings к vurn-core

### Phase 4 — Distribution
- [ ] **Распределённые профили** — хранить `blind_profiles` в DHT, а не локально
- [ ] **GossipSub для realtime** — использовать GossipSub для online-доставки, DHT только для offline mailbox
- [ ] **Public bootstrap ноды** — пул публичных нод по умолчанию (как у IPFS)

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
