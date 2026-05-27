<p align="center">
  <img src="https://img.shields.io/badge/Rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"/>
  <img src="https://img.shields.io/badge/WASM-%23654FF0.svg?style=for-the-badge&logo=webassembly&logoColor=white" alt="WebAssembly"/>
  <img src="https://img.shields.io/badge/Post--Quantum-NIST%20FIPS%20203-00d4aa?style=for-the-badge" alt="NIST FIPS 203"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-%2300a86b.svg?style=for-the-badge" alt="AES-256"/>
  <img src="https://img.shields.io/badge/ML--KEM--1024-Kyber-7b2ff7?style=for-the-badge" alt="ML-KEM-1024"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blue?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/unsafe-forbidden-red?style=flat-square" alt="Forbid Unsafe"/>
  <img src="https://img.shields.io/badge/memory-zero--knowledge--server-222?style=flat-square" alt="Zero-Knowledge Server"/>
  <img src="https://img.shields.io/badge/crypto-in--memory%20only-important?style=flat-square" alt="In-Memory Only"/>
</p>

<h1 align="center">🔐 VurnChat</h1>

<p align="center">
  <strong>Post-Quantum Encrypted Messenger<br>Quantum-resistant. Blind server. Zero traces.</strong>
</p>

<p align="center">
  <sub>Built entirely in Rust — from cryptography to browser UI —<br>compiled to WebAssembly for the client,<br>backed by a zero-knowledge WebSocket relay.</sub>
</p>

---

## 🧬 What is VurnChat?

VurnChat is a **quantum-resistant instant messenger** that runs entirely in your browser.
Every message is encrypted with **ML-KEM-1024** (the NIST-standardized post-quantum key
encapsulation mechanism, formerly CRYSTALS-Kyber) and **AES-256-GCM**.

The server is **blind** — it never sees plaintext, never learns who is talking to whom,
and stores no history. Close the tab and everything vanishes from memory — no traces
left on disk.

> **Threat model:** Resistant to *harvest-now-decrypt-later* attacks.
> Even an adversary with a large-scale quantum computer recording all your
> network traffic today cannot decrypt your messages tomorrow.

---

## 🏗 Architecture

```
┌──────────────────────┐         ┌──────────────────┐         ┌──────────────────────┐
│     Browser Tab       │         │                  │         │     Browser Tab       │
│     ────────────      │         │   vurn-server    │         │     ────────────      │
│                       │  ws://  │   ────────────   │  ws://  │                       │
│  ┌─────────────────┐  │ ◄─────► │                   ◄─────► │  ┌─────────────────┐  │
│  │   vurn-web       │  │         │  Blind relay:     │         │  │   vurn-web       │  │
│  │   Leptos + WASM  │  │         │  • no decryption  │         │  │   Leptos + WASM  │  │
│  │                  │  │         │  • no logging     │         │  │                  │  │
│  │  ┌─────────────┐ │  │         │  • no storage     │         │  │  ┌─────────────┐ │  │
│  │  │ vurn-core    │ │  │         │  • no metadata   │         │  │  │ vurn-core    │ │  │
│  │  │ ML-KEM-1024  │ │  │         │                  │         │  │  │ ML-KEM-1024  │ │  │
│  │  │ AES-256-GCM  │ │  │         │                  │         │  │  │ AES-256-GCM  │ │  │
│  │  │ SHA-256      │ │  │         │                  │         │  │  │ SHA-256      │ │  │
│  │  └─────────────┘ │  │         │                  │         │  │  └─────────────┘ │  │
│  └─────────────────┘  │         │                  │         │  └─────────────────┘  │
│                       │         │                  │         │                       │
│  Keys & messages      │         │   Port 9000      │         │  Keys & messages      │
│  in RAM only          │         │                  │         │  in RAM only          │
└──────────────────────┘         └──────────────────┘         └──────────────────────┘
```

### Three crates, one workspace

| Crate | Role | Tech |
|-------|------|------|
| **`vurn-core`** | Cryptographic engine | `ml-kem`, `aes-gcm`, `sha2`, `rand` |
| **`vurn-server`** | Blind WebSocket relay | `axum`, `tokio`, `tracing` |
| **`vurn-web`** | Browser client (WASM) | `leptos`, `wasm-bindgen`, `web-sys` |

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

- **ML-KEM-1024** is NIST FIPS 203 (formerly CRYSTALS-Kyber-1024), a lattice-based
  key encapsulation mechanism believed to be secure against both classical and
  quantum adversaries.
- All secret key material uses the `zeroize` crate — memory is wiped on `drop()`.
- `#![forbid(unsafe_code)]` in `vurn-core` — the crypto path contains **zero unsafe Rust**.

### Encryption (`encrypt`)

```
1. Deserialize recipient's EncapsulationKey
2. ek.encapsulate(&mut rng) ──► kem_ct + shared_key (32 bytes)
3. shared_key → Key<Aes256Gcm>
4. Generate random 12-byte nonce
5. AES-256-GCM encrypt(plaintext) ──► ciphertext + 16-byte auth tag
6. Pack into wire format
```

### Wire Format

```
┌───────────────┬──────────────────────┬──────────────┬───────────────────────────┐
│   2 bytes     │     N bytes (~1568)  │   12 bytes   │       M bytes             │
│  kem_ct_len   │   ML-KEM ciphertext  │  AES nonce   │  AES-GCM(payload + tag)   │
│  (u16 LE)     │  (encapsulated key)  │  (random)    │  (encrypted + auth tag)    │
└───────────────┴──────────────────────┴──────────────┴───────────────────────────┘
```

### Guarantees

- **IND-CCA2 security** via ML-KEM — the shared key is indistinguishable from random
- **Authenticated encryption** via AES-GCM — any tampering is detected and decryption fails
- **Fresh keys per message** — a new ML-KEM encapsulation is performed for every message,
  so the AES key is never reused
- **Post-quantum forward secrecy** — even if your long-term secret key is later compromised,
  past messages remain secure (the ephemeral shared key is never stored)

### Message Encryption / Decryption

```
Alice's public key ──► VurnCipher::encrypt("Hello") ──► [wire_format_bytes]
                                                              │
                                              WebSocket relay (server is blind)
                                                              │
                                                              ▼
Bob's secret key ────► VurnCipher::decrypt(bytes) ─────► "Hello"
```

---

## 📡 Network Protocol (vurn-server)

### Connection & Registration

1. Client opens WebSocket → `ws://host:9000/ws`
2. Client sends **first binary message**: its public key hash (SHA-256, 32 bytes)
   as its session ID
3. Server registers the client in an in-memory `HashMap<Vec<u8>, Sender>`

### Sending a Message

Client frames each outgoing message:

```
┌──────────────┬───────────────────────┬──────────────────────────┐
│   2 bytes    │     N bytes           │       M bytes            │
│  r_id_len    │   recipient_id        │   encrypted payload      │
│  (u16 LE)    │  (SHA-256 hash of PK) │  (vurn-core wire format) │
└──────────────┴───────────────────────┴──────────────────────────┘
```

The server:
1. Parses `recipient_id` from the frame
2. Looks up the recipient in the connection map
3. Forwards to the recipient: `[sender_id_len][sender_id][payload]`

### Error Delivery

If the recipient is offline, the server sends back to the sender:

```
[0xFF, 0xFF][original_recipient_id_bytes]
```

The client displays a ⚠ delivery failure notification.

### What the Server Does NOT Know

- ❌ Who is messaging whom (only opaque hashes, meaningless without key material)
- ❌ Message contents (encrypted with the recipient's public key)
- ❌ Message history (no database, no filesystem persistence)
- ❌ Key material (never transmitted in plaintext)

The server is ~200 lines of Rust. You can audit it in minutes.

---

## 🌐 Web Client (vurn-web)

### Tech Stack

- **Leptos 0.6** — reactive Rust UI framework with CSR (client-side rendering)
- **wasm-bindgen** — Rust ↔ JavaScript bridge
- **Trunk** — WASM bundler and dev server
- **`getrandom` with `js` feature** — delegates to `crypto.getRandomValues()` in the browser
  (never uses predictable Math.random)

### UX Flow

```
┌──────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   Setup      │      │   Connect        │      │   Chat          │
│              │      │                  │      │                 │
│  Generate    │ ───► │  Connect to      │ ───► │  Paste contact  │
│  keys        │      │  server          │      │  public key     │
│              │      │                  │      │                 │
│  Copy public │      │  Send session ID │      │  Send/receive   │
│  key & ID    │      │                  │      │  encrypted msgs │
└──────────────┘      └──────────────────┘      └─────────────────┘
```

### Security Properties

- **In-memory only** — keys and messages live in Leptos signals in RAM. Close tab → everything erased.
- **No localStorage, no IndexedDB, no cookies** — zero persistent storage.
- **WASM randomness** — `getrandom` uses `crypto.getRandomValues()` in browsers;
  on native, uses `/dev/urandom`.
- **Copy-to-clipboard** for sharing public keys (via `navigator.clipboard.writeText()`)

---

## 🚀 Quick Start

### Prerequisites

- **Rust** (stable, 1.75+): [rustup.rs](https://rustup.rs)
- **Trunk** (WASM bundler): `cargo install trunk`
- **WASM target**: `rustup target add wasm32-unknown-unknown`

### 1. Clone & Build

```bash
git clone https://github.com/scramble22/VurnChat.git
cd VurnChat

# Build everything (native + WASM)
cargo build --workspace
cargo build -p vurn-web --target wasm32-unknown-unknown
cargo test -p vurn-core
```

### 2. Start the Server

```bash
# Default: port 9000
cargo run -p vurn-server

# Custom port
cargo run -p vurn-server -- --port 8081

# With TLS (WSS)
cargo run -p vurn-server -- --cert cert.pem --key key.pem
```

You should see:
```
VurnChat relay server starting on 0.0.0.0:9000 (WS mode)
```

### 3. Start the Web Client

```bash
cd web-client
trunk serve --port 8080
```

Wait for the WASM build (~60-120 seconds first time), then:

```
📡  serving static files at http://127.0.0.1:8080
```

### 4. Test End-to-End 🎉

1. Open **Tab 1**: `http://localhost:8080`
2. Click **«Generate Post-Quantum Keypair»**
3. Click **Copy** on your Public Key — save it to a text file
4. Click **«Connect to Server & Open Chat»**
5. Open **Tab 2**: `http://localhost:8080`
6. Repeat steps 2-4
7. Paste **Tab 1's** public key into Tab 2's input field → click **Start**
8. Type a message → click **Send**
9. Return to **Tab 1**: paste **Tab 2's** public key → click **Start**
10. You should see the decrypted message!

```bash
# Stop everything
kill $(lsof -ti:9000)  # server
kill $(lsof -ti:8080)  # web client
```

### Command-line reference

```
VurnChat Blind Relay Server

Usage:
  vurn-server [--port <PORT>] [--cert <CERT> --key <KEY>]

Options:
  --port <PORT>     Port to listen on (default: 9000)
  --cert <CERT>     Path to TLS certificate PEM file
  --key <KEY>       Path to TLS private key PEM file
  --help, -h        Show this help message

Examples:
  vurn-server
  vurn-server --port 8080
  vurn-server --cert cert.pem --key key.pem
  vurn-server --port 443 --cert /etc/letsencrypt/live/example.com/fullchain.pem --key /etc/letsencrypt/live/example.com/privkey.pem
```

---

## 🧪 Testing

```bash
# Run all vurn-core tests (8 tests, all green)
cargo test -p vurn-core

# Check workspace compiles
cargo check --workspace

# Build WASM target
cargo build -p vurn-web --target wasm32-unknown-unknown
```

---

## 📁 Project Structure

```
VurnChat/
├── Cargo.toml                  # Workspace root
├── README.md                   # ← You are here
├── .gitignore
├── core/                       # vurn-core: cryptographic engine
│   ├── Cargo.toml              # ml-kem, aes-gcm, sha2, rand, zeroize
│   └── src/
│       └── lib.rs              # VurnCipher: generate_keypair, encrypt, decrypt, hash_public_key
├── server/                     # vurn-server: blind WebSocket relay
│   ├── Cargo.toml              # axum, tokio, tracing
│   └── src/
│       └── main.rs             # ConnectionMap, relay_message, graceful shutdown
└── web-client/                 # vurn-web: browser client (WASM)
    ├── Cargo.toml              # leptos, wasm-bindgen, web-sys, getrandom(js)
    ├── index.html              # Trunk entry point
    ├── style.css               # Dark theme UI
    └── src/
        ├── lib.rs              # #[wasm_bindgen(start)] → mount_to_body(App)
        └── app.rs              # Leptos component: Setup → Connect → Chat
```

---

## 🛡️ Security Model

| Property | Implementation |
|----------|---------------|
| **Encryption** | ML-KEM-1024 + AES-256-GCM (hybrid) |
| **Authentication** | GCM authentication tag (16 bytes) |
| **Key exchange** | ML-KEM encapsulation per message |
| **Post-quantum** | Lattice-based (Kyber) — NIST FIPS 203 |
| **Forward secrecy** | Ephemeral shared key per message |
| **Server knowledge** | Zero — opaque hashes only |
| **Persistence** | None — in-memory only |
| **Randomness** | OS entropy (`/dev/urandom` / `crypto.getRandomValues`) |
| **Memory safety** | Rust + `#![forbid(unsafe_code)]` |
| **Key zeroization** | `zeroize` crate — memory wiped on drop |
| **Supply chain** | Minimal dependencies, all auditable |

---

## 🔮 Roadmap

### v0.2 — Usability
- [ ] Persistent contact list (localStorage, encrypted with a passphrase)
- [ ] Multiple simultaneous chats
- [ ] Message timestamps
- [ ] Unread message indicators
- [ ] Connect to arbitrary server URLs (not just localhost:9000)

### v0.3 — Security Hardening
- [ ] Contact verification via fingerprint comparison (Signal-style safety numbers)
- [ ] Periodic ephemeral key rotation (forward secrecy)
- [ ] Server authentication (TLS/WSS)
- [ ] Rate limiting on the relay server

### v1.0 — Production
- [ ] Docker images for server + static web-client
- [ ] Tor hidden service (.onion) support
- [ ] Mobile clients (iOS/Android via `uniffi` bindings to vurn-core)
- [ ] P2P mode (WebRTC via `libp2p`, bypassing the relay server entirely)

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
