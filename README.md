# VurnChat Server

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue)]()

**Quantum-resistant, fully distributed P2P instant messenger.**

VurnChat is a distributed instant messenger that uses a **blind relay server** architecture — the server relays encrypted blobs but never sees plaintext messages or user identities. Messages are encrypted end-to-end with **ML-KEM-1024** (NIST FIPS 203) for key exchange and **AES-256-GCM** for payload encryption, protecting against "harvest-now-decrypt-later" quantum computing attacks.

> **Web client**: The browser-based UI lives in the separate [`vurnchat/vurn-web`](https://github.com/vurnchat/vurn-web) repository.

## Architecture

```
┌──────────────────────┐         ┌─────────────────────────────────────┐
│   P2P Node A          │   P2P   │   P2P Node B                       │
│   ────────────        │ ◄─────► │   ────────────                     │
│                       │         │                                     │
│  ┌─────────────────┐  │         │  ┌─────────────────┐               │
│  │  Kademlia DHT    │  │         │  │  Kademlia DHT    │              │
│  │  - Mailbox       │  │         │  │  - Mailbox       │              │
│  │  - Profiles      │  │         │  │  - Profiles      │              │
│  │  - GossipSub     │  │         │  │  - GossipSub     │              │
│  └─────────────────┘  │         │  └─────────────────┘               │
│                       │         │                                     │
│  ┌─────────────────┐  │         │  ┌─────────────────┐               │
│  │  Sled (backup)   │  │         │  │  Sled (backup)   │              │
│  └─────────────────┘  │         │  └─────────────────┘               │
└──────────────────────┘         └─────────────────────────────────────┘
```

## Repository Structure

This repository contains two crates:

| Crate | Description | Key Dependencies |
|---|---|---|
| `vurn-core` | Cryptographic engine | ML-KEM, AES-GCM, SHA2, HMAC, PBKDF2 |
| `vurn-server` | P2P relay + WebSocket gateway | libp2p (kad, gossipsub, relay, dcutr), axum, sled |

## Quick Start

```bash
# Build the server
cargo build -p vurn-server --release

# Run (plain WS)
./target/release/vurn-server --port 9000

# Run with TLS (WSS)
./target/release/vurn-server --port 443 --cert /etc/letsencrypt/live/example.com/fullchain.pem --key /etc/letsencrypt/live/example.com/privkey.pem

# Run with bootstrap peers
./target/release/vurn-server --port 9000 --bootstrap /ip4/1.2.3.4/tcp/9001
```

## Deploy

A `curl | sh` installer is provided:

```bash
curl -sSL https://raw.githubusercontent.com/vurnchat/vurn-server/main/install.sh | bash
```

Or non-interactively:

```bash
curl -sSL https://raw.githubusercontent.com/vurnchat/vurn-server/main/install.sh | bash -s -- \
  --port 443 \
  --domain vurn.example.com \
  --bootstrap /ip4/1.2.3.4/tcp/9001
```

See [`deploy/`](deploy/) for:
- `vurn.service` — Hardened systemd unit
- `vurn.env` — Environment config template
- `logrotate.conf` — Log rotation config

## Architecture Details

### 📬 Mailbox (DHT)

Messages for offline recipients are stored in the Kademlia DHT under deterministic keys:

```
vmb_<recipient_hash>_<seq>
```

Where `<seq>` is a zero-padded 20-digit decimal number. The node probes the key space using **parallel window probing** to reconstruct the full message sequence after a restart.

### 👤 Profiles (DHT)

Public keys and usernames are published under:

```
vup_<search_index>
```

Using last-write-wins conflict resolution. Lookups are one-shot `get_record` queries with `Quorum::One`.

### 📡 Real-time Delivery

Online peers receive messages instantly via **GossipSub** on topics derived from the recipient's identity hash.

### 🌐 NAT Traversal

Uses libp2p's `relay` and `dcutr` (Direct Connection Upgrade through Relay) for peers behind NAT.

### 🛡️ Cryptography (`vurn-core`)

- **Key Exchange**: ML-KEM-1024 (FIPS 203)
- **Cipher**: AES-256-GCM
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Signing**: Ed25519 (for DHT envelopes)
- **Memory Safety**: `#![forbid(unsafe_code)]` + `zeroize`

All messages are wrapped in a signed `DhtEnvelope` for payload integrity, origin authentication, sequence ordering, and recipient binding.

### 🩺 Health Endpoint

```
GET /health
```

Returns `200 OK` when the P2P node is connected to the network, `503 Service Unavailable` otherwise.

## Testing

```bash
# Unit tests (core)
cargo test -p vurn-core

# Integration tests (P2P + DHT)
cargo test -p vurn-server --test p2p_test -- --test-threads=1 --nocapture
```

## License

MIT OR Apache-2.0
