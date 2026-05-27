//! # P2P Network Module
//!
//! Decentralised networking layer for VurnChat using libp2p.
//!
//! This module turns the VurnChat server from a simple WebSocket relay
//! into a fully distributed P2P node. Nodes discover each other via
//! Kademlia DHT, exchange encrypted messages directly, and use the DHT
//! as a distributed mailbox for offline recipients.

pub mod node;
pub mod dht;

pub use node::{P2PNode, NodeEvent, NodeCommand};
pub use dht::{mailbox_index_key, mailbox_seq_key, parse_user_hash_from_key, encode_mailbox_message, decode_mailbox_message, encode_index, decode_index};
