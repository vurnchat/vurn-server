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

