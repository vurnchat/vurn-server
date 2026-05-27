//! # vurn-server (v2) — Pure P2P Node
//!
//! VurnChat server runs as a fully distributed P2P node with a local
//! WebSocket gateway for the browser client.
//!
//! ## Usage
//! ```text
//! vurn-server                              # P2P + WS on :9000
//! vurn-server --port 8080                  # WS on :8080
//! vurn-server --bootstrap /ip4/1.2.3.4/tcp/9001  # Join existing DHT
//! ```

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error};

mod p2p;
mod ws;
mod mailbox;

use p2p::{P2PNode, NodeEvent, NodeCommand};
use mailbox::MailboxManager;

// ── CLI args ────────────────────────────────────────────────────────

struct CliArgs {
    ws_port: u16,
    p2p_listen: String,
    bootstrap_addrs: Vec<String>,
}

impl CliArgs {
    fn parse() -> Self {
        let raw: Vec<String> = std::env::args().collect();
        let mut ws_port = 9000u16;
        let mut p2p_listen = "/ip4/0.0.0.0/tcp/0".to_string();
        let mut bootstrap = Vec::new();

        let mut i = 1;
        while i < raw.len() {
            match raw[i].as_str() {
                "--help" | "-h" => {
                    eprintln!("VurnChat P2P Node v2");
                    eprintln!();
                    eprintln!("Usage:");
                    eprintln!("  vurn-server [OPTIONS]");
                    eprintln!();
                    eprintln!("Options:");
                    eprintln!("  --port <PORT>         WS gateway port (default: 9000)");
                    eprintln!("  --listen-p2p <ADDR>   P2P listen addr (default: /ip4/0.0.0.0/tcp/0)");
                    eprintln!("  --bootstrap <ADDR>    Bootstrap node (repeatable)");
                    eprintln!("  --help, -h            Show this help");
                    eprintln!();
                    eprintln!("Examples:");
                    eprintln!("  vurn-server");
                    eprintln!("  vurn-server --port 8080 --listen-p2p /ip4/0.0.0.0/tcp/9001");
                    eprintln!("  vurn-server --bootstrap /ip4/1.2.3.4/tcp/9001");
                    std::process::exit(0);
                }
                "--port" => {
                    i += 1;
                    ws_port = raw.get(i).expect("--port requires a value")
                        .parse().expect("--port must be a number");
                }
                "--listen-p2p" => {
                    i += 1;
                    p2p_listen = raw.get(i).expect("--listen-p2p requires an address").clone();
                }
                "--bootstrap" => {
                    i += 1;
                    bootstrap.push(raw.get(i).expect("--bootstrap requires a multiaddr").clone());
                }
                other => {
                    eprintln!("Unknown argument: {other}");
                    std::process::exit(1);
                }
            }
            i += 1;
        }

        CliArgs {
            ws_port,
            p2p_listen,
            bootstrap_addrs: bootstrap,
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = CliArgs::parse();
    info!("VurnChat P2P node starting...");

    // ── 1. Start P2P node ──
    let (p2p_event_tx, mut p2p_event_rx) = mpsc::channel::<NodeEvent>(256);

    let p2p_node = match P2PNode::new(&args.p2p_listen, p2p_event_tx).await {
        Ok(node) => {
            info!("P2P node started: {}", node.peer_id);
            node
        }
        Err(e) => {
            error!("Failed to start P2P node: {e}");
            std::process::exit(1);
        }
    };

    // Bootstrap to known nodes
    for bs_addr in &args.bootstrap_addrs {
        if let Ok(addr) = bs_addr.parse::<libp2p::Multiaddr>() {
            let _ = p2p_node.cmd_tx.send(NodeCommand::Dial { addr }).await;
            info!("Dialing bootstrap: {bs_addr}");
        } else {
            warn!("Invalid bootstrap address: {bs_addr}");
        }
    }

    // ── 2. Start Mailbox Manager ──
    let mailbox_mgr = MailboxManager::new(&p2p_node);

    // ── 3. Build WS Gateway State ──
    let ws_state: ws::SharedState = Arc::new(RwLock::new(ws::GatewayStateInner {
        p2p_cmd_tx: Some(p2p_node.cmd_tx.clone()),
        ..Default::default()
    }));

    // ── 4. Spawn P2P event handler ──
    let ws_state_ev = ws_state.clone();
    let mailbox_mgr_ev = mailbox_mgr;
    let p2p_cmd_ev = p2p_node.cmd_tx.clone();

    tokio::spawn(async move {
        handle_p2p_events(&mut p2p_event_rx, &ws_state_ev, &mailbox_mgr_ev, &p2p_cmd_ev).await;
    });

    // ── 5. Start axum server ──
    let ws_addr = format!("127.0.0.1:{}", args.ws_port);
    let app = crate::ws::build_gateway_router().with_state(ws_state.clone());

    info!("WS Gateway on {ws_addr}");
    info!("Connect browser to: ws://{ws_addr}/ws");
    info!("Press Ctrl+C to stop");

    let listener = tokio::net::TcpListener::bind(&ws_addr)
        .await
        .expect("Failed to bind WS gateway address");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    info!("Server shut down gracefully");
}

// ── P2P Event Handler ──────────────────────────────────────────────

async fn handle_p2p_events(
    rx: &mut mpsc::Receiver<NodeEvent>,
    ws_state: &ws::SharedState,
    mailbox_mgr: &MailboxManager,
    p2p_cmd_tx: &mpsc::Sender<NodeCommand>,
) {
    while let Some(event) = rx.recv().await {
        match event {
            NodeEvent::MessageReceived { from, data } => {
                info!("P2P message from {from} ({} bytes)", data.len());
                let map = ws_state.read().await;
                for (_, senders) in map.clients.iter() {
                    for tx in senders {
                        let _ = tx.send(data.clone());
                    }
                }
            }
            NodeEvent::MailboxRetrieved { key, value } => {
                let frames = mailbox_mgr.handle_retrieval_result(key, value).await;
                if let Some(frame_list) = frames {
                    let map = ws_state.read().await;
                    for frame in frame_list {
                        for (_, senders) in map.clients.iter() {
                            for tx in senders {
                                let _ = tx.send(frame.clone());
                            }
                        }
                    }
                }
            }
            NodeEvent::PeerDiscovered(peer_id) => {
                info!("P2P peer discovered: {peer_id}");
            }
            NodeEvent::ListeningOn(addr) => {
                info!("P2P listening on: {addr}");
                // Bootstrap DHT now that we have a listen address
                let _ = p2p_cmd_tx.send(NodeCommand::Bootstrap).await;
            }
            NodeEvent::Error(msg) => {
                warn!("P2P error: {msg}");
            }
        }
    }
}

// ── Shutdown ────────────────────────────────────────────────────────

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = std::pin::pin!(async {
        #[cfg(unix)]
        {
            let mut stream = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            )
            .expect("Failed to install SIGTERM handler");
            stream.recv().await;
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<()>().await;
        }
    });

    tokio::select! {
        _ = ctrl_c => {}
        _ = &mut term => {}
    }
    info!("Shutdown signal received...");
}
