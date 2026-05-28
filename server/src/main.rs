//! # vurn-server (v2) — Pure P2P Node with WSS Support
//!
//! VurnChat server runs as a fully distributed P2P node with a local
//! WebSocket gateway for the browser client. Supports both plain WS
//! and TLS-encrypted WSS.
//!
//! ## Usage
//! ```text
//! vurn-server                              # WS on :9000
//! vurn-server --port 8080                  # WS on :8080
//! vurn-server --cert cert.pem --key key.pem  # WSS (TLS)
//! vurn-server --bootstrap /ip4/1.2.3.4/tcp/9001  # Join P2P network
//! ```

use rustls::{pki_types::PrivateKeyDer, ServerConfig};
use std::{fs::File, io::BufReader, sync::Arc};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, trace, warn};

mod p2p;
mod ws;
mod mailbox;

use p2p::{P2PNode, NodeEvent, NodeCommand};
use mailbox::MailboxManager;

// ── Server mode ─────────────────────────────────────────────────────

/// Server mode: plain WS or TLS-encrypted WSS.
enum ServerMode {
    Plain,
    Tls { cert_path: String, key_path: String },
}

// ── CLI args ────────────────────────────────────────────────────────

struct CliArgs {
    ws_port: u16,
    p2p_listen: String,
    bootstrap_addrs: Vec<String>,
    mode: ServerMode,
}

impl CliArgs {
    fn parse() -> Self {
        let raw: Vec<String> = std::env::args().collect();
        let mut ws_port = 9000u16;
        let mut p2p_listen = "/ip4/0.0.0.0/tcp/0".to_string();
        let mut bootstrap = Vec::new();
        let mut cert: Option<String> = None;
        let mut key: Option<String> = None;

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
                    eprintln!("  --port <PORT>         WS/WSS gateway port (default: 9000)");
                    eprintln!("  --listen-p2p <ADDR>   P2P listen addr (default: /ip4/0.0.0.0/tcp/0)");
                    eprintln!("  --bootstrap <ADDR>    Bootstrap P2P node (repeatable)");
                    eprintln!("  --cert <FILE>         TLS certificate (enables WSS)");
                    eprintln!("  --key <FILE>          TLS private key  (enables WSS)");
                    eprintln!("  --help, -h            Show this help");
                    eprintln!();
                    eprintln!("Examples:");
                    eprintln!("  vurn-server");
                    eprintln!("  vurn-server --port 8080");
                    eprintln!("  vurn-server --cert cert.pem --key key.pem --port 443");
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
                "--cert" => {
                    i += 1;
                    cert = Some(raw.get(i).expect("--cert requires a path").clone());
                }
                "--key" => {
                    i += 1;
                    key = Some(raw.get(i).expect("--key requires a path").clone());
                }
                other => {
                    eprintln!("Unknown argument: {other}");
                    std::process::exit(1);
                }
            }
            i += 1;
        }

        let mode = match (cert, key) {
            (Some(cert_path), Some(key_path)) => ServerMode::Tls { cert_path, key_path },
            (None, None) => ServerMode::Plain,
            (Some(_), None) | (None, Some(_)) => {
                eprintln!("Error: --cert and --key must be used together");
                std::process::exit(1);
            }
        };

        CliArgs {
            ws_port,
            p2p_listen,
            bootstrap_addrs: bootstrap,
            mode,
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────

    #[tokio::main]
    async fn main() {
        // Ensure a crypto provider is installed for rustls 0.23
        // Using the `ring` provider which is enabled via Cargo features.
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
            .expect("Failed to install rustls crypto provider");
    tracing_subscriber::fmt::init();
    let args = CliArgs::parse();
    info!("VurnChat P2P node starting...");

    // ── 1. Open Sled DB (shared between P2P node and Mailbox manager) ──
    let db_path = format!("vurn_mailbox_{}.db", args.ws_port);
    let sled_db = Arc::new(
        sled::open(&db_path).unwrap_or_else(|e| {
            warn!("Failed to open Sled DB at {db_path}: {e}, using in-memory fallback");
            sled::Config::new().temporary(true).open().expect("In-memory sled")
        })
    );
    info!("Sled DB opened at {db_path}");

    // ── 2. Start P2P node ──
    let (p2p_event_tx, mut p2p_event_rx) = mpsc::channel::<NodeEvent>(256);

    let p2p_node = match P2PNode::new(&args.p2p_listen, p2p_event_tx, sled_db.clone()).await {
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

    // ── 3. Start Mailbox Manager with shared Sled backup ──
    let mailbox_mgr = MailboxManager::with_db(sled_db);

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

    // ── 5. Start WS/WSS gateway ──
    let ws_addr = format!("127.0.0.1:{}", args.ws_port);
    let app = crate::ws::build_gateway_router().with_state(ws_state.clone());

    match args.mode {
        ServerMode::Tls { cert_path, key_path } => {
            info!("WSS Gateway on {ws_addr} (TLS enabled)");
            info!("Connect browser to: wss://{ws_addr}/ws");
            info!("TLS: cert={cert_path}, key={key_path}");
            info!("Press Ctrl+C to stop");

            let tls_state = Arc::new(RwLock::new(
                load_tls_config(&cert_path, &key_path)
                    .await
                    .expect("Failed to load TLS certificates"),
            ));

            // Spawn background cert reload every 24 hours
            let reload_state = tls_state.clone();
            let reload_cert = cert_path.clone();
            let reload_key = key_path.clone();
            tokio::spawn(async move {
                cert_reload_task(reload_state, &reload_cert, &reload_key).await;
            });

            run_tls_server(&ws_addr, app, tls_state).await;
        }
        ServerMode::Plain => {
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
        }
    }

    info!("Server shut down gracefully");
}

// ── P2P Event Handler ──────────────────────────────────────────────

/// Set the P2P connected flag in the WebSocket gateway state.
async fn set_p2p_connected(ws_state: &ws::SharedState, connected: bool) {
    let mut map = ws_state.write().await;
    map.p2p_connected = connected;
}

async fn handle_p2p_events(
    rx: &mut mpsc::Receiver<NodeEvent>,
    ws_state: &ws::SharedState,
    mailbox_mgr: &MailboxManager,
    p2p_cmd_tx: &mpsc::Sender<NodeCommand>,
) {
    while let Some(event) = rx.recv().await {
        match event {
            NodeEvent::MessageReceived { from, topic, data } => {
                // If topic is present (GossipSub), route to the specific recipient
                if !topic.is_empty() {
                    if let Ok(recipient_id) = hex::decode(&topic) {
                        let map = ws_state.read().await;
                        if let Some(senders) = map.clients.get(&recipient_id) {
                            info!("GossipSub message from {from} routed to recipient ({} bytes)", data.len());
                            for tx in senders {
                                let _ = tx.send(data.clone());
                            }
                        } else {
                            trace!("GossipSub message for {}/{}b — recipient not connected on this node",
                                ws::hex_fmt(&recipient_id, 8), data.len());
                        }
                    }
                } else {
                    info!("P2P message from {from} ({} bytes)", data.len());
                    let map = ws_state.read().await;
                    for (_, senders) in map.clients.iter() {
                        for tx in senders {
                            let _ = tx.send(data.clone());
                        }
                    }
                }
            }
            NodeEvent::MailboxRetrieved { user_hash, messages } => {
                info!("MailboxRetrieved: {} messages for {}",
                    messages.len(), ws::hex_fmt(&user_hash, 8));

                if messages.is_empty() {
                    continue;
                }

                // Persist to Sled (seq-based dedup) and extract payloads for WS delivery
                let payloads = mailbox_mgr.handle_retrieval_result(&user_hash, &messages).await;

                // Deliver ONLY to the matching user (privacy fix!)
                let map = ws_state.read().await;
                if let Some(senders) = map.clients.get(&user_hash) {
                    for payload in &payloads {
                        for tx in senders {
                            let _ = tx.send(payload.clone());
                        }
                    }
                } else {
                    info!("MailboxRetrieved: user {} not connected, stored in Sled backup",
                        ws::hex_fmt(&user_hash, 8));
                }
            }
            NodeEvent::PeerDiscovered(peer_id) => {
                info!("P2P peer discovered: {peer_id}");
                set_p2p_connected(ws_state, true).await;
                // Bootstrap DHT to populate routing table with this peer
                let _ = p2p_cmd_tx.send(NodeCommand::Bootstrap).await;
            }
            NodeEvent::ListeningOn(addr) => {
                info!("P2P listening on: {addr}");
                set_p2p_connected(ws_state, true).await;
                // Bootstrap DHT now that we have a listen address
                let _ = p2p_cmd_tx.send(NodeCommand::Bootstrap).await;
            }
        }
    }
}

// ── Shutdown ────────────────────────────────────────────────────────

// ── TLS support ────────────────────────────────────────────────────

/// Loads TLS configuration from PEM certificate and private key files.
async fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    let certs = tokio::task::spawn_blocking({
        let cp = cert_path.to_string();
        move || -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
            let mut reader = BufReader::new(
                File::open(&cp).map_err(|e| format!("Failed to open cert file: {e}"))?,
            );
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Failed to parse cert file: {e}"))
        }
    })
    .await
    .map_err(|e| format!("Task join failed: {e}"))??;

    if certs.is_empty() {
        return Err("No certificates found in cert file".to_string());
    }

    let key = tokio::task::spawn_blocking({
        let kp = key_path.to_string();
        move || -> Result<PrivateKeyDer<'static>, String> {
            let mut reader = BufReader::new(
                File::open(&kp).map_err(|e| format!("Failed to open key file: {e}"))?,
            );
            rustls_pemfile::private_key(&mut reader)
                .map_err(|e| format!("Failed to parse key file: {e}"))?
                .ok_or_else(|| "No private key found in key file".to_string())
        }
    })
    .await
    .map_err(|e| format!("Task join failed: {e}"))??;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config build failed: {e}"))?;

    Ok(Arc::new(config))
}

/// Background task that reloads TLS certificates from disk every 24 hours.
async fn cert_reload_task(
    tls_state: Arc<RwLock<Arc<ServerConfig>>>,
    cert_path: &str,
    key_path: &str,
) {
    let cp = cert_path.to_string();
    let kp = key_path.to_string();

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;

        match load_tls_config(&cp, &kp).await {
            Ok(new_config) => {
                let mut guard = tls_state.write().await;
                *guard = new_config;
                info!("TLS certificates reloaded successfully — new certs are live");
            }
            Err(e) => {
                warn!(
                    "Failed to reload TLS certificates (old certs still active): {e}"
                );
            }
        }
    }
}

/// Runs a TLS-encrypted WSS accept loop.
///
/// Each incoming TCP connection is wrapped in TLS via `tokio-rustls`,
/// then served by the axum router using hyper's http1 connection builder.
/// The shared `tls_state` allows hot-reloading of certificates via the
/// background reload task without dropping active connections.
async fn run_tls_server(
    addr: &str,
    app: axum::Router,
    tls_state: Arc<RwLock<Arc<ServerConfig>>>,
) {
    use hyper::body::Incoming;
    use tower::Service;

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind TCP listener");

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, _) = accept_result.expect("Failed to accept connection");
                let app = app.clone();
                let tls_state = tls_state.clone();

                tokio::spawn(async move {
                    let config = tls_state.read().await.clone();
                    let acceptor = tokio_rustls::TlsAcceptor::from(config);

                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = hyper_util::rt::TokioIo::new(tls_stream);

                            let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                                let mut app = app.clone();
                                async move {
                                    let resp = Service::call(&mut app, req).await
                                        .expect("axum handler should not fail");
                                    Ok::<_, std::convert::Infallible>(resp)
                                }
                            });

                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                            {
                                warn!("TLS connection error: {e}");
                            }
                        }
                        Err(e) => {
                            warn!("TLS handshake failed: {e}");
                        }
                    }
                });
            }
            _ = &mut shutdown => {
                info!("Shutdown signal received, stopping TLS accept loop...");
                break;
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
