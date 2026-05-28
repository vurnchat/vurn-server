#!/bin/bash
# ── VurnChat P2P Node — One-Click Production Installer ────────────
#
# Usage (one-liner, fully automatic):
#    curl -sSL https://raw.githubusercontent.com/vurnchat/vurn-server/main/install.sh | bash
#
# The binary AUTOMATICALLY fetches official bootstrap nodes from
# the GitHub repo — no manual bootstrap entry needed!
# For TLS/WSS, socat handles TLS termination (bypasses VPN issues):
#    socat (port 9443, TLS) → localhost:PORT (plain WS)
#
# Usage with domain (enables TLS + socat):
#    curl -sSL https://raw.githubusercontent.com/.../install.sh | bash -s -- \
#      --domain vurn.example.com --email admin@example.com
#
# Options:
#   --port <PORT>           WS port (default: 9000)
#   --domain <DOMAIN>       Domain for TLS (enables certbot + socat)
#   --email <EMAIL>         Email for Let's Encrypt
#   --socat-port <PORT>     Socat TLS listen port (default: 9443)
#   --bootstrap <ADDR>      Bootstrap peer (optional, overrides auto-fetch)
#   --non-interactive       No prompts (use defaults)
#   --help, -h              Show this help
#
set -euo pipefail

# ── Constants ───────────────────────────────────────────────────────
REPO="vurnchat/vurn-server"
BINARY_NAME="vurn-server"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
STATE_DIR="/var/lib/vurn"
CONFIG_DIR="/etc/vurn"
SERVICE_FILE="/etc/systemd/system/vurn.service"
SOCAT_SERVICE_FILE="/etc/systemd/system/vurn-socat.service"
LOGROTATE_FILE="/etc/logrotate.d/vurn"

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ─────────────────────────────────────────────────────────
info()  { echo -e "${CYAN}==>${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e " ${GREEN}✔${NC} $1"; }
warn()  { echo -e " ${YELLOW}⚠${NC} $1"; }
err()   { echo -e " ${RED}✘${NC} $1"; }
header(){ echo -e "${BLUE}$1${NC}"; }

# ── Parse CLI flags ─────────────────────────────────────────────────
PORT="9000"
DOMAIN=""
EMAIL=""
SOCAT_PORT="9443"
BOOTSTRAP_ADDRS=()
SSL="n"
INTERACTIVE=true

# ── Firewall detection ──────────────────────────────────────────────
HAS_UFW=false
HAS_IPTABLES=false
command -v ufw &>/dev/null && HAS_UFW=true
command -v iptables &>/dev/null && HAS_IPTABLES=true

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port) PORT="$2"; shift 2 ;;
            --domain) DOMAIN="$2"; SSL="y"; shift 2 ;;
            --email) EMAIL="$2"; shift 2 ;;
            --socat-port) SOCAT_PORT="$2"; shift 2 ;;
            --bootstrap) BOOTSTRAP_ADDRS+=("$2"); shift 2 ;;
            --non-interactive) INTERACTIVE=false; shift ;;
            --help|-h)
                echo "VurnChat P2P Node — One-Click Production Installer"
                echo ""
                echo "USAGE:"
                echo "  # Fully automatic (no options needed):"
                echo "  curl -sSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash"
                echo ""
                echo "  # With TLS domain:"
                echo "  curl -sSL ... | bash -s -- --domain vurn.example.com --email admin@example.com"
                echo ""
                echo "OPTIONS:"
                echo "  --port <PORT>         WS port (default: 9000)"
                echo "  --domain <DOMAIN>     Domain for TLS (enables certbot + socat proxy)"
                echo "  --email <EMAIL>       Email for Let's Encrypt"
                echo "  --socat-port <PORT>   Socat TLS listen port (default: 9443)"
                echo "  --bootstrap <ADDR>    Bootstrap peer (optional, overrides auto-fetch)"
                echo "  --non-interactive     No prompts (use defaults)"
                echo "  --help, -h            Show this help"
                echo ""
                echo "BOOTSTRAP:"
                echo "  Bootstrap nodes are auto-fetched from the GitHub repo."
                echo "  No manual --bootstrap needed!"
                echo ""
                echo "TLS/SOCAT SETUP:"
                echo "  vurn-server  ─(plain WS)─►  socat  ─(TLS)─►  Client (WSS)"
                echo "  :PORT                      :SOCAT_PORT        :SOCAT_PORT"
                echo "  Socat terminates TLS on SOCAT_PORT and forwards"
                echo "  to vurn-server on PORT via plain TCP."
                echo "  This bypasses VPN/MTU issues with direct TLS."
                exit 0
                ;;
            *) err "Unknown argument: $1"; exit 1 ;;
        esac
    done
}

parse_args "$@"

# If script is not attached to a terminal (e.g., piped from curl),
# automatically switch to non‑interactive mode to avoid empty reads.
if [ ! -t 0 ]; then
    INTERACTIVE=false
fi

# ── Step 1: Welcome & environment check ─────────────────────────────
echo ""
header "┌─────────────────────────────────────────────────────────┐"
header "│  VurnChat P2P Node — One-Click Installer                │"
header "│  Post-Quantum Encrypted Distributed Messenger           │"
header "│  Auto-bootstrap • SOCAT TLS-proxy • Zero config         │"
header "└─────────────────────────────────────────────────────────┘"
echo ""

# OS check
OS="$(uname -s)"
ARCH="$(uname -m)"
IS_LINUX=false
IS_MAC=false

case "$OS" in
    Linux)   IS_LINUX=true ;;
    Darwin)  IS_MAC=true ;;
    *)
        err "Unsupported OS: $OS (expected Linux or macOS)"
        exit 1
        ;;
esac

if [[ "$IS_MAC" == "true" ]]; then
    warn "macOS detected — systemd, logrotate, certbot, and socat steps will be skipped."
    warn "The binary will be installed directly into /usr/local/bin."
    echo ""
fi

# Sudo check
SUDO="sudo"
if [[ $EUID -eq 0 ]]; then
    SUDO=""
fi

if [[ $EUID -ne 0 ]] && ! command -v sudo &>/dev/null; then
    err "sudo is required. Run as root or install sudo."
    exit 1
fi

ok "OS: $OS ($ARCH)"
ok "Privileges: $([ $EUID -eq 0 ] && echo 'root' || echo 'sudo available')"

# ── Step 2: Interactive prompts (if enabled) ────────────────────────
if [[ "$INTERACTIVE" == "true" ]]; then
    echo ""
    info "Configuration (press Enter for defaults — bootstrap is auto-fetched)"
    echo ""

    read -r -p "   WebSocket port [${PORT}]: " input_port
    PORT="${input_port:-$PORT}"

    echo ""
    read -r -p "   Domain for TLS/WSS (optional — enables socat TLS proxy): " input_domain
    if [[ -n "$input_domain" ]]; then
        DOMAIN="$input_domain"
        SSL="y"
        read -r -p "   Email for Let's Encrypt [admin@${DOMAIN}]: " input_email
        EMAIL="${input_email:-admin@${DOMAIN}}"
        read -r -p "   Socat TLS listen port [${SOCAT_PORT}]: " input_socat
        SOCAT_PORT="${input_socat:-$SOCAT_PORT}"
    fi

    echo ""
    echo -e "  ${CYAN}ℹ️ Bootstrap nodes are auto-fetched from GitHub — no manual entry needed!${NC}"
    echo ""
fi

echo ""
info "Configuration summary:"
echo "  WebSocket port:  ${PORT}"
if [[ "$SSL" == "y" ]]; then
    echo "  Domain:          ${DOMAIN}"
    echo "  Email:           ${EMAIL}"
    echo "  Socat TLS port:  ${SOCAT_PORT} (forwards TLS → plain WS on :${PORT})"
else
    echo "  TLS:             disabled (plain WS)"
fi
echo "  Bootstrap:       auto-fetched from GitHub (${REPO}/blob/main/bootstrap_nodes.txt)"
echo ""

# ── Step 3: Create vurn user and state directories ──────────────────
info "Creating system user and directories..."

$SUDO mkdir -p "${STATE_DIR}"
$SUDO mkdir -p "${CONFIG_DIR}"
$SUDO chmod 750 "${STATE_DIR}"
$SUDO chmod 750 "${CONFIG_DIR}"
ok "State directories created: ${STATE_DIR}, ${CONFIG_DIR}"

if [[ "$IS_LINUX" == "true" ]]; then
    if ! id -u vurn &>/dev/null; then
        $SUDO useradd \
            --system \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "VurnChat P2P Node" \
            vurn
        ok "Created system user: vurn"
    else
        ok "System user vurn already exists"
    fi
    
    $SUDO chown -R vurn:vurn "${STATE_DIR}" "${CONFIG_DIR}"
else
    ok "Skipping system user creation (macOS)"
fi

# ── Step 4: Download binary ─────────────────────────────────────────
info "Detecting system architecture..."

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64)        binary_arch="x86_64-unknown-linux-gnu" ;;
            aarch64|arm64) binary_arch="aarch64-unknown-linux-gnu" ;;
            *)
                err "Unsupported architecture: $ARCH (expected x86_64 or aarch64 on Linux)"
                exit 1
                ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            x86_64)  binary_arch="x86_64-apple-darwin" ;;
            arm64)   binary_arch="aarch64-apple-darwin" ;;
            *)
                err "Unsupported architecture: $ARCH (expected x86_64 or arm64 on macOS)"
                exit 1
                ;;
        esac
        ;;
esac

ok "Architecture: $ARCH → ${binary_arch}"
echo ""

info "Downloading ${BINARY_NAME} binary..."

BINARY_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}-${binary_arch}"
CHECKSUM_URL="${BINARY_URL}.sha256"

download_with_retry() {
    local url="$1"
    local output="$2"
    local attempt=0
    until [[ $attempt -ge 3 ]]; do
        if command -v curl &>/dev/null; then
            if $SUDO curl -fsSL "$url" -o "$output" 2>/dev/null; then
                return 0
            fi
        elif command -v wget &>/dev/null; then
            if $SUDO wget -q "$url" -O "$output" 2>/dev/null; then
                return 0
            fi
        fi
        attempt=$((attempt + 1))
        [[ $attempt -lt 3 ]] && sleep 2
    done
    return 1
}

download_with_retry "$BINARY_URL" "$INSTALL_PATH" || {
    warn "Pre-compiled binary not available for ${binary_arch}."

    if [[ "$INTERACTIVE" == "true" ]]; then
        echo -e -n "  ${YELLOW}?${NC} Build from source instead? [Y/n]: "
        read -r _build_choice
        _build_choice="${_build_choice:-y}"
    else
        _build_choice="y"
    fi

    if [[ "$_build_choice" =~ ^[Yy] ]]; then
        info "Building from source (requires Rust toolchain)..."

        if ! command -v cargo &>/dev/null; then
            info "Rust not found — installing via rustup..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>/dev/null || {
                err "Rustup installation failed."
                exit 1
            }
            if [[ -f "$HOME/.cargo/env" ]]; then
                source "$HOME/.cargo/env"
            fi
        fi

        if ! command -v cargo &>/dev/null; then
            err "Cargo not found after rustup installation."
            exit 1
        fi

        ok "Rust toolchain: $(cargo --version)"

        _build_dir=$(mktemp -d)
        info "Cloning ${REPO}..."
        git clone --depth 1 "https://github.com/${REPO}.git" "$_build_dir" || {
            err "Git clone failed."
            rm -rf "$_build_dir"
            exit 1
        }

        info "Building vurn-server --release (this takes a few minutes)..."
        (cd "$_build_dir" && cargo build --release -p vurn-server) || {
            err "Build failed!"
            rm -rf "$_build_dir"
            exit 1
        }

        $SUDO cp "$_build_dir/target/release/vurn-server" "$INSTALL_PATH"
        $SUDO chmod +x "$INSTALL_PATH"
        rm -rf "$_build_dir"

        ok "Built from source: ${INSTALL_PATH}"
    else
        err "Installation aborted by user."
        exit 1
    fi
}

$SUDO chmod +x "$INSTALL_PATH"

if ! $INSTALL_PATH --help &>/dev/null; then
    err "Downloaded binary failed to execute!"
    file "$INSTALL_PATH"
    exit 1
fi

ok "Binary installed: ${INSTALL_PATH} ($(du -h "$INSTALL_PATH" | cut -f1))"

# Checksum verification (best-effort)
if command -v sha256sum &>/dev/null; then
    _local_checksum=$(sha256sum "$INSTALL_PATH" | cut -d' ' -f1)
    _remote_checksum=$(download_with_retry "$CHECKSUM_URL" "/tmp/vurn-server.sha256" && cat "/tmp/vurn-server.sha256" | cut -d' ' -f1 || echo "")
    if [[ -n "$_remote_checksum" ]]; then
        if [[ "$_local_checksum" == "$_remote_checksum" ]]; then
            ok "Checksum verified"
        else
            warn "Checksum mismatch! Expected: ${_remote_checksum}, got: ${_local_checksum}"
        fi
    else
        warn "Checksum file not available (dev build — skipping verification)"
    fi
fi

# ── Step 5: Install socat (if SSL mode) ───────────────────────────────
SOCAT_INSTALLED=false
if [[ "$SSL" == "y" && -n "$DOMAIN" && "$IS_LINUX" == "true" ]]; then
    echo ""
    info "Installing socat for TLS proxy..."
    
    if command -v socat &>/dev/null; then
        ok "socat already installed"
        SOCAT_INSTALLED=true
    else
        if command -v apt &>/dev/null; then
            $SUDO apt update -qq && $SUDO apt install socat -y -qq && SOCAT_INSTALLED=true
        elif command -v apk &>/dev/null; then
            $SUDO apk add socat && SOCAT_INSTALLED=true
        elif command -v yum &>/dev/null; then
            $SUDO yum install socat -y -q && SOCAT_INSTALLED=true
        elif command -v dnf &>/dev/null; then
            $SUDO dnf install socat -y -q && SOCAT_INSTALLED=true
        else
            warn "Could not install socat automatically."
            warn "Install it manually: sudo apt install socat"
            SOCAT_INSTALLED=false
        fi
        
        if [[ "$SOCAT_INSTALLED" == "true" ]]; then
            ok "socat installed"
        fi
    fi
fi

# ── Step 6: SSL certificate (if domain provided) ────────────────────
if [[ "$SSL" == "y" && -n "$DOMAIN" ]]; then
    if [[ "$IS_MAC" == "true" ]]; then
        warn "Let's Encrypt / Certbot is not supported on macOS in this installer."
        SSL="n"
    fi
fi

if [[ "$SSL" == "y" && -n "$DOMAIN" ]]; then
    echo ""
    info "Setting up TLS with Let's Encrypt (Certbot)..."

    if ! command -v certbot &>/dev/null; then
        info "Certbot not found — installing..."
        if command -v apt &>/dev/null; then
            $SUDO apt update -qq && $SUDO apt install certbot -y -qq
        elif command -v apk &>/dev/null; then
            $SUDO apk add certbot
        elif command -v yum &>/dev/null; then
            $SUDO yum install certbot -y -q
        elif command -v dnf &>/dev/null; then
            $SUDO dnf install certbot -y -q
        else
            err "Could not install certbot automatically."
            err "Install manually: sudo certbot certonly --standalone -d ${DOMAIN}"
            exit 1
        fi
        ok "Certbot installed"
    else
        ok "Certbot already installed"
    fi

    CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

    if [[ -f "$CERT_PATH" && -f "$KEY_PATH" ]]; then
        ok "Existing certificate found for ${DOMAIN}, skipping issuance"
        $SUDO certbot renew --dry-run &>/dev/null && ok "Certificate renewal check passed" || warn "Renewal check failed"
    else
        info "Issuing new SSL certificate for: ${DOMAIN}"

        $SUDO certbot certonly --standalone --non-interactive --agree-tos \
            --email "${EMAIL:-admin@${DOMAIN}}" \
            -d "${DOMAIN}" || {
            err "Failed to issue SSL certificate for ${DOMAIN}."
            exit 1
        }
        ok "SSL certificate issued for ${DOMAIN}"
    fi

    # Open permissions for vurn user to read certs
    $SUDO chmod 755 /etc/letsencrypt/live /etc/letsencrypt/archive
    $SUDO chmod 755 "/etc/letsencrypt/live/${DOMAIN}"
    $SUDO chmod -R o+r "/etc/letsencrypt/archive/${DOMAIN}" 2>/dev/null || true

    ok "TLS certificates ready"
fi

# ── Step 7: Write environment config ────────────────────────────────
info "Writing environment config..."

$SUDO tee "${CONFIG_DIR}/vurn.env" > /dev/null <<ENVEOF
# VurnChat Server Configuration
# Generated by install.sh on $(date -I)

# WS port — vurn-server runs in plain WS mode
VURN_PORT=${PORT}

# Fixed P2P listen port for stable bootstrap multiaddr
VURN_P2P_LISTEN=/ip4/0.0.0.0/tcp/9001

# Bootstrap is auto-fetched from GitHub by the binary.
# Override here if needed: VURN_BOOTSTRAP="/ip4/.../tcp/..."
ENVEOF

# In socat mode, vurn-server runs WITHOUT --cert/--key (plain WS),
# and socat handles TLS termination externally.
# No VURN_CERT/VURN_KEY in env file!

# Write bootstrap addrs to env file only if explicitly provided
if [[ ${#BOOTSTRAP_ADDRS[@]} -gt 0 ]]; then
    echo "VURN_BOOTSTRAP=${BOOTSTRAP_ADDRS[*]}" | $SUDO tee -a "${CONFIG_DIR}/vurn.env" > /dev/null
fi

$SUDO chmod 600 "${CONFIG_DIR}/vurn.env"
if [[ "$IS_LINUX" == "true" ]]; then
    $SUDO chown vurn:vurn "${CONFIG_DIR}/vurn.env"
fi
ok "Config written: ${CONFIG_DIR}/vurn.env"

# ── Step 8: Create systemd services (Linux only) ────────────────────
if [[ "$IS_MAC" == "true" ]]; then
    info "Skipping systemd service creation (macOS)"
else
    # ── 8a. vurn-server service (plain WS, no TLS) ──
    info "Creating vurn-server systemd service..."

    $SUDO tee "$SERVICE_FILE" > /dev/null <<SERVICEEOF
[Unit]
Description=VurnChat — Post-Quantum Encrypted P2P Messenger Node
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vurn
Group=vurn
WorkingDirectory=${STATE_DIR}
StateDirectory=vurn
StateDirectoryMode=0750
EnvironmentFile=-${CONFIG_DIR}/vurn.env

ExecStart=${INSTALL_PATH}

Restart=always
RestartSec=5
RestartMaxDelaySec=30
MemoryMax=512M

CapabilityBoundingSet=
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectProc=invisible
PrivateDevices=true
DevicePolicy=closed
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
SERVICEEOF

    $SUDO chmod 644 "$SERVICE_FILE"
    ok "vurn-server service created: ${SERVICE_FILE}"

    # ── 8b. socat TLS proxy service (if SSL mode) ──
    if [[ "$SSL" == "y" && -n "$DOMAIN" && "$IS_LINUX" == "true" && "$SOCAT_INSTALLED" == "true" ]]; then
        info "Creating socat TLS proxy service (port ${SOCAT_PORT} → :${PORT})..."

        $SUDO tee "$SOCAT_SERVICE_FILE" > /dev/null <<SOCATEOF
[Unit]
Description=VurnChat — Socat TLS Proxy (:${SOCAT_PORT} TLS → :${PORT} plain WS)
Documentation=https://github.com/${REPO}
After=network-online.target vurn.service
Requires=vurn.service

[Service]
Type=simple
User=vurn
Group=vurn

ExecStart=/usr/bin/socat openssl-listen:${SOCAT_PORT},fork,reuseaddr,cert=${CERT_PATH},key=${KEY_PATH},verify=0 tcp:127.0.0.1:${PORT}

Restart=always
RestartSec=5
RestartMaxDelaySec=30

NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SOCATEOF

        $SUDO chmod 644 "$SOCAT_SERVICE_FILE"
        ok "Socat TLS proxy service created: ${SOCAT_SERVICE_FILE}"
    fi
fi

# ── Step 9: Install cert renewal hook ────────────────────────────────
if [[ "$SSL" == "y" && -n "$DOMAIN" && "$IS_LINUX" == "true" ]]; then
    RENEWAL_HOOK="/etc/letsencrypt/renewal-hooks/deploy/vurn-restart.sh"
    $SUDO mkdir -p "$(dirname "$RENEWAL_HOOK")"
    $SUDO tee "$RENEWAL_HOOK" > /dev/null <<'HOOKEOF'
#!/bin/bash
systemctl restart vurn-socat.service
HOOKEOF
    $SUDO chmod +x "$RENEWAL_HOOK"
    ok "Cert renewal hook installed (restarts socat on cert rotation)"
fi

# ── Step 10: Install logrotate ───────────────────────────────────────
if [[ "$IS_MAC" == "true" ]]; then
    info "Skipping logrotate configuration (macOS)"
else
    info "Installing logrotate configuration..."

    $SUDO mkdir -p /var/log/vurn
    $SUDO chown vurn:vurn /var/log/vurn

    $SUDO tee "$LOGROTATE_FILE" > /dev/null <<'LOGROTEOF'
/var/log/vurn/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    maxsize 100M
}
LOGROTEOF

    $SUDO chmod 644 "$LOGROTATE_FILE"
    ok "Logrotate installed: ${LOGROTATE_FILE}"
fi

# ── Step 11: Enable & start services ─────────────────────────────────
echo ""
if [[ "$IS_MAC" == "true" ]]; then
    info "Start the server manually:"
    echo "  ${INSTALL_PATH}"
    echo ""
else
    info "Enabling and starting services..."
    $SUDO systemctl daemon-reload
    
    # Start vurn-server first
    $SUDO systemctl enable vurn.service
    $SUDO systemctl stop vurn.service 2>/dev/null || true
    sleep 1
    $SUDO systemctl start vurn.service
    
    # Start socat if installed
    if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
        $SUDO systemctl enable vurn-socat.service
        $SUDO systemctl start vurn-socat.service 2>/dev/null || true
    fi
fi

# ── Step 12: Health check ───────────────────────────────────────────
echo ""
HEALTH_OK=false

if [[ "$IS_MAC" == "true" ]]; then
    HEALTH_OK=true
else
    info "Waiting for service to start (up to 15 seconds)..."

    for i in $(seq 1 15); do
        sleep 1
        if $SUDO systemctl is-active --quiet vurn.service 2>/dev/null; then
            # Health check always goes to localhost WS (plain, no TLS)
            if command -v curl &>/dev/null; then
                if curl -sf "http://127.0.0.1:${PORT}/health" > /dev/null 2>&1; then
                    HEALTH_OK=true
                    break
                fi
            elif command -v wget &>/dev/null; then
                if wget -q -O /dev/null "http://127.0.0.1:${PORT}/health" 2>/dev/null; then
                    HEALTH_OK=true
                    break
                fi
            else
                HEALTH_OK=true
                break
            fi
        fi
    done
fi

echo ""
if $HEALTH_OK; then
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  ✅ VurnChat P2P Node is running!                       │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""
    if [[ "$SSL" == "y" && -n "$DOMAIN" ]]; then
        echo -e "  ${CYAN}Connect browser:${NC}  wss://${DOMAIN}:${SOCAT_PORT}/ws"
        echo -e "  ${CYAN}Socat TLS proxy:${NC} :${SOCAT_PORT} (TLS) → :${PORT} (plain WS)"
    else
        echo -e "  ${CYAN}Connect browser:${NC}  ws://YOUR_SERVER_IP:${PORT}/ws"
    fi
    echo ""
    if [[ "$IS_MAC" == "true" ]]; then
        echo -e "  ${YELLOW}Run:${NC}     ${INSTALL_PATH}"
    else
        echo -e "  ${YELLOW}Status:${NC}  sudo systemctl status vurn.service"
        if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
            echo -e "  ${YELLOW}Socat:${NC}    sudo systemctl status vurn-socat.service"
        fi
        echo -e "  ${YELLOW}Logs:${NC}    sudo journalctl -u vurn.service -f"
    fi
    echo ""
else
    err "Health check failed after 15 seconds."
    err "Check logs: sudo journalctl -u vurn.service -n 50 --no-pager"
    exit 1
fi

info "Installation complete!"
echo ""

# ── Step 13: Firewall configuration (best-effort) ───────────────────
echo ""
info "Checking firewall configuration..."

FIREWALL_PORTS=("$PORT" "9001")
if [[ "$SSL" == "y" && -n "$DOMAIN" && "$SOCAT_INSTALLED" == "true" ]]; then
    FIREWALL_PORTS+=("$SOCAT_PORT")
fi

if [[ "$HAS_UFW" == "true" ]]; then
    for fport in "${FIREWALL_PORTS[@]}"; do
        if ! $SUDO ufw status | grep -q "$fport/tcp"; then
            $SUDO ufw allow "$fport/tcp" 2>/dev/null && ok "UFW: opened port $fport/tcp"
        fi
    done
elif [[ "$HAS_IPTABLES" == "true" ]]; then
    for fport in "${FIREWALL_PORTS[@]}"; do
        $SUDO iptables -C INPUT -p tcp --dport "$fport" -j ACCEPT 2>/dev/null || {
            $SUDO iptables -A INPUT -p tcp --dport "$fport" -j ACCEPT 2>/dev/null && ok "iptables: opened port $fport/tcp"
        }
    done
    # Save iptables rules
    if command -v iptables-save &>/dev/null; then
        $SUDO iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
else
    warn "No firewall tool detected (ufw/iptables)."
    warn "Make sure these ports are open in your firewall:"
    for fport in "${FIREWALL_PORTS[@]}"; do
        echo "  - ${fport}/tcp"
    done
fi
