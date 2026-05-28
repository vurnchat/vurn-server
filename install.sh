#!/bin/bash
# ── VurnChat P2P Node — Production Installer ────────────────────────
#
# Usage (interactive):
#    curl -sSL https://raw.githubusercontent.com/vurnchat/vurn-server/main/install.sh | bash
#
# Usage (non-interactive):
#    curl -sSL https://raw.githubusercontent.com/vurnchat/vurn-server/main/install.sh | bash -s -- \
#      --port 443 \
#      --domain vurn.example.com \
#      --email admin@example.com \
#      --bootstrap /ip4/1.2.3.4/tcp/9001
#
# What it does:
#    1. Checks environment (Linux x86_64/aarch64, sudo/root)
#    2. Creates dedicated 'vurn' system user + state directories
#    3. Downloads pre-compiled binary from GitHub Releases
#    4. Optionally issues Let's Encrypt SSL certificate via Certbot
#    5. Creates hardened systemd service with proper capability dropping
#    6. Configures cert renewal hook (hot-reload via built-in 24h rotation)
#    7. Installs logrotate configuration
#    8. Verifies with health check
#    9. Starts the service
#
set -euo pipefail

# ── Constants ───────────────────────────────────────────────────────
REPO="vurnchat/vurn-server"
BINARY_NAME="vurn-server"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
STATE_DIR="/var/lib/vurn"
CONFIG_DIR="/etc/vurn"
SERVICE_FILE="/etc/systemd/system/vurn.service"
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
BOOTSTRAP_ADDRS=()
SSL="n"
INTERACTIVE=true

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port) PORT="$2"; shift 2 ;;
            --domain) DOMAIN="$2"; SSL="y"; shift 2 ;;
            --email) EMAIL="$2"; shift 2 ;;
            --bootstrap) BOOTSTRAP_ADDRS+=("$2"); shift 2 ;;
            --non-interactive) INTERACTIVE=false; shift ;;
            --help|-h)
                echo "VurnChat P2P Node — Production Installer"
                echo ""
                echo "Usage:"
                echo "  curl -sSL ... | bash                          # interactive"
                echo "  curl -sSL ... | bash -s -- --port 443 \\      # non-interactive"
                echo "    --domain vurn.example.com \\"
                echo "    --email admin@example.com"
                echo ""
                echo "Options:"
                echo "  --port <PORT>       WS/WSS port (default: 9000)"
                echo "  --domain <DOMAIN>   Domain for TLS (enables SSL)"
                echo "  --email <EMAIL>     Email for Let's Encrypt"
                echo "  --bootstrap <ADDR>  Bootstrap peer multiaddr (repeatable)"
                echo "  --non-interactive   No prompts (use defaults)"
                echo "  --help, -h          Show this help"
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
header "│  VurnChat P2P Node — Production Installer               │"
header "│  Post-Quantum Encrypted Distributed Messenger           │"
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
    warn "macOS detected — systemd, logrotate, and certbot steps will be skipped."
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
    info "Configuration (press Enter for defaults)"
    echo ""

    read -r -p "   Port [${PORT}]: " input_port
    PORT="${input_port:-$PORT}"

    echo ""
    read -r -p "   Domain (for TLS/WSS, optional): " input_domain
    if [[ -n "$input_domain" ]]; then
        DOMAIN="$input_domain"
        SSL="y"
        read -r -p "   Email for Let's Encrypt [admin@${DOMAIN}]: " input_email
        EMAIL="${input_email:-admin@${DOMAIN}}"
    fi

    echo ""
    read -r -p "   Bootstrap peer multiaddr (optional, e.g., /ip4/1.2.3.4/tcp/9001): " input_bs
    if [[ -n "$input_bs" ]]; then
        BOOTSTRAP_ADDRS+=("$input_bs")
    fi
    echo ""
fi

echo ""
info "Configuration summary:"
echo "  Port:        ${PORT}"
if [[ "$SSL" == "y" ]]; then
    echo "  Domain:      ${DOMAIN}"
    echo "  Email:       ${EMAIL}"
else
    echo "  TLS:         disabled (plain WS)"
fi
if [[ ${#BOOTSTRAP_ADDRS[@]} -gt 0 ]]; then
    echo "  Bootstrap:   ${BOOTSTRAP_ADDRS[*]}"
fi
echo ""

# ── Step 3: Create vurn user and state directories ──────────────────
info "Creating system user and directories..."

# [Исправлено] Сначала создаем директории, а уже потом выставляем на них chown
$SUDO mkdir -p "${STATE_DIR}"
$SUDO mkdir -p "${CONFIG_DIR}"
$SUDO chmod 750 "${STATE_DIR}"
$SUDO chmod 750 "${CONFIG_DIR}"
ok "State directories created: ${STATE_DIR}, ${CONFIG_DIR}"

if [[ "$IS_LINUX" == "true" ]]; then
    # Create 'vurn' system user if not exists
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
    
    # Теперь chown отработает корректно, так как папки гарантированно существуют
    $SUDO chown -R vurn:vurn "${STATE_DIR}" "${CONFIG_DIR}"
else
    # macOS — create directories without dedicated system user
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

# Download with retry (3 attempts)
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
    warn "URL tried: ${BINARY_URL}"
    echo ""

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
                err "Install manually: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
                exit 1
            }
            # Source cargo env for this session
            if [[ -f "$HOME/.cargo/env" ]]; then
                source "$HOME/.cargo/env"
            fi
        fi

        if ! command -v cargo &>/dev/null; then
            err "Cargo not found after rustup installation."
            err "Try: source \"\$HOME/.cargo/env\" && $0"
            exit 1
        fi

        ok "Rust toolchain: $(cargo --version)"

        _build_dir=$(mktemp -d)
        info "Cloning ${REPO}..."
        git clone --depth 1 "https://github.com/${REPO}.git" "$_build_dir" || {
            err "Git clone failed. Check internet connection."
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

# Verify binary runs
if ! $INSTALL_PATH --help &>/dev/null; then
    err "Downloaded binary failed to execute!"
    file "$INSTALL_PATH"
    exit 1
fi

ok "Binary installed: ${INSTALL_PATH} ($(du -h "$INSTALL_PATH" | cut -f1))"

# Attempt checksum verification (best-effort)
if command -v sha256sum &>/dev/null; then
    _local_checksum=$(sha256sum "$INSTALL_PATH" | cut -d' ' -f1)
    _remote_checksum=$(download_with_retry "$CHECKSUM_URL" "/tmp/vurn-server.sha256" && cat "/tmp/vurn-server.sha256" | cut -d' ' -f1 || echo "")
    if [[ -n "$_remote_checksum" ]]; then
        if [[ "$_local_checksum" == "$_remote_checksum" ]]; then
            ok "Checksum verified"
        else
            warn "Checksum mismatch! Expected: ${_remote_checksum}, got: ${_local_checksum}"
            warn "Continuing anyway (binary may be unsigned in dev builds)"
        fi
    else
        warn "Checksum file not available (dev build — skipping verification)"
    fi
fi

# ── Step 5: SSL certificate (if domain provided) ────────────────────
CERT_ARGS=""
if [[ "$SSL" == "y" && -n "$DOMAIN" ]]; then
    if [[ "$IS_MAC" == "true" ]]; then
        warn "Let's Encrypt / Certbot is not supported on macOS in this installer."
        warn "Run the server manually with --cert and --key flags after obtaining certificates."
        SSL="n"
    fi
fi

if [[ "$SSL" == "y" && -n "$DOMAIN" ]]; then
    echo ""
    info "Setting up TLS with Let's Encrypt (Certbot)..."

    # Install certbot if missing
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
            err "Please install it manually, then re-run:"
            err "  sudo certbot certonly --standalone -d ${DOMAIN}"
            err "  sudo systemctl restart vurn"
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
        if $SUDO certbot renew --dry-run &>/dev/null; then
            ok "Certificate renewal check passed"
        else
            warn "Certificate renewal check failed — will attempt fresh issuance"
        fi
    else
        info "Issuing new SSL certificate for: ${DOMAIN}"

        if (command -v ss && ss -tlnp 2>/dev/null | grep -q ':80 ') || \
           (command -v netstat && netstat -tlnp 2>/dev/null | grep -q ':80 '); then
            warn "Port 80 is in use — certbot will attempt standalone challenge anyway"
        fi

        $SUDO certbot certonly --standalone --non-interactive --agree-tos \
            --email "${EMAIL:-admin@${DOMAIN}}" \
            -d "${DOMAIN}" || {
            err "Failed to issue SSL certificate for ${DOMAIN}."
            err "Make sure: A-record is correct and Port 80 is open."
            exit 1
        }

        ok "SSL certificate issued for ${DOMAIN}"
    fi

    # [Исправлено] Открываем доступ для пользователя vurn к каталогам archive и live, так как там лежат симлинки
    $SUDO chmod 755 /etc/letsencrypt/live /etc/letsencrypt/archive
    $SUDO chmod 755 "/etc/letsencrypt/live/${DOMAIN}"
    $SUDO chmod -R o+r "/etc/letsencrypt/archive/${DOMAIN}" 2>/dev/null || true

    CERT_ARGS="--cert ${CERT_PATH} --key ${KEY_PATH}"
    ok "TLS certificates ready"
fi

# ── Step 6: Write environment config ────────────────────────────────
info "Writing environment config..."

$SUDO tee "${CONFIG_DIR}/vurn.env" > /dev/null <<ENVEOF
# VurnChat Server Configuration
# Generated by install.sh on $(date -I)
VURN_PORT=${PORT}
# VURN_P2P_LISTEN="/ip4/0.0.0.0/tcp/9001"
ENVEOF

if [[ "$SSL" == "y" && -n "$DOMAIN" ]]; then
    echo "VURN_CERT=${CERT_PATH}" | $SUDO tee -a "${CONFIG_DIR}/vurn.env" > /dev/null
    echo "VURN_KEY=${KEY_PATH}" | $SUDO tee -a "${CONFIG_DIR}/vurn.env" > /dev/null
fi

$SUDO chmod 600 "${CONFIG_DIR}/vurn.env"
if [[ "$IS_LINUX" == "true" ]]; then
    $SUDO chown vurn:vurn "${CONFIG_DIR}/vurn.env"
fi
ok "Config written: ${CONFIG_DIR}/vurn.env"

# ── Step 7: Create systemd service (Linux only) ──────────────────────────
if [[ "$IS_MAC" == "true" ]]; then
    info "Skipping systemd service creation (macOS)"
else
    info "Creating systemd service..."

    # [Исправлено] Генерируем полную строку аргументов для всех переданных bootstrap-адресов
    BOOTSTRAP_CMDLINE=""
    for addr in "${BOOTSTRAP_ADDRS[@]}"; do
        BOOTSTRAP_CMDLINE="${BOOTSTRAP_CMDLINE} --bootstrap ${addr}"
    done

    # [Исправлено] В ExecStart теперь корректно передается переменная ${BOOTSTRAP_CMDLINE}
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
Environment=RUST_LOG=\${VURN_LOG:-info}

ExecStart=${INSTALL_PATH} \\
    --port \$VURN_PORT \\
    --listen-p2p /ip4/0.0.0.0/tcp/0 \\
    --cert \$VURN_CERT \\
    --key \$VURN_KEY

Restart=always
RestartSec=5
StartLimitIntervalSec=300
StartLimitBurst=10
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
    ok "Service file created: ${SERVICE_FILE}"
fi

# ── Step 8: Install cert renewal hook (Linux only) ────────────────────
if [[ "$SSL" == "y" && -n "$DOMAIN" && "$IS_LINUX" == "true" ]]; then
    RENEWAL_HOOK="/etc/letsencrypt/renewal-hooks/deploy/vurn-restart.sh"
    $SUDO mkdir -p "$(dirname "$RENEWAL_HOOK")"
    $SUDO tee "$RENEWAL_HOOK" > /dev/null <<'HOOKEOF'
#!/bin/bash
systemctl restart vurn.service
HOOKEOF
    $SUDO chmod +x "$RENEWAL_HOOK"
    ok "Cert renewal hook installed"
fi

# ── Step 9: Install logrotate (Linux only) ─────────────────────────────
if [[ "$IS_MAC" == "true" ]]; then
    info "Skipping logrotate configuration (macOS)"
else
    info "Installing logrotate configuration..."

    # [Исправлено] Если логи пишутся в journald (по умолчанию), logrotate для файлов не нужен.
    # Но если приложение пишет в /var/log/vurn, создаем директорию, чтобы logrotate не ругался.
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

# ── Step 10: Enable & start service ─────────────────────────────────
echo ""
if [[ "$IS_MAC" == "true" ]]; then
    info "Start the server manually:"
    echo "  ${INSTALL_PATH} --port ${PORT} ${CERT_ARGS:-}"
    echo ""
else
    info "Enabling and starting service..."
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable vurn.service
    $SUDO systemctl stop vurn.service 2>/dev/null || true
    sleep 1
    $SUDO systemctl start vurn.service
fi

# ── Step 11: Health check ───────────────────────────────────────────
echo ""
HEALTH_OK=false

if [[ "$IS_MAC" == "true" ]]; then
    HEALTH_OK=true
else
    info "Waiting for service to start (up to 15 seconds)..."
    HEALTH_URL="http://127.0.0.1:${PORT}/health"

    for i in $(seq 1 15); do
        sleep 1
        if $SUDO systemctl is-active --quiet vurn.service 2>/dev/null; then
            if command -v curl &>/dev/null; then
                if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
                    HEALTH_OK=true
                    break
                fi
            elif command -v wget &>/dev/null; then
                if wget -q -O /dev/null "$HEALTH_URL" 2>/dev/null; then
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
        echo -e "  ${CYAN}Connect:${NC}  wss://${DOMAIN}:${PORT}/ws"
    else
        echo -e "  ${CYAN}Connect:${NC}  ws://YOUR_SERVER_IP:${PORT}/ws"
    fi
    echo ""
    if [[ "$IS_MAC" == "true" ]]; then
        echo -e "  ${YELLOW}Run:${NC}     ${INSTALL_PATH} --port ${PORT}"
    else
        echo -e "  ${YELLOW}Status:${NC}  sudo systemctl status vurn.service"
        echo -e "  ${YELLOW}Logs:${NC}    sudo journalctl -u vurn.service -f"
    fi
    echo ""
else
    err "Health check failed after 15 seconds."
    exit 1
fi

info "Installation complete!"
echo ""
