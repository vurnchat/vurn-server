#!/bin/bash
# ── VurnChat Blind Relay Server — One-liner installer ──────────────
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/scramble22/VurnChat/main/install.sh | bash
#
# What it does:
#   1. Checks environment (Linux, sudo)
#   2. Asks: port, domain/SSL?
#   3. Downloads pre-compiled binary from GitHub Releases
#   4. Optionally issues Let's Encrypt SSL certificate via Certbot
#   5. Creates systemd service with auto-restart
#   6. Starts the server
#
# The server auto-reloads certificates every 24 hours (built-in),
# so no cron jobs or manual restarts are needed.
#
set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Helpers ─────────────────────────────────────────────────────────
info()  { echo -e "${CYAN}==>${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Step 1: Welcome & environment check ─────────────────────────────
echo ""
echo -e "${BLUE}┌─────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${NC}  ${BOLD}VurnChat Blind Relay Server v1.0${NC}          ${BLUE}│${NC}"
echo -e "${BLUE}│${NC}  Zero-knowledge WebSocket message relay    ${BLUE}│${NC}"
echo -e "${BLUE}└─────────────────────────────────────────────┘${NC}"
echo ""

# Detect OS
if [[ "$(uname -s)" != "Linux" ]]; then
    err "This script is designed for Linux systems only."
    err "Detected: $(uname -s)"
    exit 1
fi

# Check for sudo (or root)
if [[ $EUID -ne 0 ]]; then
    if ! command -v sudo &>/dev/null; then
        err "sudo is required but not installed."
        err "Run this script as root or install sudo."
        exit 1
    fi
    info "sudo privileges detected — will use them for system installation."
fi

SUDO="sudo"
[[ $EUID -eq 0 ]] && SUDO=""

# ── Step 2: Interactive prompts ─────────────────────────────────────
echo ""
info "Configuration (press Enter for defaults)"
echo ""

read -r -p "  $(echo -e "${BOLD}Port${NC}") [9000]: " input_port
port="${input_port:-9000}"
echo ""

read -r -p "  $(echo -e "${BOLD}Use domain with SSL?${NC}") (y/n): " use_ssl
use_ssl="${use_ssl:-n}"
echo ""

domain=""
if [[ "$use_ssl" == "y" || "$use_ssl" == "Y" ]]; then
    read -r -p "  $(echo -e "${BOLD}Enter your domain${NC}") (e.g., vurn.example.com): " domain
    if [[ -z "$domain" ]]; then
        err "Domain is required when SSL is enabled."
        exit 1
    fi
    echo ""
fi

# ── Step 3: Detect architecture & download binary ───────────────────
info "Detecting system architecture..."

arch=$(uname -m)
case "$arch" in
    x86_64)
        binary_arch="x86_64-unknown-linux-gnu"
        ;;
    aarch64 | arm64)
        binary_arch="aarch64-unknown-linux-gnu"
        ;;
    *)
        err "Unsupported architecture: $arch"
        err "Expected: x86_64 or aarch64"
        exit 1
        ;;
esac

ok "Architecture: $arch → $binary_arch"
echo ""

info "Downloading vurn-server binary..."

# Download URL — GitHub Releases latest
REPO="scramble22/VurnChat"
BINARY_URL="https://github.com/${REPO}/releases/latest/download/vurn-server-${binary_arch}"
INSTALL_PATH="/usr/local/bin/vurn-server"

if command -v curl &>/dev/null; then
    $SUDO curl -fsSL "$BINARY_URL" -o "$INSTALL_PATH" || {
        err "Download failed!"
        err "URL: $BINARY_URL"
        exit 1
    }
elif command -v wget &>/dev/null; then
    $SUDO wget -q "$BINARY_URL" -O "$INSTALL_PATH" || {
        err "Download failed!"
        err "URL: $BINARY_URL"
        exit 1
    }
else
    err "Neither curl nor wget found. Please install one of them."
    exit 1
fi

$SUDO chmod +x "$INSTALL_PATH"
ok "Binary installed: ${INSTALL_PATH}"

# ── Step 4: SSL certificate (if domain provided) ────────────────────
cert_args=""
if [[ "$use_ssl" == "y" || "$use_ssl" == "Y" ]]; then
    echo ""
    info "Setting up SSL with Let's Encrypt (Certbot)..."

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
            err "Please install it manually, then re-run this script."
            exit 1
        fi
        ok "Certbot installed"
    else
        ok "Certbot already installed"
    fi

    # Issue certificate
    echo ""
    info "Issuing SSL certificate for: ${domain}"
    $SUDO certbot certonly --standalone --non-interactive --agree-tos \
        --email "admin@${domain}" -d "${domain}" || {
        err "Failed to issue SSL certificate for ${domain}."
        err "Make sure the domain points to this server's IP and port 80 is open."
        exit 1
    }

    cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${domain}/privkey.pem"

    if [[ ! -f "$cert_path" || ! -f "$key_path" ]]; then
        err "Certificate files not found at expected location:"
        err "  $cert_path"
        err "  $key_path"
        exit 1
    fi

    cert_args="--cert ${cert_path} --key ${key_path}"
    ok "SSL certificate issued for ${domain}"
fi

# ── Step 5: Create systemd service ──────────────────────────────────
echo ""
info "Creating systemd service..."

SERVICE_FILE="/etc/systemd/system/vurn.service"

$SUDO tee "$SERVICE_FILE" > /dev/null <<SERVICEEOF
[Unit]
Description=VurnChat Blind Relay Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_PATH} --port ${port} ${cert_args}
Restart=always
RestartSec=3
User=root
# Secure the service
CapabilityBoundingSet=
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
SERVICEEOF

ok "Service file created: ${SERVICE_FILE}"

# ── Step 5b: Set up cert renewal hook (auto-restart after renewal) ──
if [[ "$use_ssl" == "y" || "$use_ssl" == "Y" ]]; then
    RENEWAL_HOOK="/etc/letsencrypt/renewal-hooks/deploy/vurn-restart.sh"
    $SUDO mkdir -p "$(dirname "$RENEWAL_HOOK")"
    $SUDO tee "$RENEWAL_HOOK" > /dev/null <<'HOOKEOF'
#!/bin/bash
# Certbot deploy hook — restarts vurn-server after certificate renewal.
# The server's built-in auto-reload handles zero-downtime rotation,
# but a restart ensures the OS-level file handles are refreshed too.
systemctl restart vurn.service
HOOKEOF
    $SUDO chmod +x "$RENEWAL_HOOK"
    ok "Cert renewal hook installed (restarts vurn.service on cert renewal)"
fi

# ── Step 6: Enable & start ──────────────────────────────────────────
echo ""
info "Enabling and starting service..."

$SUDO systemctl daemon-reload
$SUDO systemctl enable vurn.service
$SUDO systemctl start vurn.service

# Give it a moment to start
sleep 2

if $SUDO systemctl is-active --quiet vurn.service; then
    echo ""
    echo -e "${GREEN}┌─────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│${NC}  ${BOLD}VurnChat Blind Server is running!${NC}             ${GREEN}│${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────┘${NC}"
    echo ""

    if [[ "$use_ssl" == "y" || "$use_ssl" == "Y" ]]; then
        echo -e "  ${CYAN}Connect:${NC}  wss://${domain}:${port}/ws"
    else
        echo -e "  ${CYAN}Connect:${NC}  ws://YOUR_SERVER_IP:${port}/ws"
    fi
    echo ""
    echo -e "  ${YELLOW}Status:${NC}  sudo systemctl status vurn.service"
    echo -e "  ${YELLOW}Logs:${NC}    sudo journalctl -u vurn.service -f"
    echo ""

    # Verify the binary responds to --help
    if $INSTALL_PATH --help &>/dev/null; then
        ok "Binary responds correctly"
    fi
else
    err "Service failed to start!"
    err "Checking status..."
    $SUDO systemctl status vurn.service || true
    err "Last 20 log lines:"
    $SUDO journalctl -u vurn.service -n 20 --no-pager || true
    exit 1
fi
