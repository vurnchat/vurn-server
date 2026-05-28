#!/bin/bash
# ── VurnChat P2P Node — Management Script ───────────────────────────
#
# Usage:
#    ./manage.sh --update
#    ./manage.sh --reconfigure
#    ./manage.sh --uninstall
#
set -euo pipefail

# ── Constants ───────────────────────────────────────────────────────
REPO="vurnchat/vurn-server"
BINARY_NAME="vurn-server"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
STATE_DIR="/var/lib/vurn"
CONFIG_DIR="/etc/vurn"
ENV_FILE="${CONFIG_DIR}/vurn.env"
SERVICE_FILE="/etc/systemd/system/vurn.service"
SOCAT_SERVICE_FILE="/etc/systemd/system/vurn-socat.service"
LOGROTATE_FILE="/etc/logrotate.d/vurn"
RENEWAL_HOOK="/etc/letsencrypt/renewal-hooks/deploy/vurn-restart.sh"
SOCAT_PORT="9443"

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

# ── Environment & Privileges Check ──────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
if [[ "$OS" != "Linux" ]]; then
    err "This management script fully supports Linux only (due to systemd/certbot dependency)."
    exit 1
fi

SUDO="sudo"
if [[ $EUID -eq 0 ]]; then
    SUDO=""
fi

if [[ $EUID -ne 0 ]] && ! command -v sudo &>/dev/null; then
    err "sudo is required. Run as root or install sudo."
    exit 1
fi

# ── Architecture Detection ──────────────────────────────────────────
case "$ARCH" in
    x86_64)        binary_arch="x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) binary_arch="aarch64-unknown-linux-gnu" ;;
    *)
        err "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# ── Actions ─────────────────────────────────────────────────────────

show_help() {
    echo "VurnChat Node Management Script"
    echo ""
    echo "Usage:"
    echo "  $0 [option]"
    echo ""
    echo "Options:"
    echo "  --update         Update node binary to the latest GitHub release"
    echo "  --reconfigure    Change settings (port, domain, SSL, bootstrap nodes)"
    echo "  --uninstall      Completely remove the node, configurations, certificates and user"
    echo "  --help, -h       Show this help menu"
    echo ""
}

do_update() {
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  🔄 Updating VurnChat Node to Latest Release            │"
    header "└─────────────────────────────────────────────────────────┘"
    
    if [ ! -f "$INSTALL_PATH" ]; then
        err "VurnChat is not installed at $INSTALL_PATH. Run install.sh first."
        exit 1
    fi

    BINARY_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}-${binary_arch}"
    
    info "Downloading latest binary..."
    _tmp_bin=$(mktemp)
    if $SUDO curl -fsSL "$BINARY_URL" -o "$_tmp_bin"; then
        chmod +x "$_tmp_bin"
        if ! "$_tmp_bin" --help &>/dev/null; then
            err "Downloaded binary is corrupted or failed execution check."
            rm -f "$_tmp_bin"
            exit 1
        fi
        
        info "Stopping vurn service..."
        $SUDO systemctl stop vurn.service || true
        $SUDO systemctl stop vurn-socat.service 2>/dev/null || true
        
        info "Replacing binary..."
        $SUDO mv "$_tmp_bin" "$INSTALL_PATH"
        $SUDO chmod +x "$INSTALL_PATH"
        
        info "Starting vurn service..."
        $SUDO systemctl start vurn.service
        if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
            $SUDO systemctl start vurn-socat.service
        fi
        ok "VurnChat node updated successfully!"
    else
        err "Failed to download latest release. Check internet connection or repository status."
        rm -f "$_tmp_bin"
        exit 1
    fi
}

do_reconfigure() {
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  ⚙️ Reconfiguring VurnChat Node Settings                 │"
    header "└─────────────────────────────────────────────────────────┘"

    # Считываем текущие настройки, если они есть
    CURRENT_PORT="9000"
    if [ -f "$ENV_FILE" ]; then
        CURRENT_PORT=$(grep "VURN_PORT=" "$ENV_FILE" | cut -d'=' -f2 || echo "9000")
    fi

    echo ""
    info "Enter new configuration values (Press Enter to keep defaults)"
    echo ""
    
    read -r -p "   Port [${CURRENT_PORT}]: " input_port
    PORT="${input_port:-$CURRENT_PORT}"

    DOMAIN=""
    EMAIL=""
    SSL="n"
    read -r -p "   Domain for SSL/WSS (leave empty to skip/disable TLS): " DOMAIN
    if [[ -n "$DOMAIN" ]]; then
        SSL="y"
        read -r -p "   Email for Let's Encrypt [admin@${DOMAIN}]: " input_email
        EMAIL="${input_email:-admin@${DOMAIN}}"
        read -r -p "   Socat TLS listen port [${SOCAT_PORT}]: " input_socat
        SOCAT_PORT="${input_socat:-$SOCAT_PORT}"
    fi

    BOOTSTRAP_ADDRS=()
    read -r -p "   Bootstrap peer multiaddr (optional): " input_bs
    if [[ -n "$input_bs" ]]; then
        BOOTSTRAP_ADDRS+=("$input_bs")
    fi

    # Настройка SSL через Certbot
    CERT_ARGS=""
    if [[ "$SSL" == "y" ]]; then
        info "Checking/Issuing SSL certificate via Certbot..."
        if ! command -v certbot &>/dev/null; then
            info "Installing certbot..."
            if command -v apt &>/dev/null; then $SUDO apt update -qq && $SUDO apt install certbot -y -qq; fi
        fi

        CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
        KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

        if [[ ! -f "$CERT_PATH" ]]; then
            $SUDO certbot certonly --standalone --non-interactive --agree-tos --email "${EMAIL}" -d "${DOMAIN}" || {
                err "Failed to issue SSL certificate."
                exit 1
            }
        fi
        
        $SUDO chmod 755 /etc/letsencrypt/live /etc/letsencrypt/archive
        $SUDO chmod 755 "/etc/letsencrypt/live/${DOMAIN}"
        $SUDO chmod -R o+r "/etc/letsencrypt/archive/${DOMAIN}" 2>/dev/null || true
        CERT_ARGS="--cert ${CERT_PATH} --key ${KEY_PATH}"
    fi

    info "Writing new environment file..."
    $SUDO rm -f "$ENV_FILE"
    $SUDO tee "$ENV_FILE" > /dev/null <<ENVEOF
# VurnChat Server Configuration — Reconfigured on $(date -I)
VURN_PORT=${PORT}
VURN_P2P_LISTEN=/ip4/0.0.0.0/tcp/9001
ENVEOF

    if [[ ${#BOOTSTRAP_ADDRS[@]} -gt 0 ]]; then
        echo "VURN_BOOTSTRAP=${BOOTSTRAP_ADDRS[*]}" | $SUDO tee -a "$ENV_FILE" > /dev/null
    fi

    $SUDO chmod 600 "$ENV_FILE"
    $SUDO chown vurn:vurn "$ENV_FILE"

    info "Rebuilding systemd service..."

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
EnvironmentFile=-${ENV_FILE}

ExecStart=${INSTALL_PATH}

Restart=always
RestartSec=5
RestartMaxDelaySec=30
MemoryMax=512M
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
SystemCallFilter=@system-service
[Install]
WantedBy=multi-user.target
SERVICEEOF

    $SUDO chmod 644 "$SERVICE_FILE"

    # Socat TLS proxy service (if SSL enabled)
    if [[ "$SSL" == "y" ]]; then
        $SUDO tee "$SOCAT_SERVICE_FILE" > /dev/null <<SOCATEOF
[Unit]
Description=VurnChat — Socat TLS Proxy (:${SOCAT_PORT} TLS -> :${PORT} plain WS)
Documentation=https://github.com/${REPO}
After=network-online.target vurn.service
Requires=vurn.service

[Service]
Type=simple
ExecStart=/usr/bin/socat openssl-listen:${SOCAT_PORT},fork,reuseaddr,cert=${CERT_PATH},key=${KEY_PATH},verify=0 tcp:127.0.0.1:${PORT}
Restart=always
RestartSec=5
RestartMaxDelaySec=30
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SOCATEOF
        $SUDO chmod 644 "$SOCAT_SERVICE_FILE"

        $SUDO mkdir -p "$(dirname "$RENEWAL_HOOK")"
        $SUDO tee "$RENEWAL_HOOK" > /dev/null <<'HOOKEOF'
#!/bin/bash
systemctl restart vurn-socat.service
HOOKEOF
        $SUDO chmod +x "$RENEWAL_HOOK"
    else
        $SUDO rm -f "$SOCAT_SERVICE_FILE" 2>/dev/null || true
        $SUDO rm -f "$RENEWAL_HOOK"
    fi

    info "Applying configuration changes..."
    $SUDO systemctl daemon-reload
    $SUDO systemctl restart vurn.service
    if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
        $SUDO systemctl enable vurn-socat.service 2>/dev/null || true
        $SUDO systemctl restart vurn-socat.service 2>/dev/null || true
    fi
    ok "Node successfully reconfigured and restarted!"
}

do_uninstall() {
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  🚨 UNINSTALLING VURNCHAT NODE COMPLETELY               │"
    header "└─────────────────────────────────────────────────────────┘"
    warn "This action will permanently delete all logs, configurations, and state databases!"
    read -r -p "   Are you absolutely sure you want to proceed? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Uninstall aborted."
        exit 0
    fi

    info "Stopping and disabling services..."
    $SUDO systemctl stop vurn-socat.service 2>/dev/null || true
    $SUDO systemctl disable vurn-socat.service 2>/dev/null || true
    $SUDO systemctl stop vurn.service 2>/dev/null || true
    $SUDO systemctl disable vurn.service 2>/dev/null || true

    info "Removing files and service units..."
    $SUDO rm -f "$SERVICE_FILE"
    $SUDO rm -f "$SOCAT_SERVICE_FILE"
    $SUDO rm -f "$INSTALL_PATH"
    $SUDO rm -f "$LOGROTATE_FILE"
    $SUDO rm -f "$RENEWAL_HOOK"

    info "Deleting state and configuration directories..."
    $SUDO rm -rf "$STATE_DIR"
    $SUDO rm -rf "$CONFIG_DIR"

    # Очистка системных логов в /var/log, если они создавались logrotate
    $SUDO rm -rf /var/log/vurn

    info "Removing system user 'vurn'..."
    if id -u vurn &>/dev/null; then
        $SUDO userdel -r vurn 2>/dev/null || $SUDO userdel vurn || true
        ok "System user 'vurn' removed"
    fi

    $SUDO systemctl daemon-reload
    echo ""
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  💥 VurnChat Node has been completely removed.          │"
    header "└─────────────────────────────────────────────────────────┘"
}

# ── CLI Router ──────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

case "$1" in
    --update)       do_update ;;
    --reconfigure)  do_reconfigure ;;
    --uninstall)    do_uninstall ;;
    --help|-h)      show_help ;;
    *)              err "Unknown option: $1"; show_help; exit 1 ;;
esac
