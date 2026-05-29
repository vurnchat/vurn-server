#!/bin/bash
# ── VurnChat P2P Node — Management Script ───────────────────────────
#
# Usage:
#    ./manage.sh                   → Interactive menu (TUI)
#    ./manage.sh status            → Show node status
#    ./manage.sh logs [lines]      → Tail service logs
#    ./manage.sh restart           → Restart service
#    ./manage.sh start             → Start service
#    ./manage.sh stop              → Stop service
#    ./manage.sh update            → Update to latest release
#    ./manage.sh reconfigure       → Change settings interactively
#    ./manage.sh config            → Show current environment config
#    ./manage.sh health            → Quick health check
#    ./manage.sh version           → Show installed version
#    ./manage.sh uninstall         → Completely remove the node
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
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── OS & Privileges Check ──────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
IS_LINUX=false
[[ "$OS" == "Linux" ]] && IS_LINUX=true

SUDO="sudo"
[[ $EUID -eq 0 ]] && SUDO=""

if [[ "$IS_LINUX" == "false" ]]; then
    echo -e " ${RED}✘${NC} This script is designed for Linux (systemd)."
    echo "   macOS users: manage the binary directly at ${INSTALL_PATH}"
    exit 1
fi

if [[ $EUID -ne 0 ]] && ! command -v sudo &>/dev/null; then
    echo -e " ${RED}✘${NC} sudo is required. Run as root or install sudo."
    exit 1
fi

# ── Architecture Detection ──────────────────────────────────────────
case "$ARCH" in
    x86_64)        BINARY_ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) BINARY_ARCH="aarch64-unknown-linux-gnu" ;;
    *)             BINARY_ARCH="" ;;
esac

# ── Helpers ─────────────────────────────────────────────────────────
info()   { echo -e "${CYAN}==>${NC} ${BOLD}$1${NC}"; }
ok()     { echo -e "  ${GREEN}✔${NC} $1"; }
warn()   { echo -e "  ${YELLOW}⚠${NC} $1"; }
err()    { echo -e "  ${RED}✘${NC} $1"; }
header() { echo -e "${BLUE}$1${NC}"; }
dim()    { echo -e "${DIM}$1${NC}"; }

menu_item() {
    local num="$1"; shift
    echo -e "  ${BOLD}${CYAN}$num${NC}   ${BOLD}$1${NC}"
    if [[ -n "${2:-}" ]]; then
        echo -e "      ${DIM}$2${NC}"
    fi
}

divider() {
    echo -e "  ${BLUE}─────────────────────────────────────────────────────${NC}"
}

# ── Checks ──────────────────────────────────────────────────────────
is_installed() {
    [[ -f "$INSTALL_PATH" ]]
}

is_service_running() {
    $SUDO systemctl is-active --quiet vurn.service 2>/dev/null
}

get_version() {
    if is_installed; then
        $INSTALL_PATH --help 2>&1 | head -1 || echo "unknown"
    else
        echo "not installed"
    fi
}

get_config() {
    local key="$1"
    if [[ -f "$ENV_FILE" ]]; then
        grep "^${key}=" "$ENV_FILE" | cut -d'=' -f2- || echo ""
    else
        echo ""
    fi
}

# ── Commands ────────────────────────────────────────────────────────

cmd_version() {
    if is_installed; then
        local ver
        ver=$($INSTALL_PATH --help 2>&1 | head -1)
        ok "Installed: ${ver:-vurn-server}"
        local binary_size
        binary_size=$(du -h "$INSTALL_PATH" | cut -f1)
        dim "  Path: $INSTALL_PATH ($binary_size)"
    else
        err "Not installed at $INSTALL_PATH"
        echo "  Run install.sh first, or download from:"
        echo "  https://github.com/${REPO}/releases"
    fi
}

cmd_status() {
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  📊  VurnChat Node — Status                            │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""

    # ── Binary ──
    if is_installed; then
        local ver binary_size
        ver=$($INSTALL_PATH --help 2>&1 | head -1 || echo "vurn-server")
        binary_size=$(du -h "$INSTALL_PATH" | cut -f1)
        echo -e "  ${GREEN}●${NC} ${BOLD}Binary${NC}       ${ver} (${binary_size})"
        dim "                  ${INSTALL_PATH}"
    else
        echo -e "  ${RED}✘${NC} ${BOLD}Binary${NC}       Not installed"
    fi
    echo ""

    # ── Services ──
    echo -e "  ${BOLD}Services${NC}"
    for svc in vurn.service vurn-socat.service; do
        if [[ -f "/etc/systemd/system/$svc" ]]; then
            local state
            state="$($SUDO systemctl is-active "$svc" 2>/dev/null || echo inactive)"
            local enabled
            enabled="$($SUDO systemctl is-enabled "$svc" 2>/dev/null || echo disabled)"
            if [[ "$state" == "active" ]]; then
                echo -e "    ${GREEN}●${NC} $svc    ${GREEN}$state${NC} (${enabled})"
            else
                echo -e "    ${RED}✘${NC} $svc    ${RED}$state${NC} (${enabled})"
            fi
        fi
    done
    echo ""

    # ── Config ──
    echo -e "  ${BOLD}Configuration${NC}"
    if [[ -f "$ENV_FILE" ]]; then
        local port domain
        port=$(get_config "VURN_PORT")
        [[ -z "$port" ]] && port="9000"
        echo -e "    ${CYAN}WS Port:${NC}      ${BOLD}$port${NC}"
        if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
            local socat_line
            socat_line=$(grep 'ExecStart=' "$SOCAT_SERVICE_FILE" 2>/dev/null || true)
            if echo "$socat_line" | grep -q 'openssl-listen:'; then
                local socat_port
                socat_port=$(echo "$socat_line" | sed -n 's/.*openssl-listen:\([0-9]*\).*/\1/p')
                local cert_path
                cert_path=$(echo "$socat_line" | sed -n 's/.*cert=\([^,]*\).*/\1/p')
                echo -e "    ${CYAN}TLS Port:${NC}     ${BOLD}${socat_port}${NC} (socat → :${port})"
                if [[ -f "$cert_path" ]]; then
                    echo -e "    ${CYAN}Certificate:${NC}  ${cert_path} ${GREEN}✓${NC}"
                else
                    echo -e "    ${CYAN}Certificate:${NC}  ${cert_path} ${RED}✘ not found${NC}"
                fi
            fi
        else
            echo -e "    ${CYAN}TLS:${NC}          ${YELLOW}disabled${NC} (plain WS)"
        fi
    else
        echo -e "    ${YELLOW}No config file found${NC}"
    fi
    echo ""

    # ── Health Check ──
    echo -e "  ${BOLD}Health${NC}"
    if is_service_running; then
        local port health_code
        port=$(get_config "VURN_PORT")
        [[ -z "$port" ]] && port="9000"
        health_code=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/health" 2>/dev/null || echo "000")
        if [[ "$health_code" == "200" ]]; then
            echo -e "    ${GREEN}●${NC} HTTP /health → ${GREEN}200 OK${NC}"
        elif [[ "$health_code" == "503" ]]; then
            echo -e "    ${YELLOW}●${NC} HTTP /health → ${YELLOW}503 P2P not connected${NC}"
        else
            echo -e "    ${RED}●${NC} HTTP /health → ${RED}${health_code:-unreachable}${NC}"
        fi
    else
        echo -e "    ${RED}●${NC} Service not running"
    fi
    echo ""

    # ── Resource Usage ──
    if is_service_running; then
        echo -e "  ${BOLD}Resources${NC}"
        local pid mem cpu uptime
        pid=$($SUDO systemctl show vurn.service -p MainPID --value 2>/dev/null || echo "")
        if [[ -n "$pid" && "$pid" -gt 1 ]]; then
            mem=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0")
            cpu=$(ps -o %cpu= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0")
            local mem_mb=$((mem / 1024))
            echo -e "    ${CYAN}PID:${NC}      ${BOLD}$pid${NC}"
            echo -e "    ${CYAN}Memory:${NC}   ${BOLD}${mem_mb}MB${NC} RSS"
            echo -e "    ${CYAN}CPU:${NC}      ${BOLD}${cpu}%${NC}"
            local started
            started=$($SUDO systemctl show vurn.service -p ActiveEnterTimestamp --value 2>/dev/null || echo "")
            [[ -n "$started" ]] && echo -e "    ${CYAN}Uptime:${NC}   ${started}"
        fi
        echo ""
    fi

    # ── P2P Network ──
    echo -e "  ${BOLD}P2P Network${NC}"
    local p2p_port
    p2p_port=$(get_config "VURN_P2P_LISTEN" | grep -oP 'tcp/\K[0-9]+' || echo "dynamic")
    echo -e "    ${CYAN}P2P listen:${NC}  /ip4/0.0.0.0/tcp/${p2p_port}"
    echo ""

    # ── Data ──
    echo -e "  ${BOLD}Data${NC}"
    if [[ -d "$STATE_DIR" ]]; then
        local db_size
        db_size=$(du -sh "$STATE_DIR" 2>/dev/null | cut -f1 || echo "?")
        echo -e "    ${CYAN}State:${NC}      ${STATE_DIR} (${db_size})"
    fi
    if [[ -d "$CONFIG_DIR" ]]; then
        echo -e "    ${CYAN}Config:${NC}     ${CONFIG_DIR}"
    fi
    echo ""
}

cmd_logs() {
    local lines="${1:-50}"
    if ! is_service_running && [[ ! -f "$SERVICE_FILE" ]]; then
        err "vurn.service not found. Is the node installed?"
        exit 1
    fi
    info "Showing last $lines lines of vurn.service logs (Ctrl+C to exit)..."
    echo ""
    $SUDO journalctl -u vurn.service -n "$lines" --no-pager -e
    echo ""
    info "Follow live: ${DIM}sudo journalctl -u vurn.service -f${NC}"
}

cmd_start() {
    if ! is_installed; then
        err "Binary not found at $INSTALL_PATH. Run install.sh first."
        exit 1
    fi
    if ! [[ -f "$SERVICE_FILE" ]]; then
        err "Service file not found. Run './manage.sh reconfigure' first."
        exit 1
    fi
    info "Starting vurn.service..."
    $SUDO systemctl start vurn.service
    if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
        $SUDO systemctl start vurn-socat.service 2>/dev/null || true
    fi
    sleep 2
    if is_service_running; then
        ok "vurn.service started successfully"
    else
        err "Failed to start — check: sudo journalctl -u vurn.service -n 30 --no-pager"
    fi
}

cmd_stop() {
    if ! is_service_running; then
        warn "vurn.service is not running"
        return
    fi
    info "Stopping vurn.service..."
    $SUDO systemctl stop vurn.service
    if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
        $SUDO systemctl stop vurn-socat.service 2>/dev/null || true
    fi
    sleep 1
    if ! is_service_running; then
        ok "vurn.service stopped"
    else
        err "Failed to stop — force: sudo systemctl kill vurn.service"
    fi
}

cmd_restart() {
    if is_service_running; then
        info "Restarting vurn.service..."
        $SUDO systemctl restart vurn.service
        if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
            $SUDO systemctl restart vurn-socat.service 2>/dev/null || true
        fi
    else
        cmd_start
        return
    fi
    sleep 2
    if is_service_running; then
        ok "vurn.service restarted successfully"
    else
        err "Restart failed — check: sudo journalctl -u vurn.service -n 30 --no-pager"
    fi
}

cmd_health() {
    if ! is_service_running; then
        err "vurn.service is not running"
        exit 1
    fi

    local port
    port=$(get_config "VURN_PORT")
    [[ -z "$port" ]] && port="9000"

    info "Health check (127.0.0.1:${port}/health)..."
    echo ""
    local http_code body tmp_body
    tmp_body=$(mktemp)
    http_code=$(curl -sf -o "$tmp_body" -w "%{http_code}" "http://127.0.0.1:${port}/health" 2>/dev/null || echo "000")
    body=$(cat "$tmp_body" 2>/dev/null || echo "")
    rm -f "$tmp_body"

    if [[ "$http_code" == "200" ]]; then
        echo -e "  ${GREEN}✔${NC} HTTP ${http_code} — ${body:-OK}"
        echo ""
        ok "Node is healthy and P2P connected"
    elif [[ "$http_code" == "503" ]]; then
        echo -e "  ${YELLOW}●${NC} HTTP ${http_code} — ${body:-P2P not connected}"
        echo ""
        warn "Node is running but P2P network not connected yet"
        warn "This is normal during startup — wait a few seconds"
    else
        echo -e "  ${RED}✘${NC} HTTP ${http_code} — ${body:-unreachable}"
        echo ""
        err "Health check failed"
        err "Check: sudo journalctl -u vurn.service -n 20 --no-pager"
        exit 1
    fi
}

cmd_config() {
    if ! [[ -f "$ENV_FILE" ]]; then
        err "No config file found at $ENV_FILE"
        echo "  Run './manage.sh reconfigure' to create one."
        exit 1
    fi

    header "┌─────────────────────────────────────────────────────────┐"
    header "│  ⚙️  VurnChat Node — Configuration                      │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""
    echo -e "  ${DIM}File: ${ENV_FILE}${NC}"
    echo ""

    # Read and display all non-empty, non-comment lines
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            echo ""
        elif [[ "$line" =~ ^# ]]; then
            # Comment line — dim it
            local clean_comment
            clean_comment="${line#\# }"
            clean_comment="${clean_comment#\#}"
            echo -e "  ${DIM}${clean_comment}${NC}"
        elif [[ "$line" =~ ^[A-Z_]+= ]]; then
            local key val
            key="${line%%=*}"
            val="${line#*=}"
            # Mask secrets
            if [[ "$key" == *"KEY"* ]] || [[ "$key" == *"SECRET"* ]] || [[ "$key" == *"PASSWORD"* ]]; then
                val="${val:0:4}****"
            fi
            echo -e "  ${BOLD}${CYAN}${key}${NC}=${val}"
        fi
    done < "$ENV_FILE"
    echo ""
}

cmd_update() {
    if ! is_installed; then
        err "VurnChat is not installed at $INSTALL_PATH. Run install.sh first."
        exit 1
    fi

    local old_ver new_ver
    old_ver=$($INSTALL_PATH --help 2>&1 | head -1 || echo "unknown")

    header "┌─────────────────────────────────────────────────────────┐"
    header "│  🔄  Updating VurnChat Node to Latest Release           │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""
    echo -e "  ${CYAN}Current:${NC}  ${BOLD}${old_ver}${NC}"
    echo -e "  ${CYAN}Arch:${NC}     ${BINARY_ARCH}"
    echo ""

    if [[ -z "$BINARY_ARCH" ]]; then
        err "Unsupported architecture: $ARCH"
        exit 1
    fi

    local binary_url
    binary_url="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}-${BINARY_ARCH}"

    info "Downloading latest binary..."
    local tmp_bin
    tmp_bin=$(mktemp)

    if ! curl -fsSL "$binary_url" -o "$tmp_bin"; then
        err "Failed to download. Check internet or repo status."
        rm -f "$tmp_bin"
        exit 1
    fi

    chmod +x "$tmp_bin"

    # Quick sanity check
    if ! "$tmp_bin" --help &>/dev/null; then
        err "Downloaded binary is corrupted or invalid"
        rm -f "$tmp_bin"
        exit 1
    fi

    new_ver=$("$tmp_bin" --help 2>&1 | head -1 || echo "unknown")
    local binary_size
    binary_size=$(du -h "$tmp_bin" | cut -f1)

    info "Stopping services..."
    $SUDO systemctl stop vurn.service || true
    $SUDO systemctl stop vurn-socat.service 2>/dev/null || true

    info "Replacing binary..."
    $SUDO mv "$tmp_bin" "$INSTALL_PATH"
    $SUDO chmod +x "$INSTALL_PATH"

    info "Starting services..."
    $SUDO systemctl start vurn.service
    if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
        $SUDO systemctl start vurn-socat.service 2>/dev/null || true
    fi

    echo ""
    echo -e "  ${GREEN}✔${NC} Update complete:"
    echo -e "    ${CYAN}Before:${NC}  ${old_ver}"
    echo -e "    ${CYAN}After:${NC}   ${BOLD}${new_ver}${NC} (${binary_size})"
    echo ""

    # Auto health check
    sleep 2
    if is_service_running; then
        local port health_code
        port=$(get_config "VURN_PORT")
        [[ -z "$port" ]] && port="9000"
        health_code=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/health" 2>/dev/null || echo "000")
        if [[ "$health_code" == "200" ]]; then
            ok "Service running and healthy (HTTP ${health_code})"
        else
            warn "Service running, health returned HTTP ${health_code}"
            warn "Check: sudo journalctl -u vurn.service -n 20 --no-pager"
        fi
    else
        err "Service failed to start after update"
        err "Check: sudo journalctl -u vurn.service -n 30 --no-pager"
    fi
}

cmd_reconfigure() {
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  ⚙️  Reconfiguring VurnChat Node                        │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""

    # Read current settings
    local current_port current_bs
    current_port=$(get_config "VURN_PORT")
    [[ -z "$current_port" ]] && current_port="9000"
    current_bs=$(get_config "VURN_BOOTSTRAP" || true)

    info "Enter new values (Enter to keep current):"
    echo ""

    read -r -p "   WS Port [${current_port}]: " input_port
    PORT="${input_port:-$current_port}"

    local domain="" email="" ssl="n"
    local current_domain="" current_ssl="n"
    if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
        local socat_line
        socat_line=$(grep 'ExecStart=' "$SOCAT_SERVICE_FILE" 2>/dev/null || true)
        if echo "$socat_line" | grep -q 'openssl-listen:'; then
            current_ssl="y"
            current_domain=$(echo "$socat_line" | sed -n 's/.*cert=/etc/letsencrypt/live\/\([^/]*\).*/\1/p' 2>/dev/null || echo "")
            SOCAT_PORT=$(echo "$socat_line" | sed -n 's/.*openssl-listen:\([0-9]*\).*/\1/p')
        fi
    fi

    local domain_prompt="Domain for TLS/WSS"
    if [[ "$current_ssl" == "y" ]]; then
        domain_prompt="Domain for TLS/WSS [${current_domain}]"
    fi

    read -r -p "   ${domain_prompt} (empty = plain WS): " input_domain
    if [[ -n "$input_domain" ]]; then
        domain="$input_domain"
        ssl="y"
        local default_email="admin@${domain}"
        read -r -p "   Email for Let's Encrypt [${default_email}]: " input_email
        email="${input_email:-$default_email}"
        read -r -p "   Socat TLS listen port [${SOCAT_PORT}]: " input_socat
        SOCAT_PORT="${input_socat:-$SOCAT_PORT}"
    elif [[ "$current_ssl" == "y" ]] && [[ -z "$input_domain" ]]; then
        # Keep existing domain
        domain="$current_domain"
        ssl="y"
    fi

    local bootstrap_addrs=()
    echo ""
    warn "Bootstrap nodes are auto-fetched from GitHub. Manual override is optional."
    read -r -p "   Bootstrap peer (optional): " input_bs
    if [[ -n "$input_bs" ]]; then
        bootstrap_addrs+=("$input_bs")
    fi

    echo ""

    # TLS certificate via Certbot
    if [[ "$ssl" == "y" && -n "$domain" ]]; then
        info "SSL Certificate Setup..."
        if ! command -v certbot &>/dev/null; then
            info "Installing certbot..."
            if command -v apt &>/dev/null; then
                $SUDO apt update -qq && $SUDO apt install certbot -y -qq
            fi
        fi

        local cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
        local key_path="/etc/letsencrypt/live/${domain}/privkey.pem"

        if [[ ! -f "$cert_path" ]]; then
            info "Issuing certificate for ${domain}..."
            $SUDO certbot certonly --standalone --non-interactive --agree-tos \
                --email "${email}" -d "${domain}" || {
                err "Certificate issuance failed"
                exit 1
            }
            ok "Certificate issued for ${domain}"
        else
            ok "Certificate already exists for ${domain}"
        fi

        $SUDO chmod 755 /etc/letsencrypt/live /etc/letsencrypt/archive
        $SUDO chmod 755 "/etc/letsencrypt/live/${domain}"
        $SUDO chmod -R o+r "/etc/letsencrypt/archive/${domain}" 2>/dev/null || true
    fi

    # Write env file
    info "Writing environment config..."
    $SUDO tee "$ENV_FILE" > /dev/null <<ENVEOF
# VurnChat Server Configuration — reconfigured on $(date -I)
VURN_PORT=${PORT}
VURN_P2P_LISTEN=/ip4/0.0.0.0/tcp/9001
ENVEOF

    if [[ ${#bootstrap_addrs[@]} -gt 0 ]]; then
        echo "VURN_BOOTSTRAP=${bootstrap_addrs[*]}" | $SUDO tee -a "$ENV_FILE" > /dev/null
    fi

    $SUDO chmod 600 "$ENV_FILE"
    $SUDO chown vurn:vurn "$ENV_FILE" 2>/dev/null || true
    ok "Config written"

    # Write systemd service
    info "Writing service file..."
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
    ok "Service file written"

    # Write socat service if TLS
    if [[ "$ssl" == "y" && -n "$domain" ]]; then
        local cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
        local key_path="/etc/letsencrypt/live/${domain}/privkey.pem"

        info "Writing socat TLS proxy service..."
        $SUDO tee "$SOCAT_SERVICE_FILE" > /dev/null <<SOCATEOF
[Unit]
Description=VurnChat — Socat TLS Proxy (:${SOCAT_PORT} TLS → :${PORT} plain WS)
Documentation=https://github.com/${REPO}
After=network-online.target vurn.service
Requires=vurn.service

[Service]
Type=simple
ExecStart=/usr/bin/socat openssl-listen:${SOCAT_PORT},fork,reuseaddr,cert=${cert_path},key=${key_path},verify=0 tcp:127.0.0.1:${PORT}
Restart=always
RestartSec=5
RestartMaxDelaySec=30
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SOCATEOF
        $SUDO chmod 644 "$SOCAT_SERVICE_FILE"

        # Renewal hook
        $SUDO mkdir -p "$(dirname "$RENEWAL_HOOK")"
        $SUDO tee "$RENEWAL_HOOK" > /dev/null <<'HOOKEOF'
#!/bin/bash
systemctl restart vurn-socat.service
HOOKEOF
        $SUDO chmod +x "$RENEWAL_HOOK"

        ok "Socat TLS proxy on :${SOCAT_PORT} → :${PORT}"
    else
        $SUDO rm -f "$SOCAT_SERVICE_FILE" 2>/dev/null || true
        $SUDO rm -f "$RENEWAL_HOOK" 2>/dev/null || true
    fi

    # Apply
    info "Applying configuration..."
    $SUDO systemctl daemon-reload
    $SUDO systemctl restart vurn.service
    if [[ -f "$SOCAT_SERVICE_FILE" ]]; then
        $SUDO systemctl enable vurn-socat.service 2>/dev/null || true
        $SUDO systemctl restart vurn-socat.service 2>/dev/null || true
    fi

    echo ""
    ok "Node reconfigured and restarted!"
    echo ""

    # Show result
    if [[ "$ssl" == "y" && -n "$domain" ]]; then
        echo -e "  ${CYAN}Connect:${NC} wss://${domain}:${SOCAT_PORT}/ws"
    else
        local ip
        ip=$(curl -fs https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP")
        echo -e "  ${CYAN}Connect:${NC} ws://${ip}:${PORT}/ws"
    fi
    echo ""
}

cmd_uninstall() {
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  🚨  UNINSTALL VURNCHAT NODE                             │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""
    warn "${BOLD}This will permanently delete:${NC}"
    echo "    • Binary:        ${INSTALL_PATH}"
    echo "    • State DB:      ${STATE_DIR}  (all mailbox data!)"
    echo "    • Config:        ${CONFIG_DIR}"
    echo "    • Service files: vurn.service, vurn-socat.service"
    echo "    • Log rotation:  ${LOGROTATE_FILE}"
    echo "    • Certificates:  /etc/letsencrypt/live/* (if TLS)"
    echo "    • System user:   vurn"
    echo ""
    read -r -p "   Are you absolutely sure? Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        info "Uninstall aborted."
        exit 0
    fi

    echo ""

    info "Stopping and disabling services..."
    $SUDO systemctl stop vurn-socat.service 2>/dev/null || true
    $SUDO systemctl disable vurn-socat.service 2>/dev/null || true
    $SUDO systemctl stop vurn.service 2>/dev/null || true
    $SUDO systemctl disable vurn.service 2>/dev/null || true
    ok "Services stopped"

    info "Removing files..."
    $SUDO rm -f "$SERVICE_FILE" "$SOCAT_SERVICE_FILE" "$INSTALL_PATH"
    $SUDO rm -f "$LOGROTATE_FILE" "$RENEWAL_HOOK"
    ok "Binaries and service units removed"

    info "Deleting data and config directories..."
    $SUDO rm -rf "$STATE_DIR" "$CONFIG_DIR" /var/log/vurn
    ok "Data and config deleted"

    info "Removing system user..."
    if id -u vurn &>/dev/null; then
        $SUDO userdel -r vurn 2>/dev/null || $SUDO userdel vurn || true
        ok "User 'vurn' removed"
    fi

    $SUDO systemctl daemon-reload

    echo ""
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  ✅  VurnChat Node completely removed.                   │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""
    warn "If you used TLS, certificates remain at /etc/letsencrypt/"
    warn "Remove manually: sudo certbot delete --cert-name <domain>"
}

# ── TUI Menu ────────────────────────────────────────────────────────

show_menu_header() {
    clear
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  🟣  VurnChat P2P Node Management                      │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""
    # Status line
    local state_text state_color
    if is_service_running; then
        state_text="● Active"
        state_color="${GREEN}"
        local ver
        ver=$($INSTALL_PATH --help 2>&1 | head -1 | sed 's/^VurnChat P2P Node //' || echo "")
        echo -e "  ${state_color}●${NC} ${BOLD}Status:${NC} ${GREEN}Running${NC} ${DIM}${ver}${NC}          $(date '+%H:%M:%S')"
    elif is_installed; then
        echo -e "  ${YELLOW}●${NC} ${BOLD}Status:${NC} ${YELLOW}Stopped${NC}               $(date '+%H:%M:%S')"
    else
        echo -e "  ${RED}✘${NC} ${BOLD}Status:${NC} ${RED}Not installed${NC}          $(date '+%H:%M:%S')"
    fi
    echo ""
}

show_menu() {
    show_menu_header

    divider
    echo ""
    echo -e "  ${BOLD}${BLUE}━━─═══  Management ═══─━━${NC}"
    echo ""
    menu_item "1"  "Status"        "Full node status: health, resources, config"
    menu_item "2"  "Logs"          "Tail service logs (journalctl)"
    menu_item "3"  "Restart"       "Restart vurn service"
    echo ""
    echo -e "  ${BOLD}${BLUE}━━─═══  Updates & Config ═══─━━${NC}"
    echo ""
    menu_item "4"  "Update"        "Download and install latest release"
    menu_item "5"  "Reconfigure"   "Change port, domain, TLS settings"
    menu_item "6"  "Config"        "View current configuration"
    menu_item "7"  "Health"        "Quick health check (HTTP /health)"
    echo ""
    echo -e "  ${BOLD}${BLUE}━━─═══  Danger Zone ═══─━━${NC}"
    echo ""
    menu_item "u"  "Uninstall"     "${RED}Completely remove node and all data${NC}"
    echo ""
    divider
    echo ""
    echo -e "  ${DIM}Version: 0.6.5  |  q = quit  |  ? = help${NC}"
    echo ""
}

menu_loop() {
    local choice
    while true; do
        show_menu
        read -r -p "  ${BOLD}Select action${NC} [1-7/q]: " choice
        echo ""

        case "$choice" in
            1)   cmd_status; press_any_key ;;
            2)   cmd_logs; press_any_key ;;
            3)   cmd_restart; press_any_key ;;
            4)   cmd_update; press_any_key ;;
            5)   cmd_reconfigure; press_any_key ;;
            6)   cmd_config; press_any_key ;;
            7)   cmd_health; press_any_key ;;
            u|U) cmd_uninstall; press_any_key ;;
            q|Q|exit) echo -e "  ${CYAN}Bye!${NC}"; exit 0 ;;
            *)   echo -e "  ${YELLOW}Invalid option: $choice${NC}"; press_any_key ;;
        esac
    done
}

press_any_key() {
    echo ""
    read -r -p "  ${DIM}Press Enter to continue...${NC}" _dummy
}

# ── CLI Router & Help ───────────────────────────────────────────────

show_help() {
    header "┌─────────────────────────────────────────────────────────┐"
    header "│  🟣  VurnChat Node — Management Script                  │"
    header "└─────────────────────────────────────────────────────────┘"
    echo ""
    echo -e "  ${BOLD}Usage:${NC}"
    echo ""
    echo -e "    ${BOLD}${CYAN}./manage.sh${NC}                    ${DIM}Interactive menu${NC}"
    echo -e "    ${BOLD}${CYAN}./manage.sh <command>${NC}           ${DIM}Direct command${NC}"
    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo ""
    echo -e "    ${GREEN}status${NC}       ${DIM}Show full node status${NC}"
    echo -e "    ${GREEN}logs [N]${NC}     ${DIM}Tail last N lines of logs (default 50)${NC}"
    echo -e "    ${GREEN}restart${NC}      ${DIM}Restart vurn service${NC}"
    echo -e "    ${GREEN}start${NC}        ${DIM}Start vurn service${NC}"
    echo -e "    ${GREEN}stop${NC}         ${DIM}Stop vurn service${NC}"
    echo -e "    ${GREEN}update${NC}       ${DIM}Update binary to latest GitHub release${NC}"
    echo -e "    ${GREEN}reconfigure${NC}  ${DIM}Change port, domain, TLS settings${NC}"
    echo -e "    ${GREEN}config${NC}       ${DIM}Show current environment config${NC}"
    echo -e "    ${GREEN}health${NC}       ${DIM}Quick health check (HTTP /health)${NC}"
    echo -e "    ${GREEN}version${NC}      ${DIM}Show installed binary version${NC}"
    echo -e "    ${GREEN}uninstall${NC}    ${DIM}Completely remove node and all data${NC}"
    echo ""
    # Also accept old --flags
    echo -e "  ${DIM}Legacy flags: --update, --reconfigure, --uninstall${NC}"
    echo ""
}

# ── Main Entry Point ────────────────────────────────────────────────

main() {
    if [[ $# -eq 0 ]]; then
        # Interactive menu if terminal attached
        if [[ -t 0 ]]; then
            menu_loop
        else
            show_help
        fi
        exit 0
    fi

    local cmd="${1:-}"
    local arg="${2:-}"

    case "$cmd" in
        # Modern CLI commands
        status)    cmd_status ;;
        logs)      cmd_logs "$arg" ;;
        restart)   cmd_restart ;;
        start)     cmd_start ;;
        stop)      cmd_stop ;;
        update)    cmd_update ;;
        reconfigure) cmd_reconfigure ;;
                   config)      cmd_config ;;
        health)    cmd_health ;;
        version)   cmd_version ;;
        uninstall) cmd_uninstall ;;
        help|--help|-h)
                   show_help ;;
        # Legacy flags (backwards compat with old API)
        --update)      cmd_update ;;
        --reconfigure) cmd_reconfigure ;;
        --uninstall)   cmd_uninstall ;;
        *)
            err "Unknown command: $cmd"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
