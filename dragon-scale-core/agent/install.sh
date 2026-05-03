#!/usr/bin/env bash
# DRAGON_SCALE Agent Installer
# Usage: curl -sSL https://dragon-scale.example.com/install.sh | bash -s -- --token <AGENT_TOKEN> --server <API_URL>
set -euo pipefail

DRAGON_SCALE_VERSION="${DRAGON_SCALE_VERSION:-latest}"
DRAGON_SCALE_API_URL=""
DRAGON_SCALE_AGENT_TOKEN=""
INSTALL_DIR="/opt/dragon-scale-agent"
DATA_DIR="/var/lib/dragon-scale"
LOG_DIR="/var/log/dragon-scale"
SERVICE_NAME="dragon-scale-agent"

log() { echo "[dragon-scale-install] $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --token)   DRAGON_SCALE_AGENT_TOKEN="$2"; shift 2 ;;
            --server)  DRAGON_SCALE_API_URL="$2"; shift 2 ;;
            --version) DRAGON_SCALE_VERSION="$2"; shift 2 ;;
            *)         die "Unknown option: $1" ;;
        esac
    done

    [[ -n "$DRAGON_SCALE_AGENT_TOKEN" ]] || die "--token is required"
    [[ -n "$DRAGON_SCALE_API_URL" ]] || die "--server is required"
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VERSION="${VERSION_ID:-0}"
    else
        DISTRO_ID="unknown"
        DISTRO_VERSION="0"
    fi
    log "Detected distro: $DISTRO_ID $DISTRO_VERSION"
}

install_dependencies() {
    local deps=(curl ca-certificates)

    case "$DISTRO_ID" in
        ubuntu|debian)
            log "Installing dependencies via apt..."
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${deps[@]}" >/dev/null
            ;;
        rhel|centos|rocky|almalinux|fedora)
            log "Installing dependencies via dnf/yum..."
            if command -v dnf &>/dev/null; then
                dnf install -y -q "${deps[@]}"
            else
                yum install -y -q "${deps[@]}"
            fi
            ;;
        *)
            log "WARNING: Unknown distro '$DISTRO_ID'; skipping dependency install."
            log "Ensure curl and ca-certificates are available."
            ;;
    esac
}

check_prereqs() {
    [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root"
    [[ "$(uname -s)" == "Linux" ]] || die "DRAGON_SCALE Agent requires Linux"

    detect_distro
    install_dependencies

    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1-2)
    local major minor
    major=$(echo "$kernel_version" | cut -d. -f1)
    minor=$(echo "$kernel_version" | cut -d. -f2)

    if (( major < 5 || (major == 5 && minor < 8) )); then
        log "WARNING: Kernel $kernel_version detected. eBPF features require 5.8+."
    fi

    log "System: $(uname -srm)"
    log "Kernel: $(uname -r)"
}

install_agent() {
    log "Installing DRAGON_SCALE Agent to $INSTALL_DIR"

    mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"

    local download_url="${DRAGON_SCALE_API_URL%/}/downloads/agent/${DRAGON_SCALE_VERSION}/dragon-scale-agent-$(uname -m)"
    log "Downloading agent binary from $download_url..."
    if ! curl -fsSL -o "$INSTALL_DIR/dragon-scale-agent" "$download_url"; then
        die "Failed to download agent binary. Verify --server URL and network connectivity."
    fi
    chmod 755 "$INSTALL_DIR/dragon-scale-agent"
    log "Agent binary installed at $INSTALL_DIR/dragon-scale-agent"

    cat > "$INSTALL_DIR/config.json" <<EOF
{
  "control_plane_url": "$DRAGON_SCALE_API_URL",
  "auth_token": "$DRAGON_SCALE_AGENT_TOKEN",
  "data_dir": "$DATA_DIR",
  "log_dir": "$LOG_DIR",
  "enable_xdp": true,
  "enable_hids": true,
  "enable_hardening": true,
  "enable_fim": true
}
EOF
    chmod 600 "$INSTALL_DIR/config.json"

    log "Configuration written to $INSTALL_DIR/config.json"
}

create_systemd_service() {
    log "Creating systemd service: $SERVICE_NAME"

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=DRAGON_SCALE Security Agent
Documentation=https://docs.dragon-scale.example.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/dragon-scale-agent
Environment=DRAGON_SCALE_CONFIG=$INSTALL_DIR/config.json
Restart=always
RestartSec=10
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Security hardening for the service itself
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=$DATA_DIR $LOG_DIR /sys/fs/bpf
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    log "Service $SERVICE_NAME started"
}

main() {
    parse_args "$@"

    log "DRAGON_SCALE Agent Installer v${DRAGON_SCALE_VERSION}"
    log "=================================="

    check_prereqs
    install_agent
    create_systemd_service

    log ""
    log "Installation complete."
    log "  Status:  systemctl status $SERVICE_NAME"
    log "  Logs:    journalctl -u $SERVICE_NAME -f"
    log "  Config:  $INSTALL_DIR/config.json"
}

main "$@"
