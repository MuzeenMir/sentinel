#!/usr/bin/env bash
# SENTINEL Agent Installer
# Usage: curl -sSL https://sentinel.example.com/install.sh | bash -s -- --token <AGENT_TOKEN> --server <API_URL> --sha256 <EXPECTED_SHA256>
set -euo pipefail

SENTINEL_VERSION="${SENTINEL_VERSION:-latest}"
SENTINEL_API_URL=""
SENTINEL_AGENT_TOKEN=""
SENTINEL_AGENT_SHA256="${SENTINEL_AGENT_SHA256:-}"
SENTINEL_COSIGN_PUBKEY="${SENTINEL_COSIGN_PUBKEY:-}"
INSTALL_DIR="/opt/sentinel-agent"
DATA_DIR="/var/lib/sentinel"
LOG_DIR="/var/log/sentinel"
SERVICE_NAME="sentinel-agent"

log() { echo "[sentinel-install] $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --token)   SENTINEL_AGENT_TOKEN="$2"; shift 2 ;;
            --server)  SENTINEL_API_URL="$2"; shift 2 ;;
            --version) SENTINEL_VERSION="$2"; shift 2 ;;
            --sha256)  SENTINEL_AGENT_SHA256="$2"; shift 2 ;;
            --cosign-pubkey) SENTINEL_COSIGN_PUBKEY="$2"; shift 2 ;;
            *)         die "Unknown option: $1" ;;
        esac
    done

    [[ -n "$SENTINEL_AGENT_TOKEN" ]] || die "--token is required"
    [[ -n "$SENTINEL_API_URL" ]] || die "--server is required"
    [[ "$SENTINEL_API_URL" == https://* ]] || die "--server must use https://"
    [[ -n "$SENTINEL_AGENT_SHA256" ]] || die "--sha256 or SENTINEL_AGENT_SHA256 is required"
    [[ "$SENTINEL_AGENT_SHA256" =~ ^[A-Fa-f0-9]{64}$ ]] || die "agent SHA-256 must be 64 hex characters"
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
    local deps=(curl ca-certificates coreutils python3)

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
    [[ "$(uname -s)" == "Linux" ]] || die "SENTINEL Agent requires Linux"

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
    log "Installing SENTINEL Agent to $INSTALL_DIR"

    mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"

    local download_url="${SENTINEL_API_URL%/}/downloads/agent/${SENTINEL_VERSION}/sentinel-agent-$(uname -m)"
    local tmp_binary
    tmp_binary="$(mktemp)"
    cleanup_agent_download() {
        rm -f "$tmp_binary" "$tmp_binary.sig"
    }
    trap cleanup_agent_download EXIT

    log "Downloading agent binary from $download_url..."
    if ! curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp_binary" "$download_url"; then
        die "Failed to download agent binary. Verify --server URL and network connectivity."
    fi

    printf '%s  %s\n' "$SENTINEL_AGENT_SHA256" "$tmp_binary" | sha256sum -c - >/dev/null ||
        die "Agent binary checksum verification failed"

    if [[ -n "$SENTINEL_COSIGN_PUBKEY" ]]; then
        command -v cosign >/dev/null 2>&1 || die "cosign is required when --cosign-pubkey is set"
        curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp_binary.sig" "${download_url}.sig" ||
            die "Failed to download agent signature"
        cosign verify-blob --key "$SENTINEL_COSIGN_PUBKEY" --signature "$tmp_binary.sig" "$tmp_binary" >/dev/null ||
            die "Agent binary signature verification failed"
    fi

    install -m 755 "$tmp_binary" "$INSTALL_DIR/sentinel-agent"
    cleanup_agent_download
    trap - EXIT
    log "Agent binary installed at $INSTALL_DIR/sentinel-agent"

    SENTINEL_API_URL="$SENTINEL_API_URL" \
    SENTINEL_AGENT_TOKEN="$SENTINEL_AGENT_TOKEN" \
    DATA_DIR="$DATA_DIR" \
    LOG_DIR="$LOG_DIR" \
    python3 - "$INSTALL_DIR/config.json" <<'PY'
import json
import os
import sys

config = {
    "control_plane_url": os.environ["SENTINEL_API_URL"],
    "auth_token": os.environ["SENTINEL_AGENT_TOKEN"],
    "data_dir": os.environ["DATA_DIR"],
    "log_dir": os.environ["LOG_DIR"],
    "enable_xdp": True,
    "enable_hids": True,
    "enable_hardening": True,
    "enable_fim": True,
}

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
    chmod 600 "$INSTALL_DIR/config.json"

    log "Configuration written to $INSTALL_DIR/config.json"
}

create_systemd_service() {
    log "Creating systemd service: $SERVICE_NAME"

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SENTINEL Security Agent
Documentation=https://docs.sentinel.example.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/sentinel-agent
Environment=SENTINEL_CONFIG=$INSTALL_DIR/config.json
Restart=always
RestartSec=10
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Security hardening for the service itself
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_RESOURCE CAP_SYS_ADMIN
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_RESOURCE CAP_SYS_ADMIN
ProtectSystem=strict
ReadWritePaths=$DATA_DIR $LOG_DIR /sys/fs/bpf
ProtectHome=true
PrivateTmp=true

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

    log "SENTINEL Agent Installer v${SENTINEL_VERSION}"
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
