#!/usr/bin/env bash
# =============================================================================
# setup-target.sh — Prepare the Ubuntu 20.04 LTS VM as the SSS lab target.
#
# Run on the UBUNTU VM as a user with sudo privileges.
# Usage:  chmod +x setup-target.sh && sudo ./setup-target.sh
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/MuzeenMir/sentinel.git"
INSTALL_DIR="/opt/sentinel"
LAB_USER="sentinel"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo -e "\n\033[1;34m[SSS-SETUP]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; exit 1; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "This script must be run as root (use sudo)."
    fi
}

# ---------------------------------------------------------------------------
# 1. System update & base packages
# ---------------------------------------------------------------------------
install_base() {
    log "Updating system packages..."
    apt-get update -qq
    apt-get upgrade -y -qq

    log "Installing base dependencies..."
    apt-get install -y -qq \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        git \
        python3 \
        python3-pip \
        python3-venv \
        jq \
        net-tools \
        iptables \
        tcpdump \
        sqlite3
    ok "Base packages installed."
}

# ---------------------------------------------------------------------------
# 2. Docker Engine + Compose v2
# ---------------------------------------------------------------------------
install_docker() {
    if command -v docker &>/dev/null; then
        ok "Docker already installed: $(docker --version)"
    else
        log "Installing Docker Engine..."
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
          https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
          | tee /etc/apt/sources.list.d/docker.list > /dev/null

        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
        ok "Docker installed: $(docker --version)"
    fi

    # Ensure the Docker service is running
    systemctl enable docker
    systemctl start docker

    # Verify compose v2
    if docker compose version &>/dev/null; then
        ok "Docker Compose v2: $(docker compose version --short)"
    else
        fail "Docker Compose v2 plugin not found."
    fi
}

# ---------------------------------------------------------------------------
# 3. Create lab user
# ---------------------------------------------------------------------------
create_user() {
    if id "${LAB_USER}" &>/dev/null; then
        ok "User '${LAB_USER}' already exists."
    else
        log "Creating user '${LAB_USER}'..."
        useradd -m -s /bin/bash "${LAB_USER}"
        usermod -aG sudo "${LAB_USER}"
        ok "User '${LAB_USER}' created with sudo."
    fi
    usermod -aG docker "${LAB_USER}"
    ok "User '${LAB_USER}' added to docker group."
}

# ---------------------------------------------------------------------------
# 4. Clone the SSS repository
# ---------------------------------------------------------------------------
clone_repo() {
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        log "Repository already cloned at ${INSTALL_DIR}. Pulling latest..."
        cd "${INSTALL_DIR}"
        git pull --ff-only
    else
        log "Cloning SSS repository..."
        git clone "${REPO_URL}" "${INSTALL_DIR}"
    fi
    chown -R "${LAB_USER}:${LAB_USER}" "${INSTALL_DIR}"
    ok "SSS repository ready at ${INSTALL_DIR}."
}

# ---------------------------------------------------------------------------
# 5. Configure firewall (UFW baseline)
# ---------------------------------------------------------------------------
configure_firewall() {
    log "Configuring UFW baseline rules..."
    # Install UFW if not present
    apt-get install -y -qq ufw

    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH so we don't lock ourselves out
    ufw allow 22/tcp comment "SSH"

    # Allow the vulnerable web app
    ufw allow 8888/tcp comment "VulnApp"

    # Allow SSS Admin Console
    ufw allow 3000/tcp comment "SSS Admin Console"

    # Allow HTTP for general web
    ufw allow 80/tcp comment "HTTP"

    # Allow the entire NAT Network subnet (adjust if different)
    # Default VirtualBox NAT Network is 10.0.2.0/24
    # Adjust this to match your actual NAT Network CIDR
    ufw allow from 10.0.2.0/24 comment "NAT Network"

    ufw --force enable
    ok "UFW configured and enabled."
    ufw status verbose
}

# ---------------------------------------------------------------------------
# 6. Verify installation
# ---------------------------------------------------------------------------
verify() {
    log "Verifying installation..."
    local errors=0

    command -v docker   &>/dev/null || { echo "  MISSING: docker";   errors=$((errors+1)); }
    command -v git      &>/dev/null || { echo "  MISSING: git";      errors=$((errors+1)); }
    command -v python3  &>/dev/null || { echo "  MISSING: python3";  errors=$((errors+1)); }
    command -v jq       &>/dev/null || { echo "  MISSING: jq";       errors=$((errors+1)); }
    command -v iptables &>/dev/null || { echo "  MISSING: iptables"; errors=$((errors+1)); }

    [[ -d "${INSTALL_DIR}/sentinel-core" ]] || { echo "  MISSING: ${INSTALL_DIR}/sentinel-core"; errors=$((errors+1)); }

    if [[ $errors -eq 0 ]]; then
        ok "All checks passed."
    else
        fail "${errors} check(s) failed. Review output above."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    require_root
    log "============================================="
    log " SSS Lab Target Setup — Ubuntu 20.04 LTS"
    log "============================================="
    install_base
    install_docker
    create_user
    clone_repo
    configure_firewall
    verify

    echo ""
    log "============================================="
    log " Setup complete."
    log " Next steps:"
    log "   1. Run deploy-vuln-app.sh  to start the vulnerable web app"
    log "   2. Run deploy-sss.sh       to start the Sentinel Security System"
    log "============================================="
}

main "$@"
