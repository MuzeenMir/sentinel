#!/usr/bin/env bash
# =============================================================================
# setup-attacker.sh — Verify / install attack tools on the Kali VM.
#
# Run on the KALI VM.
# Usage:  chmod +x setup-attacker.sh && sudo ./setup-attacker.sh <TARGET_IP>
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/lab.conf"

log()  { echo -e "\033[1;31m[RED-TEAM]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; exit 1; }

# ---------------------------------------------------------------------------
# 1. Accept and persist target IP
# ---------------------------------------------------------------------------
TARGET_IP="${1:-}"
if [[ -z "${TARGET_IP}" ]]; then
    echo "Usage: $0 <TARGET_IP>"
    echo "  Example: $0 10.0.2.15"
    exit 1
fi

cat > "${CONFIG_FILE}" <<EOF
# SSS Lab Attacker Configuration — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
TARGET_IP=${TARGET_IP}
VULN_APP_PORT=8888
SSH_PORT=22
RESULTS_DIR=${SCRIPT_DIR}/results
ATTACK_TIMEOUT=120
EOF

ok "Configuration written to ${CONFIG_FILE}"
echo "  TARGET_IP=${TARGET_IP}"

# ---------------------------------------------------------------------------
# 2. Verify / install required tools
# ---------------------------------------------------------------------------
REQUIRED_TOOLS=(
    nmap
    hydra
    hping3
    sqlmap
    curl
    jq
    dnsutils    # provides dig
    python3
    arpspoof    # part of dsniff
    ettercap-text-only
)

PACKAGES_TO_INSTALL=()

log "Checking required attack tools..."
for tool in "${REQUIRED_TOOLS[@]}"; do
    bin_name="${tool}"
    pkg_name="${tool}"

    # Map tool names to their actual binaries / packages
    case "${tool}" in
        dnsutils)    bin_name="dig" ;;
        ettercap-text-only) bin_name="ettercap" ;;
        arpspoof)    pkg_name="dsniff"; bin_name="arpspoof" ;;
    esac

    if command -v "${bin_name}" &>/dev/null; then
        ok "  ${bin_name} — installed"
    else
        echo "  MISSING: ${bin_name} (package: ${pkg_name})"
        PACKAGES_TO_INSTALL+=("${pkg_name}")
    fi
done

# Install slowloris via pip if missing
if ! command -v slowloris &>/dev/null && ! python3 -c "import slowloris" 2>/dev/null; then
    echo "  MISSING: slowloris"
    INSTALL_SLOWLORIS=true
else
    ok "  slowloris — installed"
    INSTALL_SLOWLORIS=false
fi

if [[ ${#PACKAGES_TO_INSTALL[@]} -gt 0 ]]; then
    log "Installing missing packages: ${PACKAGES_TO_INSTALL[*]}"
    apt-get update -qq
    apt-get install -y -qq "${PACKAGES_TO_INSTALL[@]}" || true
fi

if $INSTALL_SLOWLORIS; then
    log "Installing slowloris via pip..."
    pip3 install slowloris 2>/dev/null || pip3 install --break-system-packages slowloris 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 3. Create results directory
# ---------------------------------------------------------------------------
RESULTS_DIR="${SCRIPT_DIR}/results"
mkdir -p "${RESULTS_DIR}"
ok "Results directory: ${RESULTS_DIR}"

# ---------------------------------------------------------------------------
# 4. Verify connectivity to target
# ---------------------------------------------------------------------------
log "Verifying connectivity to ${TARGET_IP}..."

if ping -c 2 -W 3 "${TARGET_IP}" &>/dev/null; then
    ok "Target ${TARGET_IP} is reachable (ICMP)."
else
    echo "  WARNING: ICMP ping failed (may be filtered). Trying TCP..."
fi

# Try a TCP connection to SSH port
if timeout 5 bash -c "echo >/dev/tcp/${TARGET_IP}/22" 2>/dev/null; then
    ok "Target SSH port (22) is open."
elif timeout 5 bash -c "echo >/dev/tcp/${TARGET_IP}/8888" 2>/dev/null; then
    ok "Target VulnApp port (8888) is open."
else
    echo "  WARNING: Could not reach target on standard ports."
    echo "  Ensure the VMs are on the same NAT Network and the target is running."
fi

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------
echo ""
log "============================================="
log " Kali Attacker Setup Complete"
log "============================================="
log " Target IP:     ${TARGET_IP}"
log " Config file:   ${CONFIG_FILE}"
log " Results dir:   ${RESULTS_DIR}"
log ""
log " Run attacks:"
log "   ./attacks/01-recon-portscan.sh     (individual)"
log "   ./run-all-attacks.sh               (full suite)"
log "============================================="
