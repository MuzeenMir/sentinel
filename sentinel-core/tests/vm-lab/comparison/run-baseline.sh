#!/usr/bin/env bash
# =============================================================================
# run-baseline.sh — Orchestrate the BASELINE (unprotected) attack run.
#
# This script:
#   1. Connects to the target to tear down SSS (if running)
#   2. Runs the full attack suite from Kali
#   3. Collects results into results/baseline/
#
# Run on the KALI VM.
# Usage:  sudo ./run-baseline.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ATTACKER_DIR="${LAB_ROOT}/attacker"
CONFIG_FILE="${ATTACKER_DIR}/lab.conf"

log()  { echo -e "\033[1;33m[BASELINE]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; exit 1; }

# Load config
if [[ ! -f "${CONFIG_FILE}" ]]; then
    fail "lab.conf not found. Run attacker/setup-attacker.sh first."
fi
# shellcheck source=/dev/null
source "${CONFIG_FILE}"

TARGET_SSH_USER="${TARGET_SSH_USER:-sentinel}"
TARGET_SSH_KEY="${TARGET_SSH_KEY:-}"
SSS_ROOT_ON_TARGET="${SSS_ROOT_ON_TARGET:-/opt/sentinel/sentinel-core}"

echo ""
echo "================================================================"
echo " SSS Lab — BASELINE Run (No Protection)"
echo "================================================================"
echo " Target:  ${TARGET_IP}"
echo " Purpose: Measure attack success WITHOUT SSS"
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# 1. Tear down SSS on the target (if accessible via SSH)
# ---------------------------------------------------------------------------
log "Step 1: Tearing down SSS on target ${TARGET_IP}..."

ssh_cmd() {
    local cmd="$1"
    if [[ -n "${TARGET_SSH_KEY}" ]]; then
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            -i "${TARGET_SSH_KEY}" \
            "${TARGET_SSH_USER}@${TARGET_IP}" "${cmd}"
    else
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            "${TARGET_SSH_USER}@${TARGET_IP}" "${cmd}"
    fi
}

if ssh_cmd "echo connected" 2>/dev/null; then
    ok "SSH connection to target established."

    # Stop SSS Docker stack
    log "Stopping SSS Docker stack..."
    ssh_cmd "cd ${SSS_ROOT_ON_TARGET} && docker compose down --remove-orphans 2>/dev/null || true" || true

    # Flush SENTINEL iptables rules
    log "Flushing SENTINEL iptables rules..."
    ssh_cmd "sudo iptables -F SENTINEL 2>/dev/null; sudo iptables -X SENTINEL 2>/dev/null; true" || true
    ssh_cmd "sudo iptables -D INPUT -j SENTINEL 2>/dev/null; true" || true
    ssh_cmd "sudo iptables -D OUTPUT -j SENTINEL 2>/dev/null; true" || true

    ok "SSS torn down on target."
else
    echo ""
    echo "================================================================"
    echo " WARNING: Cannot SSH to target at ${TARGET_SSH_USER}@${TARGET_IP}"
    echo ""
    echo " Please manually run on the Ubuntu VM:"
    echo "   sudo ./tests/vm-lab/target/teardown-sss.sh"
    echo ""
    echo " Then press ENTER to continue..."
    echo "================================================================"
    read -r
fi

# ---------------------------------------------------------------------------
# 2. Wait for iptables to clear
# ---------------------------------------------------------------------------
log "Step 2: Waiting 15s for firewall rules to clear..."
sleep 15
ok "Ready."

# ---------------------------------------------------------------------------
# 3. Verify target is reachable and VulnApp is running
# ---------------------------------------------------------------------------
log "Step 3: Verifying target services..."

if curl -sf "http://${TARGET_IP}:${VULN_APP_PORT:-8888}/health" >/dev/null 2>&1; then
    ok "VulnApp is accessible on port ${VULN_APP_PORT:-8888}."
else
    echo "  WARNING: VulnApp not accessible. Some attacks may fail."
    echo "  Ensure deploy-vuln-app.sh was run on the target."
fi

# ---------------------------------------------------------------------------
# 4. Run the full attack suite
# ---------------------------------------------------------------------------
log "Step 4: Launching attack suite..."
chmod +x "${ATTACKER_DIR}/run-all-attacks.sh"
sudo bash "${ATTACKER_DIR}/run-all-attacks.sh" "baseline"

# ---------------------------------------------------------------------------
# 5. Done
# ---------------------------------------------------------------------------
echo ""
log "================================================================"
log " BASELINE run complete."
log " Results saved to: ${ATTACKER_DIR}/results/baseline_*"
log ""
log " Next: Deploy SSS on the target, then run ./run-protected.sh"
log "================================================================"
