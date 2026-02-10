#!/usr/bin/env bash
# =============================================================================
# run-protected.sh — Orchestrate the PROTECTED (SSS active) attack run.
#
# This script:
#   1. Connects to the target to deploy/start SSS
#   2. Waits for all SSS services to be healthy
#   3. Runs the full attack suite from Kali
#   4. Collects SSS detection logs alongside attack results
#
# Run on the KALI VM.
# Usage:  sudo ./run-protected.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ATTACKER_DIR="${LAB_ROOT}/attacker"
CONFIG_FILE="${ATTACKER_DIR}/lab.conf"

log()  { echo -e "\033[1;34m[PROTECTED]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
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
echo " SSS Lab — PROTECTED Run (SSS Active)"
echo "================================================================"
echo " Target:  ${TARGET_IP}"
echo " Purpose: Measure attack success WITH SSS protecting the target"
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# 1. Deploy SSS on the target
# ---------------------------------------------------------------------------
log "Step 1: Deploying SSS on target ${TARGET_IP}..."

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

    # Start SSS Docker stack
    log "Starting SSS Docker stack..."
    ssh_cmd "cd ${SSS_ROOT_ON_TARGET} && docker compose up -d" || true

    ok "SSS deployment initiated."
else
    echo ""
    echo "================================================================"
    echo " WARNING: Cannot SSH to target at ${TARGET_SSH_USER}@${TARGET_IP}"
    echo ""
    echo " Please manually run on the Ubuntu VM:"
    echo "   sudo ./tests/vm-lab/target/deploy-sss.sh"
    echo ""
    echo " Then press ENTER to continue..."
    echo "================================================================"
    read -r
fi

# ---------------------------------------------------------------------------
# 2. Wait for SSS to be healthy
# ---------------------------------------------------------------------------
log "Step 2: Waiting 60s for SSS services to become healthy..."
sleep 30

# Check key SSS endpoints
for endpoint in "8080/health" "5001/health" "5003/health"; do
    port_path="${endpoint}"
    if curl -sf "http://${TARGET_IP}:${port_path}" >/dev/null 2>&1; then
        ok "SSS endpoint :${port_path} is responding."
    else
        warn "SSS endpoint :${port_path} not yet responding."
    fi
done

# Give remaining services more time
sleep 30
ok "Wait complete. Proceeding with attacks."

# ---------------------------------------------------------------------------
# 3. Verify SSS Admin Console
# ---------------------------------------------------------------------------
log "Step 3: Verifying SSS Admin Console..."
if curl -sf "http://${TARGET_IP}:3000/" >/dev/null 2>&1; then
    ok "Admin Console accessible at http://${TARGET_IP}:3000"
else
    warn "Admin Console not accessible (non-critical for test)."
fi

# ---------------------------------------------------------------------------
# 4. Record SSS state before attacks
# ---------------------------------------------------------------------------
log "Step 4: Recording pre-attack SSS state..."
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PRE_STATE_DIR="${ATTACKER_DIR}/results/protected_${TIMESTAMP}_sss_state"
mkdir -p "${PRE_STATE_DIR}"

# Capture current alerts
curl -s "http://${TARGET_IP}:8080/api/v1/alerts" \
    > "${PRE_STATE_DIR}/pre_alerts.json" 2>/dev/null || echo '[]' > "${PRE_STATE_DIR}/pre_alerts.json"

# Capture current policies
curl -s "http://${TARGET_IP}:8080/api/v1/policies" \
    > "${PRE_STATE_DIR}/pre_policies.json" 2>/dev/null || echo '[]' > "${PRE_STATE_DIR}/pre_policies.json"

ok "Pre-attack SSS state captured."

# ---------------------------------------------------------------------------
# 5. Run the full attack suite
# ---------------------------------------------------------------------------
log "Step 5: Launching attack suite against SSS-protected target..."
chmod +x "${ATTACKER_DIR}/run-all-attacks.sh"
sudo bash "${ATTACKER_DIR}/run-all-attacks.sh" "protected"

# ---------------------------------------------------------------------------
# 6. Collect post-attack SSS state
# ---------------------------------------------------------------------------
log "Step 6: Collecting post-attack SSS detection data..."
sleep 10  # Let SSS finish processing

# Capture alerts after attacks
curl -s "http://${TARGET_IP}:8080/api/v1/alerts" \
    > "${PRE_STATE_DIR}/post_alerts.json" 2>/dev/null || echo '[]' > "${PRE_STATE_DIR}/post_alerts.json"

# Capture policies after attacks
curl -s "http://${TARGET_IP}:8080/api/v1/policies" \
    > "${PRE_STATE_DIR}/post_policies.json" 2>/dev/null || echo '[]' > "${PRE_STATE_DIR}/post_policies.json"

# Capture recent detections
curl -s "http://${TARGET_IP}:8080/api/v1/threats" \
    > "${PRE_STATE_DIR}/detections.json" 2>/dev/null || echo '[]' > "${PRE_STATE_DIR}/detections.json"

# Collect Docker logs from key SSS services
if ssh_cmd "echo connected" 2>/dev/null; then
    log "Pulling SSS service logs..."
    for svc in ai-engine data-collector policy-orchestrator alert-service drl-engine; do
        ssh_cmd "cd ${SSS_ROOT_ON_TARGET} && docker compose logs --tail=200 ${svc} 2>/dev/null" \
            > "${PRE_STATE_DIR}/log_${svc}.txt" 2>/dev/null || true
    done
    ok "SSS logs collected."
fi

ok "Post-attack SSS state captured at ${PRE_STATE_DIR}"

# ---------------------------------------------------------------------------
# 7. Done
# ---------------------------------------------------------------------------
echo ""
log "================================================================"
log " PROTECTED run complete."
log " Attack results: ${ATTACKER_DIR}/results/protected_*"
log " SSS state/logs: ${PRE_STATE_DIR}"
log ""
log " Next: Run comparison/generate-report.py to build the diff report."
log "================================================================"
