#!/usr/bin/env bash
# =============================================================================
# common.sh — Shared helpers for all attack scripts.
# Source this at the top of every attack script.
# =============================================================================

ATTACKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKER_DIR="$(cd "${ATTACKS_DIR}/.." && pwd)"
CONFIG_FILE="${ATTACKER_DIR}/lab.conf"

# Load config
if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
else
    echo "[ERROR] lab.conf not found. Run setup-attacker.sh first."
    exit 1
fi

# Override from env/args
TARGET_IP="${TARGET_IP:-${1:-}}"
RESULTS_DIR="${RESULTS_DIR:-${ATTACKER_DIR}/results}"
ATTACK_TIMEOUT="${ATTACK_TIMEOUT:-120}"

if [[ -z "${TARGET_IP}" ]]; then
    echo "[ERROR] TARGET_IP not set. Run setup-attacker.sh <IP> first."
    exit 1
fi

mkdir -p "${RESULTS_DIR}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_ATTACK_NAME=""
_ATTACK_START=""

attack_start() {
    _ATTACK_NAME="$1"
    _ATTACK_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "================================================================"
    echo " ATTACK: ${_ATTACK_NAME}"
    echo " TARGET: ${TARGET_IP}"
    echo " START:  ${_ATTACK_START}"
    echo "================================================================"
}

# ---------------------------------------------------------------------------
# Result recording — writes structured JSON
# ---------------------------------------------------------------------------
record_result() {
    local success="$1"        # true / false
    local evidence="$2"       # short evidence string
    local details="${3:-}"    # optional longer details

    local end_time
    end_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    local safe_name
    safe_name="$(echo "${_ATTACK_NAME}" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')"

    local outfile="${RESULTS_DIR}/${safe_name}.json"

    # Escape JSON strings
    local esc_evidence
    esc_evidence="$(echo "${evidence}" | head -c 2000 | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')"
    local esc_details
    esc_details="$(echo "${details}" | head -c 5000 | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')"

    cat > "${outfile}" <<JSONEOF
{
  "attack_name": "${_ATTACK_NAME}",
  "target_ip": "${TARGET_IP}",
  "start_time": "${_ATTACK_START}",
  "end_time": "${end_time}",
  "success": ${success},
  "evidence": ${esc_evidence},
  "details": ${esc_details}
}
JSONEOF

    if [[ "${success}" == "true" ]]; then
        echo -e "\033[1;32m[RESULT] ATTACK SUCCEEDED\033[0m — ${_ATTACK_NAME}"
    else
        echo -e "\033[1;31m[RESULT] ATTACK FAILED/BLOCKED\033[0m — ${_ATTACK_NAME}"
    fi
    echo "  Result saved to: ${outfile}"
}
