#!/usr/bin/env bash
# =============================================================================
# run-all-attacks.sh — Execute all attack scripts sequentially, collect results.
#
# Run on the KALI VM.
# Usage:  chmod +x run-all-attacks.sh && sudo ./run-all-attacks.sh [RUN_LABEL]
#
# RUN_LABEL is used to tag the result set (e.g. "baseline" or "protected").
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="${SCRIPT_DIR}/attacks"
CONFIG_FILE="${SCRIPT_DIR}/lab.conf"
RUN_LABEL="${1:-manual}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# Load config
if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "[ERROR] lab.conf not found. Run setup-attacker.sh first."
    exit 1
fi
# shellcheck source=/dev/null
source "${CONFIG_FILE}"

RESULTS_DIR="${RESULTS_DIR:-${SCRIPT_DIR}/results}"
RUN_DIR="${RESULTS_DIR}/${RUN_LABEL}_${TIMESTAMP}"
mkdir -p "${RUN_DIR}"

# Override results dir so attack scripts write here
export RESULTS_DIR="${RUN_DIR}"

log()  { echo -e "\033[1;31m[RED-TEAM]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo " SSS Lab — Full Attack Suite"
echo "================================================================"
echo " Target:     ${TARGET_IP}"
echo " Run label:  ${RUN_LABEL}"
echo " Timestamp:  ${TIMESTAMP}"
echo " Results:    ${RUN_DIR}"
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# Pre-flight: verify target is reachable
# ---------------------------------------------------------------------------
log "Pre-flight check: verifying target connectivity..."
if ! ping -c 1 -W 3 "${TARGET_IP}" &>/dev/null; then
    if ! timeout 5 bash -c "echo >/dev/tcp/${TARGET_IP}/22" 2>/dev/null; then
        echo "[ERROR] Target ${TARGET_IP} is not reachable. Aborting."
        exit 1
    fi
fi
ok "Target is reachable."

# ---------------------------------------------------------------------------
# Run attacks in order
# ---------------------------------------------------------------------------
ATTACKS=(
    "01-recon-portscan.sh"
    "02-recon-vuln-scan.sh"
    "03-brute-ssh.sh"
    "04-brute-web-login.sh"
    "05-dos-syn-flood.sh"
    "06-dos-slowloris.sh"
    "07-sqli-attack.sh"
    "08-xss-attack.sh"
    "09-data-exfil-dns.sh"
    "10-data-exfil-http.sh"
    "11-arp-spoof.sh"
    "12-c2-beacon.sh"
)

TOTAL=${#ATTACKS[@]}
PASSED=0
FAILED=0
ERRORS=0

for ((i=0; i<TOTAL; i++)); do
    attack="${ATTACKS[$i]}"
    attack_path="${ATTACKS_DIR}/${attack}"
    num=$((i + 1))

    echo ""
    echo "================================================================"
    echo " [${num}/${TOTAL}] Running: ${attack}"
    echo "================================================================"

    if [[ ! -x "${attack_path}" ]]; then
        chmod +x "${attack_path}" 2>/dev/null || true
    fi

    # Run the attack script; capture exit code
    start_time=$(date +%s)
    if bash "${attack_path}"; then
        exit_code=0
    else
        exit_code=$?
    fi
    end_time=$(date +%s)
    duration=$((end_time - start_time))

    echo "  Duration: ${duration}s | Exit code: ${exit_code}"

    # Count results by reading the JSON output
    attack_name=$(basename "${attack}" .sh | tr '-' '_')
    result_file=$(find "${RUN_DIR}" -name "*.json" -newer /tmp/.attack_marker 2>/dev/null | tail -1)
    touch /tmp/.attack_marker

    if [[ -n "${result_file}" ]] && [[ -f "${result_file}" ]]; then
        success=$(python3 -c "import json; print(json.load(open('${result_file}'))['success'])" 2>/dev/null || echo "unknown")
        if [[ "${success}" == "True" ]]; then
            PASSED=$((PASSED + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    else
        ERRORS=$((ERRORS + 1))
    fi

    # Brief pause between attacks to let SSS process events
    echo "  Pausing 5s before next attack..."
    sleep 5
done

# ---------------------------------------------------------------------------
# Generate summary JSON
# ---------------------------------------------------------------------------
SUMMARY_FILE="${RUN_DIR}/_summary.json"

cat > "${SUMMARY_FILE}" <<SUMEOF
{
  "run_label": "${RUN_LABEL}",
  "timestamp": "${TIMESTAMP}",
  "target_ip": "${TARGET_IP}",
  "total_attacks": ${TOTAL},
  "attacks_succeeded": ${PASSED},
  "attacks_failed_or_blocked": ${FAILED},
  "errors": ${ERRORS},
  "results_directory": "${RUN_DIR}"
}
SUMEOF

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo " ATTACK SUITE COMPLETE"
echo "================================================================"
echo " Run label:            ${RUN_LABEL}"
echo " Total attacks:        ${TOTAL}"
echo " Attacks succeeded:    ${PASSED}"
echo " Attacks blocked:      ${FAILED}"
echo " Errors:               ${ERRORS}"
echo " Results saved to:     ${RUN_DIR}"
echo "================================================================"
echo ""

if [[ "${RUN_LABEL}" == "baseline" ]]; then
    echo " Expected: Most/all attacks should SUCCEED (no protection)."
elif [[ "${RUN_LABEL}" == "protected" ]]; then
    echo " Expected: Most/all attacks should FAIL (SSS active)."
fi

rm -f /tmp/.attack_marker
