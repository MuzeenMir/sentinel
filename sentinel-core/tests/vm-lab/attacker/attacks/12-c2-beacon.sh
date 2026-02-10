#!/usr/bin/env bash
# =============================================================================
# 12 — Command & Control (C2) Beaconing Simulation
# Tool: curl (periodic callbacks simulating C2 check-ins)
# SSS should detect: c2_communication via periodicity and off-hours patterns
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "12_c2_beacon"

VULN_PORT="${VULN_APP_PORT:-8888}"
C2_INTERVAL=3         # seconds between beacons (fast for testing)
C2_JITTER=1           # random jitter in seconds
BEACON_COUNT=30       # number of beacon check-ins
C2_URL="http://${TARGET_IP}:${VULN_PORT}"

echo "[*] Simulating C2 beaconing to ${C2_URL}..."
echo "  Interval: ${C2_INTERVAL}s (+/- ${C2_JITTER}s jitter)"
echo "  Beacon count: ${BEACON_COUNT}"

successful_beacons=0
blocked_beacons=0
commands_received=0

for ((i=1; i<=BEACON_COUNT; i++)); do
    # Generate a realistic-looking C2 beacon
    beacon_id=$(head -c 8 /dev/urandom | xxd -p)
    timestamp=$(date -u +%s)
    hostname_fake="WORKSTATION-$(head -c 3 /dev/urandom | xxd -p | tr '[:lower:]' '[:upper:]')"

    # C2 check-in: POST system info, receive "commands"
    http_code=$(curl -s -o /tmp/c2_response.txt -w "%{http_code}" \
        --max-time 5 \
        -X POST "${C2_URL}/api/data" \
        -H "Content-Type: application/json" \
        -H "X-Beacon-ID: ${beacon_id}" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -d "{\"id\":\"${beacon_id}\",\"ts\":${timestamp},\"host\":\"${hostname_fake}\",\"type\":\"checkin\",\"data\":{\"uptime\":$((RANDOM % 86400)),\"user\":\"admin\",\"pid\":$((RANDOM % 65536))}}" \
        2>/dev/null) || http_code="000"

    if [[ "${http_code}" == "000" ]]; then
        blocked_beacons=$((blocked_beacons + 1))
        echo "  [${i}/${BEACON_COUNT}] BLOCKED (connection refused)"
    elif [[ "${http_code}" -ge 200 && "${http_code}" -lt 400 ]]; then
        successful_beacons=$((successful_beacons + 1))
        # Check if we got a "command" back
        response_size=$(wc -c < /tmp/c2_response.txt 2>/dev/null || echo 0)
        if [[ "${response_size}" -gt 10 ]]; then
            commands_received=$((commands_received + 1))
        fi
        echo "  [${i}/${BEACON_COUNT}] Beacon OK (HTTP ${http_code}, response: ${response_size} bytes)"
    else
        blocked_beacons=$((blocked_beacons + 1))
        echo "  [${i}/${BEACON_COUNT}] REJECTED (HTTP ${http_code})"
    fi

    # Add jitter to interval
    jitter=$(( RANDOM % (C2_JITTER * 2 + 1) - C2_JITTER ))
    sleep_time=$(( C2_INTERVAL + jitter ))
    [[ ${sleep_time} -lt 1 ]] && sleep_time=1
    sleep "${sleep_time}"

    # If more than half are blocked, the C2 channel is compromised
    if [[ ${blocked_beacons} -gt $((BEACON_COUNT / 3)) && ${i} -gt 10 ]]; then
        echo "  [!] C2 channel appears compromised. Stopping early."
        break
    fi
done

echo ""
echo "[*] C2 beacon results: ${successful_beacons} successful, ${blocked_beacons} blocked, ${commands_received} commands received."

# ---------------------------------------------------------------------------
# Determine result
# ---------------------------------------------------------------------------
if [[ ${blocked_beacons} -gt $((successful_beacons)) ]]; then
    evidence="C2 beaconing blocked: ${blocked_beacons}/${BEACON_COUNT} beacons refused. Channel disrupted by SSS."
    record_result "false" "${evidence}" "Successful: ${successful_beacons}, Blocked: ${blocked_beacons}"
elif [[ ${successful_beacons} -gt 0 ]]; then
    evidence="C2 beaconing succeeded: ${successful_beacons}/${BEACON_COUNT} check-ins completed, ${commands_received} commands received."
    record_result "true" "${evidence}" "Beacon interval: ${C2_INTERVAL}s, Jitter: ${C2_JITTER}s"
else
    evidence="All C2 beacons were blocked."
    record_result "false" "${evidence}" ""
fi

rm -f /tmp/c2_response.txt
