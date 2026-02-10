#!/usr/bin/env bash
# =============================================================================
# 02 — Reconnaissance: NSE Vulnerability Scan
# Tool: nmap (scripting engine)
# SSS should detect: aggressive scanning pattern + anomalous probes
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "02_recon_vuln_scan"

OUTFILE="/tmp/nmap_vuln_scan.xml"

echo "[*] Running NSE vulnerability scan on ${TARGET_IP}..."
nmap_output=$(timeout "${ATTACK_TIMEOUT}" \
    nmap -sV --script=vuln,exploit \
    -p 22,80,8888,3000,5000-5010,8080 \
    -oX "${OUTFILE}" \
    "${TARGET_IP}" 2>&1) || true

# Count vulnerability findings
vulns_found=$(echo "${nmap_output}" | grep -ciE "VULNERABLE|CVE-|exploit" || true)

if [[ "${vulns_found}" -gt 0 ]]; then
    evidence="Found ${vulns_found} vulnerability indication(s). $(echo "${nmap_output}" | grep -iE 'VULNERABLE|CVE-' | head -5)"
    record_result "true" "${evidence}" "${nmap_output}"
else
    # Even partial results count as success for recon
    port_info=$(echo "${nmap_output}" | grep -c "open" || true)
    if [[ "${port_info}" -gt 0 ]]; then
        evidence="No vulns found but gathered service info on ${port_info} ports."
        record_result "true" "${evidence}" "${nmap_output}"
    else
        evidence="Scan was blocked or returned no results."
        record_result "false" "${evidence}" "${nmap_output}"
    fi
fi
