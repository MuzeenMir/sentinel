#!/usr/bin/env bash
# =============================================================================
# 01 — Reconnaissance: SYN Port Scan + OS Fingerprinting
# Tool: nmap
# SSS should detect: port_scan pattern via behavioral features
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "01_recon_portscan"

OUTFILE="/tmp/nmap_syn_scan.xml"

echo "[*] Running SYN scan with OS detection on ${TARGET_IP}..."
nmap_output=$(timeout "${ATTACK_TIMEOUT}" \
    nmap -sS -sV -O -T4 \
    --top-ports 1000 \
    -oX "${OUTFILE}" \
    "${TARGET_IP}" 2>&1) || true

# Determine success: did we find open ports?
open_ports=$(echo "${nmap_output}" | grep -c "open" || true)

if [[ "${open_ports}" -gt 0 ]]; then
    evidence="Found ${open_ports} open port indication(s). $(echo "${nmap_output}" | grep "open" | head -10)"
    record_result "true" "${evidence}" "${nmap_output}"
else
    evidence="No open ports found or scan was blocked."
    record_result "false" "${evidence}" "${nmap_output}"
fi
