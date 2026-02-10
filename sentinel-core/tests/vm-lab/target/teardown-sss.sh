#!/usr/bin/env bash
# =============================================================================
# teardown-sss.sh — Stop SSS and clean up all firewall rules it created.
#
# Run on the UBUNTU VM.
# Usage:  chmod +x teardown-sss.sh && ./teardown-sss.sh [SSS_ROOT]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${1:-}" ]]; then
    SSS_ROOT="$1"
elif [[ -d "/opt/sentinel/sentinel-core" ]]; then
    SSS_ROOT="/opt/sentinel/sentinel-core"
elif [[ -f "${SCRIPT_DIR}/../../../docker-compose.yml" ]]; then
    SSS_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
else
    echo "Usage: $0 [SSS_ROOT]"
    exit 1
fi

log()  { echo -e "\033[1;34m[SSS-TEARDOWN]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }

# ---------------------------------------------------------------------------
# 1. Stop Docker Compose stack
# ---------------------------------------------------------------------------
if [[ -f "${SSS_ROOT}/docker-compose.yml" ]]; then
    log "Stopping SSS Docker stack..."
    cd "${SSS_ROOT}"
    docker compose down --remove-orphans 2>/dev/null || true
    ok "Docker stack stopped."
else
    warn "docker-compose.yml not found at ${SSS_ROOT}. Skipping."
fi

# ---------------------------------------------------------------------------
# 2. Flush SENTINEL iptables chains
# ---------------------------------------------------------------------------
log "Flushing SENTINEL iptables rules..."

flush_sentinel_chain() {
    local chain="$1"
    local parent="$2"

    # Remove jump rules from parent chain
    while iptables -D "${parent}" -j "${chain}" 2>/dev/null; do :; done

    # Flush and delete the chain
    if iptables -L "${chain}" -n &>/dev/null; then
        iptables -F "${chain}" 2>/dev/null || true
        iptables -X "${chain}" 2>/dev/null || true
        ok "Removed iptables chain: ${chain}"
    fi
}

# The SSS iptables adapter creates a SENTINEL chain
flush_sentinel_chain "SENTINEL" "INPUT"
flush_sentinel_chain "SENTINEL" "OUTPUT"
flush_sentinel_chain "SENTINEL" "FORWARD"

# Also clean up any rules with SENTINEL comments
for chain in INPUT OUTPUT FORWARD; do
    # List rules with line numbers, find SENTINEL ones, delete in reverse order
    iptables -L "${chain}" -n --line-numbers 2>/dev/null \
        | grep -i "SENTINEL" \
        | awk '{print $1}' \
        | sort -rn \
        | while read -r num; do
            iptables -D "${chain}" "${num}" 2>/dev/null || true
        done
done

ok "iptables SENTINEL rules flushed."

# ---------------------------------------------------------------------------
# 3. Reset any rate limiting rules added by SSS
# ---------------------------------------------------------------------------
log "Cleaning up rate limiting rules..."

# Remove any hashlimit rules referencing sentinel
iptables -L -n --line-numbers 2>/dev/null \
    | grep -i "sentinel\|hashlimit" \
    | awk '{print $1}' \
    | sort -rn \
    | while read -r num; do
        iptables -D INPUT "${num}" 2>/dev/null || true
    done

ok "Rate limiting rules cleaned."

# ---------------------------------------------------------------------------
# 4. Verify clean state
# ---------------------------------------------------------------------------
log "Current iptables rules:"
iptables -L -n --line-numbers 2>/dev/null || true

echo ""
log "============================================="
log " SSS teardown complete."
log " The host is now UNPROTECTED (baseline state)."
log "============================================="
