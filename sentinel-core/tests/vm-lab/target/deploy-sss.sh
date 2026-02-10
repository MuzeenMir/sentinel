#!/usr/bin/env bash
# =============================================================================
# deploy-sss.sh — Deploy the Sentinel Security System via Docker Compose.
#
# Run on the UBUNTU VM.
# Usage:  chmod +x deploy-sss.sh && ./deploy-sss.sh [SSS_ROOT]
#
# SSS_ROOT defaults to /opt/sentinel/sentinel-core or the repo root if
# this script is inside the repo tree.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Determine SSS root — prefer argument, then /opt/sentinel, then walk up tree
if [[ -n "${1:-}" ]]; then
    SSS_ROOT="$1"
elif [[ -d "/opt/sentinel/sentinel-core" ]]; then
    SSS_ROOT="/opt/sentinel/sentinel-core"
elif [[ -f "${SCRIPT_DIR}/../../../docker-compose.yml" ]]; then
    SSS_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
else
    echo "Usage: $0 [SSS_ROOT]"
    echo "  SSS_ROOT must contain docker-compose.yml"
    exit 1
fi

ENV_FILE="${SSS_ROOT}/sentinelenv"
ENV_EXAMPLE="${SSS_ROOT}/sentinelenv.example"

log()  { echo -e "\033[1;34m[SSS-DEPLOY]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; exit 1; }

# ---------------------------------------------------------------------------
# 1. Validate prerequisites
# ---------------------------------------------------------------------------
log "Validating prerequisites..."
command -v docker >/dev/null 2>&1          || fail "Docker is not installed."
docker compose version >/dev/null 2>&1     || fail "Docker Compose v2 is not available."
[[ -f "${SSS_ROOT}/docker-compose.yml" ]]  || fail "docker-compose.yml not found at ${SSS_ROOT}"
ok "Prerequisites met. SSS_ROOT=${SSS_ROOT}"

# ---------------------------------------------------------------------------
# 2. Create environment file if missing
# ---------------------------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
    log "Creating sentinelenv from example..."
    if [[ -f "${ENV_EXAMPLE}" ]]; then
        cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    else
        # Write minimal env
        cat > "${ENV_FILE}" <<'ENVEOF'
JWT_SECRET_KEY=sss-lab-jwt-secret-$(openssl rand -hex 16)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=SentinelLab2026!
ADMIN_EMAIL=admin@sentinel.local
POSTGRES_PASSWORD=sentinel_lab_password
ENVEOF
    fi
    ok "Environment file created at ${ENV_FILE}"
else
    ok "Environment file already exists."
fi

# Generate a real random JWT secret if the placeholder is still there
if grep -q "your-secret-key" "${ENV_FILE}" 2>/dev/null; then
    JWT=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | base64 | tr -d '/+=' | head -c 64)
    sed -i "s|JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${JWT}|" "${ENV_FILE}"
    ok "JWT secret generated."
fi

# Set a real admin password if the placeholder is still there
if grep -q "your-secure-password" "${ENV_FILE}" 2>/dev/null; then
    sed -i "s|ADMIN_PASSWORD=.*|ADMIN_PASSWORD=SentinelLab2026!|" "${ENV_FILE}"
    ok "Admin password set."
fi

# ---------------------------------------------------------------------------
# 3. Configure firewall adapter for iptables
# ---------------------------------------------------------------------------
export SENTINEL_FIREWALL_TYPE="iptables"
log "Firewall adapter: iptables"

# ---------------------------------------------------------------------------
# 4. Start Docker Compose stack
# ---------------------------------------------------------------------------
cd "${SSS_ROOT}"
log "Pulling latest images and building services..."
docker compose build --quiet 2>/dev/null || docker compose build

log "Starting SSS stack..."
docker compose up -d

# ---------------------------------------------------------------------------
# 5. Wait for critical services to be healthy
# ---------------------------------------------------------------------------
SERVICES=("api-gateway" "auth-service" "ai-engine" "data-collector" "policy-orchestrator" "alert-service")
MAX_WAIT=120
INTERVAL=5
ELAPSED=0

log "Waiting for services to become healthy (timeout: ${MAX_WAIT}s)..."
while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    all_up=true
    for svc in "${SERVICES[@]}"; do
        status=$(docker compose ps --format json 2>/dev/null | jq -r "select(.Service==\"${svc}\") | .State" 2>/dev/null || echo "unknown")
        if [[ "$status" != "running" ]]; then
            all_up=false
            break
        fi
    done
    if $all_up; then
        break
    fi
    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
    echo -n "."
done
echo ""

if [[ $ELAPSED -ge $MAX_WAIT ]]; then
    warn "Timed out waiting for all services. Checking status..."
    docker compose ps
else
    ok "All core services are running."
fi

# ---------------------------------------------------------------------------
# 6. Verify key endpoints
# ---------------------------------------------------------------------------
log "Verifying endpoints..."

# API Gateway
if curl -sf "http://localhost:8080/health" >/dev/null 2>&1; then
    ok "API Gateway: http://localhost:8080"
else
    warn "API Gateway not responding on :8080 (may still be starting)."
fi

# Admin Console
if curl -sf "http://localhost:3000/" >/dev/null 2>&1; then
    ok "Admin Console: http://localhost:3000"
else
    warn "Admin Console not responding on :3000 (may still be starting)."
fi

# Data Collector
if curl -sf "http://localhost:5001/health" >/dev/null 2>&1; then
    ok "Data Collector: http://localhost:5001"
else
    warn "Data Collector not responding on :5001 (may still be starting)."
fi

# ---------------------------------------------------------------------------
# 7. Print summary
# ---------------------------------------------------------------------------
echo ""
log "============================================="
log " SSS Deployment Summary"
log "============================================="
docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Ports}}"
echo ""
log "Admin Console:  http://localhost:3000"
log "API Gateway:    http://localhost:8080"
log "Firewall Mode:  iptables"
log ""
log "SSS is now protecting this host."
log "============================================="
