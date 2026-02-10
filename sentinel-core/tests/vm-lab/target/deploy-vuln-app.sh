#!/usr/bin/env bash
# =============================================================================
# deploy-vuln-app.sh — Build and run the intentionally vulnerable web app.
#
# Run on the UBUNTU VM.
# Usage:  chmod +x deploy-vuln-app.sh && ./deploy-vuln-app.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULN_APP_DIR="${SCRIPT_DIR}/vuln-app"
CONTAINER_NAME="vuln-app"
IMAGE_NAME="sss-lab/vuln-app"
PORT="${VULN_APP_PORT:-8888}"

log()  { echo -e "\033[1;34m[VULN-APP]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; exit 1; }

# Stop existing container if running
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    log "Stopping existing '${CONTAINER_NAME}' container..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1
fi

# Build the image
log "Building vulnerable web app image..."
docker build -t "${IMAGE_NAME}" "${VULN_APP_DIR}"
ok "Image built: ${IMAGE_NAME}"

# Run the container
log "Starting vulnerable web app on port ${PORT}..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    --restart unless-stopped \
    -p "${PORT}:8888" \
    -e VULN_APP_PORT=8888 \
    "${IMAGE_NAME}"

# Wait for it to be ready
log "Waiting for health check..."
for i in $(seq 1 15); do
    if curl -sf "http://localhost:${PORT}/health" >/dev/null 2>&1; then
        ok "VulnApp is running at http://0.0.0.0:${PORT}"
        echo ""
        echo "  Endpoints:"
        echo "    GET  /           — Home page"
        echo "    GET  /login      — Login form (brute-forceable)"
        echo "    POST /login      — Login submit"
        echo "    GET  /search?q=  — Product search (SQL injectable)"
        echo "    GET  /comment?text= — Comment (reflected XSS)"
        echo "    GET  /api/data   — Sensitive data (no auth)"
        echo "    GET  /health     — Health check"
        echo ""
        exit 0
    fi
    sleep 1
done

fail "VulnApp failed to start within 15 seconds. Check: docker logs ${CONTAINER_NAME}"
