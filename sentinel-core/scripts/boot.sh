#!/usr/bin/env bash
# SENTINEL stack boot helper
# Usage: ./scripts/boot.sh [--no-ai] [--no-flink] [--core-only]
#
# Stages:
#   1. Infrastructure  (postgres, redis, zookeeper, kafka)
#   2. Core services   (auth-service, api-gateway, data-collector, alert-service,
#                       policy-orchestrator, compliance-engine, xai-service)
#   3. AI/DRL services (ai-engine, drl-engine)      [skip with --no-ai]
#   4. eBPF services   (hids-agent, xdp-collector, hardening-service)
#   5. Flink jobs      (anomaly, feature-extraction, drl-feed) [skip with --no-flink]
#   6. Observability   (prometheus, grafana, elasticsearch, kibana)
#   7. Admin console   (frontend)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

NO_AI=false
NO_FLINK=false
CORE_ONLY=false

for arg in "$@"; do
  case $arg in
    --no-ai)    NO_AI=true ;;
    --no-flink) NO_FLINK=true ;;
    --core-only)
      NO_AI=true
      NO_FLINK=true
      CORE_ONLY=true
      ;;
  esac
done

cd "$ROOT"

# ── Colour helpers ─────────────────────────────────────────────────────────
CYAN='\033[36m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

info "SENTINEL Stack Boot — $(date)"
info "Root: $ROOT"

# ── .env check ─────────────────────────────────────────────────────────────
if [ ! -f "$ROOT/.env" ]; then
  error ".env not found. Copy .env.example to .env and configure secrets."
  exit 1
fi

ok ".env found"

# ── Stage 1: Infrastructure ────────────────────────────────────────────────
info "Stage 1: Booting infrastructure (postgres, redis, kafka)…"
docker compose up -d postgres redis zookeeper kafka

info "Waiting for postgres to be healthy…"
timeout 120 bash -c 'until docker compose exec -T postgres pg_isready -U sentinel 2>/dev/null; do sleep 2; done'
ok "postgres healthy"

info "Waiting for kafka to be healthy (up to 90s)…"
timeout 90 bash -c '
  until docker compose exec -T kafka kafka-broker-api-versions \
    --bootstrap-server localhost:9092 >/dev/null 2>&1; do sleep 3; done
' && ok "kafka healthy" || warn "kafka health check timed out — continuing anyway"

# ── Stage 2: Core services ─────────────────────────────────────────────────
info "Stage 2: Booting core services…"
docker compose up -d auth-service
info "Waiting for auth-service (up to 60s)…"
timeout 60 bash -c 'until curl -sf http://localhost:5000/health >/dev/null; do sleep 3; done' \
  && ok "auth-service healthy" \
  || { error "auth-service failed to become healthy"; docker compose logs --tail=50 auth-service; exit 1; }

docker compose up -d api-gateway data-collector alert-service policy-orchestrator compliance-engine xai-service
info "Waiting 20s for core services to stabilise…"
sleep 20

# ── Stage 3: AI/DRL ────────────────────────────────────────────────────────
if [ "$NO_AI" = false ]; then
  info "Stage 3: Booting AI/DRL engines (this may take a while for PyTorch)…"
  docker compose up -d ai-engine drl-engine
  info "Waiting 60s for AI/DRL to start (PyTorch/SB3 load takes time)…"
  sleep 60
else
  info "Stage 3: Skipping AI/DRL services (--no-ai)"
fi

# ── Stage 4: eBPF services ─────────────────────────────────────────────────
if [ "$CORE_ONLY" = false ]; then
  info "Stage 4: Booting eBPF services (privileged containers)…"
  docker compose up -d hids-agent xdp-collector hardening-service
  sleep 10
else
  info "Stage 4: Skipping eBPF services (--core-only)"
fi

# ── Stage 5: Flink ────────────────────────────────────────────────────────
if [ "$NO_FLINK" = false ]; then
  info "Stage 5: Booting Flink stream processing jobs…"
  docker compose up -d flink-anomaly-detection flink-feature-extraction flink-drl-feed
  sleep 10
else
  info "Stage 5: Skipping Flink jobs (--no-flink or --core-only)"
fi

# ── Stage 6: Observability ─────────────────────────────────────────────────
info "Stage 6: Booting observability stack…"
docker compose up -d prometheus grafana elasticsearch kibana
sleep 10

# ── Stage 7: Admin console ─────────────────────────────────────────────────
info "Stage 7: Booting admin console…"
docker compose up -d admin-console

# ── Status summary ─────────────────────────────────────────────────────────
echo ""
ok "Boot sequence complete. Container status:"
docker compose ps

echo ""
info "Service endpoints:"
echo "  Admin Console:    http://localhost:3000"
echo "  API Gateway:      http://localhost:8080/health"
echo "  Auth Service:     http://localhost:5000/health"
echo "  Grafana:          http://localhost:3001  (admin / \$GRAFANA_PASSWORD)"
echo "  Prometheus:       http://localhost:9090"
echo "  Kibana:           http://localhost:5601"
echo ""
info "Run integration tests:"
echo "  python scripts/integration_test.py --wait 30"
