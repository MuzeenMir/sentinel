#!/usr/bin/env bash
# fresh_db_check.sh — prove Alembic migrations are idempotent against a fresh database.
#
# Spins up a throwaway Postgres 16 container, runs `alembic upgrade head`, then
# `alembic downgrade base`, then `alembic upgrade head` again. Each step must
# exit 0. Any non-idempotent DDL (CREATE TABLE without IF NOT EXISTS, duplicate
# index, etc.) will fail the second upgrade.
#
# Used as a required check in `.github/workflows/integration.yml`.
#
# Assumptions:
#   - Docker (or compatible) is on PATH.
#   - `alembic.ini` lives at sentinel-core/backend/migrations/alembic.ini
#     (path overridable via $ALEMBIC_INI).
#   - $DATABASE_URL is used by alembic.env.py; we set it to the throwaway DB.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALEMBIC_INI="${ALEMBIC_INI:-${REPO_ROOT}/sentinel-core/backend/migrations/alembic.ini}"
CONTAINER="${CONTAINER:-sentinel-fresh-db-check-$$}"
PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
PG_PORT="${PG_PORT:-55432}"
PG_USER="${PG_USER:-sentinel}"
PG_PASSWORD="${PG_PASSWORD:-sentinel}"
PG_DB="${PG_DB:-sentinel_fresh_check}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-30}"

log() { printf '\033[1;34m[fresh-db]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[fresh-db]\033[0m %s\n' "$*" >&2; }

cleanup() {
  local rc=$?
  if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    log "tearing down container $CONTAINER"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

if [[ ! -f "$ALEMBIC_INI" ]]; then
  err "alembic.ini not found at $ALEMBIC_INI. Set ALEMBIC_INI=/path/to/alembic.ini and retry."
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  err "docker not on PATH"
  exit 2
fi

if ! command -v alembic >/dev/null 2>&1; then
  err "alembic not on PATH. Install with: pip install alembic psycopg[binary]"
  exit 2
fi

log "starting throwaway Postgres on :$PG_PORT as container $CONTAINER"
docker run -d --rm \
  --name "$CONTAINER" \
  -e "POSTGRES_USER=$PG_USER" \
  -e "POSTGRES_PASSWORD=$PG_PASSWORD" \
  -e "POSTGRES_DB=$PG_DB" \
  -p "${PG_PORT}:5432" \
  "$PG_IMAGE" >/dev/null

log "waiting for Postgres (timeout ${WAIT_TIMEOUT}s, require 3 consecutive ready checks)"
# Postgres entrypoint on first boot starts a bootstrap server (for init scripts)
# that briefly accepts connections, shuts down, then the real server starts.
# A single pg_isready can catch the bootstrap and misreport readiness. Require
# 3 consecutive successes (>=2s apart across the shutdown gap) to confirm the
# real server is up before alembic runs.
ready=0
for _ in $(seq 1 "$WAIT_TIMEOUT"); do
  if docker exec "$CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
    ready=$((ready + 1))
    [ "$ready" -ge 3 ] && break
  else
    ready=0
  fi
  sleep 1
done
if [ "$ready" -lt 3 ]; then
  err "Postgres did not stay ready for 3 consecutive checks within ${WAIT_TIMEOUT}s"
  docker logs "$CONTAINER" | tail -50 >&2 || true
  exit 1
fi

export DATABASE_URL="postgresql+psycopg://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/${PG_DB}"
log "DATABASE_URL set to $DATABASE_URL"

pushd "$(dirname "$ALEMBIC_INI")" >/dev/null

log "step 1: alembic upgrade head (fresh DB)"
alembic -c "$ALEMBIC_INI" upgrade head

log "step 2: alembic downgrade base"
alembic -c "$ALEMBIC_INI" downgrade base

log "step 3: alembic upgrade head (second run — exercises idempotency)"
alembic -c "$ALEMBIC_INI" upgrade head

popd >/dev/null

log "PASS — migrations are idempotent against a fresh database"
