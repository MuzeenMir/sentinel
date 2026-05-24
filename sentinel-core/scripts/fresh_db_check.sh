#!/usr/bin/env bash
# fresh_db_check.sh — Verify Alembic round-trip against a throwaway Postgres.
#
# Per Phase 0 plan
# (docs/superpowers/plans/2026-05-07-phase-0-security-stabilization.md Task 6
# step 7) and T-014e / T-030 tickets. Spins up an empty postgres:13 container
# (Alembic owns the full schema post-T-030; init.sql is extensions-only and
# applied automatically by the Postgres entrypoint, so we no longer apply it
# from this script), then runs:
#
#     alembic upgrade head
#     alembic downgrade base
#     alembic upgrade head
#
# Exits non-zero on any failure. Tears the container down on exit.
#
# Usage (from sentinel-core/):
#     bash scripts/fresh_db_check.sh
#
# Requirements: docker, python3, network access for the postgres image and the
# alembic + psycopg2-binary pip wheels. Creates a throwaway venv at
# `sentinel-core/.venv-fresh-db-check` (reused across runs; safe to delete).

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
MIGRATIONS_DIR="${REPO_ROOT}/backend/migrations"
VENV_DIR="${REPO_ROOT}/.venv-fresh-db-check"

CONTAINER_NAME="sentinel-fresh-db-check-$$"
PG_IMAGE="${PG_IMAGE:-postgres:13}"
PG_PORT="${PG_PORT:-55433}"
PG_USER="${PG_USER:-sentinel}"
PG_PASS="${PG_PASS:-freshdbcheck}"
PG_DB="${PG_DB:-sentinel}"

cleanup() {
  local rc=$?
  if docker ps -aq -f "name=^${CONTAINER_NAME}$" 2>/dev/null | grep -q .; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
  exit "${rc}"
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not on PATH" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not on PATH" >&2; exit 1; }
[ -d "${MIGRATIONS_DIR}" ] || { echo "ERROR: ${MIGRATIONS_DIR} not a directory" >&2; exit 1; }

echo "==> Starting ${PG_IMAGE} as ${CONTAINER_NAME} on port ${PG_PORT}"
docker run -d --name "${CONTAINER_NAME}" \
  -e "POSTGRES_USER=${PG_USER}" \
  -e "POSTGRES_PASSWORD=${PG_PASS}" \
  -e "POSTGRES_DB=${PG_DB}" \
  -p "${PG_PORT}:5432" \
  "${PG_IMAGE}" >/dev/null

echo "==> Waiting for Postgres to accept queries (max 60s)..."
# Use psql -c "SELECT 1" instead of pg_isready: pg_isready returns OK during the
# initial initdb cycle, but the container then restarts to apply final config,
# briefly making the server unreachable. A real query succeeds only after the
# post-initdb restart completes.
READY=
for _ in $(seq 1 60); do
  if docker exec "${CONTAINER_NAME}" psql -U "${PG_USER}" -d "${PG_DB}" -c "SELECT 1" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [ -z "${READY}" ]; then
  echo "ERROR: Postgres did not become ready within 60s" >&2
  docker logs "${CONTAINER_NAME}" >&2 || true
  exit 1
fi

if [ ! -d "${VENV_DIR}" ]; then
  echo "==> Creating venv at ${VENV_DIR}"
  python3 -m venv "${VENV_DIR}"
fi
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet alembic psycopg2-binary

ALEMBIC="${VENV_DIR}/bin/alembic"
export DATABASE_URL="postgresql://${PG_USER}:${PG_PASS}@localhost:${PG_PORT}/${PG_DB}"
# T-028 migration 20260524_001 requires SENTINEL_APP_DB_PASSWORD. Throwaway
# value is fine — this script only validates the round-trip; the runtime
# role's password is exercised by runtime_role_isolation_check.sh.
export SENTINEL_APP_DB_PASSWORD="${SENTINEL_APP_DB_PASSWORD:-freshdbcheckapp}"

cd "${MIGRATIONS_DIR}"
echo "==> alembic upgrade head"
"${ALEMBIC}" upgrade head
echo "==> alembic downgrade base"
"${ALEMBIC}" downgrade base
echo "==> alembic upgrade head (second pass)"
"${ALEMBIC}" upgrade head

echo "fresh_db_check.sh: PASS"
