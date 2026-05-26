#!/usr/bin/env bash
# runtime_role_isolation_check.sh — Verify T-028 runtime role enforcement.
#
# Spins up a throwaway postgres:13 container, runs migrations as the
# superuser (sentinel), then exercises four assertions against the
# sentinel_app runtime role:
#
#   1. sentinel_app cannot UPDATE audit_log (REVOKE matrix).
#   2. sentinel_app with SET LOCAL app.tenant_id = '1' sees only tenant 1.
#   3. sentinel_app with SET LOCAL app.tenant_id = '2' sees only tenant 2.
#   4. sentinel_app with no SET (no request context) sees zero rows
#      (fail-closed RLS posture).
#
# Sibling to fresh_db_check.sh — same throwaway-container pattern, different
# assertions. Exits non-zero on any failure. Tears the container down on exit.
#
# Usage (from sentinel-core/):
#     bash scripts/runtime_role_isolation_check.sh
#
# Requirements: docker, python3, network access for the postgres image and
# the alembic + psycopg2-binary pip wheels. Reuses the
# `.venv-fresh-db-check` venv if present.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
MIGRATIONS_DIR="${REPO_ROOT}/backend/migrations"
VENV_DIR="${REPO_ROOT}/.venv-fresh-db-check"

CONTAINER_NAME="sentinel-runtime-role-check-$$"
PG_IMAGE="${PG_IMAGE:-postgres:13}"
PG_PORT="${PG_PORT:-55434}"
PG_USER="${PG_USER:-sentinel}"
PG_PASS="${PG_PASS:-runtimerolecheck}"
PG_DB="${PG_DB:-sentinel}"
APP_PASS="${SENTINEL_APP_DB_PASSWORD:-runtimerolecheckapp}"

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
export SENTINEL_APP_DB_PASSWORD="${APP_PASS}"

cd "${MIGRATIONS_DIR}"
echo "==> alembic upgrade head"
"${ALEMBIC}" upgrade head

# Helper: run psql as sentinel_app and return its exit code without aborting
# the script. The PGPASSWORD env carries the runtime role's password.
psql_as_app() {
  PGPASSWORD="${APP_PASS}" docker exec -e PGPASSWORD \
    "${CONTAINER_NAME}" psql -U sentinel_app -d "${PG_DB}" -h 127.0.0.1 "$@"
}

psql_as_owner() {
  docker exec "${CONTAINER_NAME}" psql -U "${PG_USER}" -d "${PG_DB}" "$@"
}

echo "==> [schema] audit_log has T-031 PG-only audit columns"
SCHEMA_COLUMNS=$(psql_as_owner -t -A -c "
  SELECT string_agg(column_name, ',' ORDER BY column_name)
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND table_name = 'audit_log'
    AND column_name IN ('event_id', 'category', 'event_hash', 'prev_event_hash')
")
if [ "${SCHEMA_COLUMNS}" != "category,event_hash,event_id,prev_event_hash" ]; then
  echo "FAIL: audit_log T-031 columns missing: ${SCHEMA_COLUMNS}" >&2
  exit 1
fi

echo "==> Seeding two tenants' users as superuser (BYPASSRLS)"
psql_as_owner -v ON_ERROR_STOP=1 -c "
  INSERT INTO users (username, email, password_hash, tenant_id)
  VALUES
    ('t1-alice', 't1-alice@example.com', 'x', 1),
    ('t1-bob',   't1-bob@example.com',   'x', 1),
    ('t2-carol', 't2-carol@example.com', 'x', 2)
" >/dev/null

# ───────────────────────────── Assertion 1 ─────────────────────────────
echo "==> [1/4] sentinel_app cannot UPDATE audit_log"
set +e
ERR=$(psql_as_app -v ON_ERROR_STOP=1 -c "UPDATE audit_log SET action='x'" 2>&1)
RC=$?
set -e
if [ "${RC}" -eq 0 ]; then
  echo "FAIL: UPDATE audit_log succeeded as sentinel_app (RC=0)" >&2
  echo "       ${ERR}" >&2
  exit 1
fi
if ! echo "${ERR}" | grep -qiE "permission denied|insufficient privilege"; then
  echo "FAIL: UPDATE audit_log failed but not for permission reasons" >&2
  echo "       ${ERR}" >&2
  exit 1
fi
echo "        OK — permission denied"

# ───────────────────────────── Assertion 2 + 3 ─────────────────────────
# psql -1 wraps the -c payload in a single implicit transaction so
# set_config(is_local=true) scopes the GUC for the count(*) that follows.
# Without -1 we'd need explicit BEGIN/COMMIT, whose command tags get
# emitted to stdout in -t -A mode and confuse `tail`.
STEP=2
for TID in 1 2; do
  EXPECTED_COUNT=$([ "${TID}" -eq 1 ] && echo 2 || echo 1)
  echo "==> [${STEP}/4] sentinel_app with app.tenant_id=${TID} sees ${EXPECTED_COUNT} user row(s)"
  COUNT=$(psql_as_app -v ON_ERROR_STOP=1 -t -A -1 -c "
    SELECT set_config('app.tenant_id', '${TID}', true);
    SELECT count(*) FROM users;
  " | tail -1 | tr -d ' ')
  if [ "${COUNT}" != "${EXPECTED_COUNT}" ]; then
    echo "FAIL: tenant ${TID} saw '${COUNT}' rows, expected ${EXPECTED_COUNT}" >&2
    exit 1
  fi
  echo "        OK — ${COUNT} rows"
  STEP=$((STEP + 1))
done

# ───────────────────────────── Assertion 4 ─────────────────────────────
echo "==> [4/4] sentinel_app with no app.tenant_id sees 0 user rows (fail-closed)"
COUNT=$(psql_as_app -v ON_ERROR_STOP=1 -t -A -c "SELECT count(*) FROM users" | tr -d ' ')
if [ "${COUNT}" != "0" ]; then
  echo "FAIL: no-context query returned ${COUNT} rows, expected 0" >&2
  exit 1
fi
echo "        OK — 0 rows"

echo "runtime_role_isolation_check.sh: PASS"
