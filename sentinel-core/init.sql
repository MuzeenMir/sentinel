-- SENTINEL Platform — PostgreSQL bootstrap (T-014 / T-030)
-- Runs once via docker-entrypoint-initdb.d on first container start.
--
-- All application schema (users, tenants, audit_log, policy_decisions,
-- compliance_assessments, token_blacklist, and every later table) is owned by
-- Alembic, starting with `backend/migrations/versions/20260417_001_consolidate_schema.py`.
-- A fresh container with this file applied as initdb is identical (for schema
-- purposes) to an empty container — both arrive at the same end-state after
-- `alembic upgrade head`. See `sentinel-core/scripts/fresh_db_check.sh`.
--
-- `pgcrypto` is kept as cheap insurance for `gen_random_uuid()` on PG<13. PG13
-- and PG16 (the only versions CI exercises) provide it built-in; the extension
-- create is a no-op there.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

COMMIT;
