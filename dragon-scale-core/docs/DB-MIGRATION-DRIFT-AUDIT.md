# DB Migration Drift Audit

*Date: 2026-04-17*
*Scope: `init.sql` vs `backend/migrations/versions/*.py` vs SQLAlchemy ORM `db.create_all()`*

## Summary

Schema source-of-truth is **split three ways** and the three diverge. A fresh `docker compose up -d` will currently rely on `init.sql` *plus* `db.create_all()` from `auth-service/app.py:763` to materialise all tables; alembic migrations are layered on top and assume tables that init.sql does not create. This will break any environment that tries `alembic upgrade head` against a fresh PostgreSQL.

## Sources

| Source | Tables it creates | Notes |
|---|---|---|
| `init.sql` (117 lines) | users, token_blacklist, tenants, audit_log (**singular**), policy_decisions, compliance_assessments | Runs once via `docker-entrypoint-initdb.d` on first container start |
| `migrations/versions/20260304_001_add_host_events_and_hardening.py` | host_events, hardening_posture, ebpf_programs, baseline_hashes | Older migration |
| `migrations/versions/20260313_001_enterprise_schema.py` | tenants (**duplicate**), policy_decisions (**duplicate**), xai_explanations, hardening_scans, hids_events, integrations, model_registry, data_retention_policies; adds `tenant_id` to alerts/threats/firewall_policies/network_logs/compliance_assessments/audit_logs (**plural**)/training_data/rl_agent_states/system_config | Assumes tables not in init.sql |
| ORM `db.create_all()` (auth-service/app.py:763) | All remaining ORM-defined tables | Runs at service boot, fills the gap |

## Drift Defects

### D-1 — Naming collision: `audit_log` vs `audit_logs`
`init.sql:50` declares `CREATE TABLE audit_log` (singular). `20260313_001:48` does `op.add_column("audit_logs", ...)` (plural). Either one is wrong; they will not refer to the same table on a fresh DB.

### D-2 — Duplicate `CREATE TABLE tenants`
`init.sql:38` and `20260313_001:22` both create `tenants`. Init.sql uses `IF NOT EXISTS` so it tolerates re-run, but the migration does not. Running migrations after init.sql will fail with `relation "tenants" already exists`.

### D-3 — Duplicate `CREATE TABLE policy_decisions`
Same problem as D-2. Init.sql column set is narrower (no `model_version`, no `state_vector`, no `reward`, no `applied`/`rolled_back`); migration's broader version is the intended one. Init.sql version is stale.

### D-4 — Missing tables on fresh DB
The migration `add_column("alerts", ...)`, `add_column("threats", ...)`, etc. fail because `init.sql` does not create those tables. They only exist after `db.create_all()` runs at service boot — i.e. the migration cannot run before any service starts. This couples migration ordering to service startup.

### D-5 — No migration for SAML / OIDC / SCIM persistence
`auth-service/app.py` exposes SAML+OIDC+SCIM endpoints but neither `init.sql` nor any migration defines `saml_configs`, `oidc_configs`, `scim_tokens`, or analogous tables. Either persisted in Redis (ephemeral) or missing entirely. Memory note `c79db17b feat: complete SAML validation, SCIM provisioning, and MFA persistence` claims persistence — verify.

### D-6 — MFA columns only in init.sql
`mfa_secret`, `mfa_enabled`, `mfa_backup_codes` columns on `users` exist only in init.sql. Any env created from an earlier init.sql snapshot will be missing them with no migration to add them.

### D-7 — RLS policies in init.sql but not in migrations
`init.sql:103-117` defines four `CREATE POLICY tenant_isolation_*` rows but `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` is commented out. No migration enables RLS. Multi-tenant isolation is therefore advisory-only at the DB layer.

## Required remediation (sequence)

1. **Pick one source of truth.** Recommend: `init.sql` becomes a no-op stub; alembic owns the schema; `db.create_all()` removed at service boot (`auth-service/app.py:763` replaced with a `flask db upgrade` call or compose-time `db-migrate` service ordering).
2. **Create migration `20260417_001_consolidate_schema.py`** that:
   - Idempotent `CREATE TABLE IF NOT EXISTS` for: alerts, threats, firewall_policies, network_logs, audit_logs (rename to plural), training_data, rl_agent_states, system_config.
   - Drop `audit_log` after copying rows to `audit_logs`.
   - Add MFA columns idempotently.
3. **Create migration `20260417_002_sso_scim.py`** for: `saml_configs`, `oidc_configs`, `scim_tokens`, `mfa_challenges` (move out of Redis to durable store).
4. **Create migration `20260417_003_enable_rls.py`** that issues `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` for users, audit_logs, policy_decisions, compliance_assessments, alerts, threats, hids_events, hardening_scans, xai_explanations.
5. **Fix `init.sql`**: strip table-creation logic, keep only PostgreSQL extensions (`gen_random_uuid()` requires `pgcrypto`), `update_updated_at_column()` function, and the `default` tenant seed.
6. **Wire `db-migrate` compose service to block all backend services on `service_completed_successfully`.**
7. **Add CI job `migration-fresh-bootstrap`**: spin Postgres, run `alembic upgrade head` from empty DB, assert exit 0.
8. **Add CI job `migration-roundtrip`**: `alembic upgrade head && alembic downgrade base && alembic upgrade head`, assert idempotent.

## Quick-win patch (this PR)

Until the consolidation lands, mitigate D-2/D-3 by gating the migration:

```python
# In 20260313_001_enterprise_schema.py, top of upgrade():
def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    if "tenants" in existing:
        op.execute("-- tenants already exists, skipping create_table('tenants')")
    else:
        op.create_table("tenants", ...)
    # similarly for policy_decisions
```

## Risk if shipped as-is

- Fresh on-prem deploy from public docs: `alembic upgrade head` fails on first run.
- Any cluster that ran old init.sql + new code: missing columns at runtime, MFA endpoints crash with `column "mfa_secret" does not exist`.
- Multi-tenant isolation claim in `RISK-TIERS.md` C-1 is unenforced at DB layer (D-7).
