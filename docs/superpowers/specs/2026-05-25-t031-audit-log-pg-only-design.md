# T-031 Audit Log PG-Only Migration Design

Date: 2026-05-25
Locked: 2026-05-26 by Mir
Branch: `feat/phase-1-audit-log-redis-to-pg`
Base: stacked on `feat/phase-1-runtime-sentinel-app-role` while PR #41 is under review

## Goal

Move the production `audit_logger.audit_log()` path from Redis sorted sets to the PostgreSQL `audit_log` table so the `sentinel_app` role-level grant matrix actually protects production audit events. After T-031, the shared audit logger has no Redis storage path.

## Decision

Use PostgreSQL only for audit writes, reads, and stats. Do not keep Redis as a cache and do not dual-write for a transition release.

Reasoning: T-031 exists to make the PostgreSQL role-level append-only control the real audit path. Keeping Redis writes would preserve a second audit surface that bypasses the `audit_log` `REVOKE UPDATE, DELETE, TRUNCATE` matrix. Audit queries are forensic and compliance-oriented, not a user hot path, so PostgreSQL latency is acceptable.

Full Redis retirement is required for the security claim. If reads can still be served from Redis, the product cannot honestly claim "audit log append-only at PG role level" because a Redis root can mutate the read path. The future cryptographic audit-ledger work also needs one source of truth; a PG hash chain is not meaningful if audit events also live in a mutable cache.

## Current State

`sentinel-core/backend/audit_logger.py` currently:

- Builds an audit record with `id`, ISO timestamp, epoch, category, action, actor, resource, service, tenant_id, detail, and integrity hash.
- Writes the serialized record into Redis sorted sets:
  - `sentinel:audit:<category>`
  - `sentinel:audit:index`
- Increments Redis hash stats under `sentinel:audit:stats`.
- Provides query and stats helpers used by API Gateway audit endpoints.

The PostgreSQL table already exists from `20260417_001_consolidate_schema.py`:

- `id BIGINT PRIMARY KEY`
- `tenant_id BIGINT`
- `user_id INTEGER`
- `action VARCHAR(100) NOT NULL`
- `resource_type VARCHAR(50)`
- `resource_id VARCHAR(100)`
- `details JSONB`
- `ip_address INET`
- `timestamp TIMESTAMP DEFAULT NOW()`

The `sentinel_app` grants already exist from `20260417_003_enable_rls.py`: `INSERT, SELECT` on `audit_log`, with `UPDATE, DELETE, TRUNCATE` revoked.

## Schema-Diff Gate

Before flipping the writer, compare the existing Redis record shape against `audit_log`:

- Redis fields today: `id`, ISO `timestamp`, `epoch`, `category`, `action`, `actor`, `resource`, `service`, `tenant_id`, `detail`, `integrity_hash`.
- Existing PG columns today: `id`, `tenant_id`, `user_id`, `action`, `resource_type`, `resource_id`, `details`, `ip_address`, `timestamp`.

T-031 must add a schema migration before the writer flip. This migration is part of the same PR as the writer change so the new columns do not land unused.

New first-class columns:

- `event_id UUID UNIQUE NOT NULL DEFAULT gen_random_uuid()`: stable public audit event id and idempotent backfill key. New events use UUIDv4. Redis backfill maps the legacy Redis `id` string to a deterministic UUIDv5 under a documented T-031 namespace, and stores the original Redis id in `details.original_record_id`.
- `category VARCHAR(50) NOT NULL`: audit category. Do not overload `resource_type`; it remains the audited object domain.
- `event_hash TEXT NOT NULL`: current integrity hash. This front-loads the first-class hash column needed for the later cryptographic audit-ledger work.
- `prev_event_hash TEXT NULL`: reserved for the later hash-chain/Merkle work. It remains nullable in T-031 and must not be used to claim chain verification yet.

The migration must also ensure `audit_log.id` can be inserted without app-side bigint allocation. If the existing `id` column has no server default, create/attach an owned sequence default before any writer or backfill inserts.

Updated mapping:

- `tenant_id`: existing column.
- `action`: existing column.
- `category`: new first-class column; source = audit category.
- `resource_type`: audited object type when available, otherwise null.
- `resource_id`: audit resource.
- `event_id`: new first-class column; source = UUIDv4 for new writes, deterministic UUIDv5 from Redis `id` for backfill.
- `event_hash`: new first-class column; source = current integrity hash.
- `prev_event_hash`: null until the cryptographic audit-ledger ticket.
- `details`: JSON object containing `actor`, `service`, original `detail`, `epoch`, `original_record_id` for backfilled Redis events, and compatibility fields needed for API responses.
- `timestamp`: event timestamp.
- `user_id`: parsed from `actor` when actor is `user:<integer>`, otherwise null.
- `ip_address`: request IP when available, otherwise null.

`query_audit_log()` returns the same record shape callers already receive from Redis so API Gateway response contracts do not change.

## PR Shape

T-031 lands as one PR with two-person review from Marcus and Mir:

1. Schema migration (`event_id`, `category`, `event_hash`, `prev_event_hash`, `id` default if needed, indexes).
2. Writer/read/backfill flip to PG-only.

Do not split schema and writer into separate PRs unless PR size becomes unreviewable. Atomic landing avoids unused audit columns and keeps the two-person audit review focused on one behavioral change.

## Write Path

`audit_log()` inserts into PostgreSQL using the runtime `DATABASE_URL`, which is `sentinel_app` after T-028. It must use parameterized SQL or SQLAlchemy Core, never string-built SQL. It must not write to Redis, and it must not fall back to Redis if PostgreSQL is unavailable.

Failure semantics are audit-then-act:

- If the PostgreSQL insert fails, `audit_log()` raises an exception after logging the failure.
- Callers that currently ignore `audit_log()` failures will now fail the originating request unless they deliberately catch and handle the exception.
- Tests must cover `PUT /api/v1/auth/users/<id>` admin role/status update as the representative fail-closed mutation: if PG audit insert fails, the user change must not become durable.

## Call-Site Failure Policy

The implementation must update every current `audit_log()` call site and document any new call sites added during the branch. Current writer call sites:

| File/route | Action | Policy | Required behavior |
| --- | --- | --- | --- |
| `auth-service/app.py` `/api/v1/auth/register` | `user_registered` | fail-closed | No durable user creation unless the audit row inserts. Reorder into one transaction or explicitly roll back on audit failure. |
| `auth-service/app.py` `/api/v1/auth/login` inactive account | `login_blocked_inactive` | fail-soft-deny | The request must still deny access with 403. Audit failure must not convert a denied login into a 500-driven auth DoS. |
| `auth-service/app.py` `/api/v1/auth/login` locked account | `login_blocked_locked` | fail-soft-deny | The request must still deny access with 403. Audit failure is logged and counted, but access remains denied. |
| `auth-service/app.py` `/api/v1/auth/login` invalid credentials | `login_failed` | fail-soft-deny | The request must still deny access with 401. Failed-login counters should not be rolled back because audit is unavailable. |
| `auth-service/app.py` `/api/v1/auth/login` success | `login_success` | fail-closed | Do not issue tokens if the audit insert fails. Avoid committing login-state changes before the audit succeeds where practical. |
| `auth-service/app.py` `/api/v1/auth/logout` | `logout` | fail-soft-secure | Token revocation must remain durable even if audit fails. Do not leave a token valid because the audit sink is unavailable. |
| `auth-service/app.py` `/api/v1/auth/users/<id>` PUT | `user_updated` | fail-closed | No durable role/status change unless the audit row inserts. |
| `auth-service/app.py` `/api/v1/tenants` POST | `tenant_created` | fail-closed | No durable tenant creation unless the audit row inserts. |
| `auth-service/app.py` `/api/v1/tenants/<id>` DELETE | `tenant_deactivated` | fail-closed | No durable tenant deactivation unless the audit row inserts. |
| `policy-orchestrator/app.py` policy create | `policy_created` | fail-closed | No durable policy creation or vendor apply side effects unless the audit row inserts. If the current policy engine cannot guarantee that, stop and surface before implementation. |

`query_audit_log()` and `get_audit_stats()` call sites in `api-gateway/app.py` are read paths, not audit writers. They should return normal API errors on PG query failure rather than falling back to Redis.

## Read Path

`query_audit_log()` reads from PostgreSQL and supports the current filters:

- `category`
- `start_time`
- `end_time`
- `actor`
- `limit`
- `offset`

`get_audit_stats()` reads from PostgreSQL and returns the existing API shape:

- `total_events`
- `by_category`
- `retention_days`
- `timestamp`

Add or verify indexes for the query pattern:

- `(tenant_id, timestamp DESC)`
- `(tenant_id, category, timestamp DESC)` for category-scoped tenant queries.
- `event_id UNIQUE`
- Keep existing action and timestamp indexes unless a migration replaces them with stronger equivalents.

## Redis Backfill And Deletion

This PR includes `sentinel-core/scripts/migrate_audit_redis_to_pg.py`, a one-time backfill utility that:

1. Reads Redis audit records from `sentinel:audit:index`.
2. Inserts missing records into PostgreSQL `audit_log` using the `sentinel_app` runtime DSN and `SET LOCAL app.tenant_id` per tenant batch.
3. Verifies inserted count and reports skipped malformed records.
4. Is idempotent and replay-safe: a second run must not duplicate rows. The idempotency key is `event_id`, derived deterministically from the legacy Redis `id` during backfill.
5. Deletes Redis audit keys after successful verification:
   - `sentinel:audit:index`
   - `sentinel:audit:stats`
   - `sentinel:audit:<category>` keys.

The PR body must document whether the local/project Redis audit surface had entries. If no production entries exist to migrate, state that explicitly and include the command used to verify it.

Operator runbook updates are required in two places:

- `CHANGELOG.md` under the v1.1.4 breaking/upgrade block.
- `sentinel-core/readme.md` operator notes, with the exact script command and "run before promoting v1.1.4+" warning.

## Role Enforcement

Regression coverage must prove the wedge:

- `sentinel_app` can insert and select audit rows with matching tenant context.
- `sentinel_app` cannot update, delete, or truncate `audit_log`.
- A non-audit runtime path cannot bypass the append-only matrix.
- Missing tenant context fails closed under RLS.
- Cross-tenant reads through `query_audit_log()` do not leak rows.

The existing T-028 `runtime_role_isolation_check.sh` already covers update denial and tenant isolation. T-031 should extend that check or add a sibling check for the real audit writer path.

## XAI AuditTrail Boundary

`sentinel-core/backend/xai-service/reports/audit_trail.py` is a separate Redis-backed explanation trail and is not the shared SOC2 audit logger. T-031 does not migrate it.

To keep claims precise:

- T-031 may claim: "the shared production `audit_logger.audit_log()` path is PG-only and protected by the `sentinel_app` role grant matrix."
- T-031 may not claim: "all audit-like Redis trails in the repository are retired."
- A Phase 2 follow-up ticket must be filed before T-031 merges: "review/migrate XAI `AuditTrail` under XAI consolidation." That ticket owns whether XAI explanation trails become PG-backed audit rows, separate XAI provenance records, or are removed with the XAI service consolidation.

## Testing

Use TDD for implementation. First failing tests should cover:

1. `audit_log()` writes to PostgreSQL and does not call Redis.
2. `query_audit_log()` filters PostgreSQL rows by category, actor, time range, limit, and offset.
3. `get_audit_stats()` aggregates PostgreSQL rows by category.
4. A PostgreSQL insert failure blocks `PUT /api/v1/auth/users/<id>` admin role/status update and leaves the target user unchanged.
5. The backfill utility copies Redis sorted-set entries into PostgreSQL and deletes Redis audit keys only after verification.
6. The backfill utility can be run twice with a stable row count.
7. Runtime role enforcement still rejects audit mutation and cross-tenant reads.

Run focused tests first, then the repo's existing backend/unit/lint checks for touched files.

## Non-Goals

- Cryptographic Merkle chaining of audit rows.
- SIEM dispatcher redesign.
- Performance benchmarking beyond basic query/index sanity.
- Changing XAI service's separate `AuditTrail` helper.
- Redis-as-cache, dual-write, or write-through compatibility mode.

## Risks

- The existing `audit_log` table lacks first-class event identity, category, and hash-chain columns. T-031 adds `event_id`, `category`, `event_hash`, and nullable `prev_event_hash`; this is an audit-schema change and requires Marcus + Mir review.
- Services that call `audit_log()` outside request context may need an explicit tenant id or default behavior. Missing tenant context must not create globally visible audit rows.
- Existing tests are Redis-shaped and will need careful updates so they validate behavior rather than implementation details.
- If audit-write latency regresses by more than 10x against the Redis baseline, stop and surface it. The fallback design is a PostgreSQL-backed write-behind queue, not reintroducing Redis as audit storage.
