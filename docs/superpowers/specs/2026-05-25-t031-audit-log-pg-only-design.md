# T-031 Audit Log PG-Only Migration Design

Date: 2026-05-25
Branch: `feat/audit-log-redis-to-pg`
Base: stacked on `feat/phase-1-runtime-sentinel-app-role` while PR #41 is under review

## Goal

Move the application audit path from Redis sorted sets to the PostgreSQL `audit_log` table so the `sentinel_app` role-level grant matrix actually protects production audit events. After T-031, Redis is not an audit storage surface.

## Decision

Use PostgreSQL only for audit writes, reads, and stats. Do not keep Redis as a cache and do not dual-write for a transition release.

Reasoning: T-031 exists to make the PostgreSQL role-level append-only control the real audit path. Keeping Redis writes would preserve a second audit surface that bypasses the `audit_log` `REVOKE UPDATE, DELETE, TRUNCATE` matrix. Audit queries are forensic and compliance-oriented, not a user hot path, so PostgreSQL latency is acceptable.

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

## Data Model Mapping

Keep the existing `audit_log` table shape for this PR. Store fields without dedicated columns in `details` rather than expanding the audit schema:

- `tenant_id`: existing column.
- `action`: existing column.
- `resource_type`: audit category.
- `resource_id`: audit resource.
- `details`: JSON object containing `record_id`, `actor`, `service`, original `detail`, `integrity_hash`, and any compatibility fields needed for API responses.
- `timestamp`: event timestamp.
- `user_id`: parsed from `actor` when actor is `user:<integer>`, otherwise null.
- `ip_address`: request IP when available, otherwise null.

`query_audit_log()` returns the same record shape callers already receive from Redis so API Gateway response contracts do not change.

## Write Path

`audit_log()` inserts into PostgreSQL using the runtime `DATABASE_URL`, which is `sentinel_app` after T-028. It must use parameterized SQL or SQLAlchemy Core, never string-built SQL.

Failure semantics are audit-then-act:

- If the PostgreSQL insert fails, `audit_log()` raises an exception after logging the failure.
- Callers that currently ignore `audit_log()` failures will now fail the originating request unless they deliberately catch and handle the exception.
- Tests must cover at least one request path where an audit insert failure returns an error rather than silently allowing the action.

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
- `(resource_type, timestamp DESC)` for category queries.
- Keep existing action and timestamp indexes unless a migration replaces them with stronger equivalents.

## Redis Backfill And Deletion

This PR includes a one-time backfill utility that:

1. Reads Redis audit records from `sentinel:audit:index`.
2. Inserts missing records into PostgreSQL `audit_log`.
3. Verifies inserted count and reports skipped malformed records.
4. Deletes Redis audit keys after successful verification:
   - `sentinel:audit:index`
   - `sentinel:audit:stats`
   - `sentinel:audit:<category>` keys.

The PR body must document whether the local/project Redis audit surface had entries. If no production entries exist to migrate, state that explicitly and include the command used to verify it.

## Role Enforcement

Regression coverage must prove the wedge:

- `sentinel_app` can insert and select audit rows with matching tenant context.
- `sentinel_app` cannot update, delete, or truncate `audit_log`.
- A non-audit runtime path cannot bypass the append-only matrix.
- Missing tenant context fails closed under RLS.

The existing T-028 `runtime_role_isolation_check.sh` already covers update denial and tenant isolation. T-031 should extend that check or add a sibling check for the real audit writer path.

## Testing

Use TDD for implementation. First failing tests should cover:

1. `audit_log()` writes to PostgreSQL and does not call Redis.
2. `query_audit_log()` filters PostgreSQL rows by category, actor, time range, limit, and offset.
3. `get_audit_stats()` aggregates PostgreSQL rows by category.
4. A PostgreSQL insert failure raises and blocks a representative audited action.
5. The backfill utility copies Redis sorted-set entries into PostgreSQL and deletes Redis audit keys only after verification.
6. Runtime role enforcement still rejects audit mutation.

Run focused tests first, then the repo's existing backend/unit/lint checks for touched files.

## Non-Goals

- Cryptographic Merkle chaining of audit rows.
- SIEM dispatcher redesign.
- Performance benchmarking beyond basic query/index sanity.
- Changing XAI service's separate `AuditTrail` helper.

## Risks

- The existing `audit_log` table lacks first-class `category`, `service`, and `integrity_hash` columns. Storing them in `details` avoids schema churn but makes some queries JSON-dependent unless category is mapped to `resource_type`.
- Services that call `audit_log()` outside request context may need an explicit tenant id or default behavior. Missing tenant context must not create globally visible audit rows.
- Existing tests are Redis-shaped and will need careful updates so they validate behavior rather than implementation details.
