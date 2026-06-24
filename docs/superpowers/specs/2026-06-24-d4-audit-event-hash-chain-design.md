# D4 — Per-event hash chain for the audit ledger (SEC-08)

**Date:** 2026-06-24
**Audit finding:** SEC-08 (Low, by-design) — "No per-event hash chain — intra-day audit
tamper window before nightly root." Backlog item **D4** from
`sentinel-core/docs/reviews/CODE-AUDIT-main-2026-06-19.md` (line 145).
**Status:** design approved; implementation pending.

## Problem

The audit ledger today has two integrity layers:

1. **Role-level immutability** — `REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM
   sentinel_app` (migration `20260417_003_enable_rls.py`). The app role can only
   `INSERT, SELECT`.
2. **Nightly signed Merkle root** — `merkle-root-publish.yml` builds the previous UTC
   day's chained Merkle root over `audit_log.event_hash` and publishes it cosign-keyless
   (`scripts/publish_audit_root.py`). Auditors verify with `scripts/verify_audit_chain.py`.

The gap: between nightly roots there is an **intra-day window** with no externally
committed anchor, and rows are **not linked to each other**. The `prev_event_hash` column
exists but is written `NULL` *by deliberate design* (`audit_logger.py` and the column
comment in `20260526_001_audit_log_pg_columns.py`: tamper-evidence "comes from the daily
signed Merkle roots over event_hash, not a per-event linked list").

D4 reverses that decision: populate `prev_event_hash` into a real per-tenant chain so any
deletion / reordering / insertion is detectable **continuously**, independent of the
nightly root.

## Threat model

Defends against an actor with **more than `sentinel_app`** privileges (a DBA / superuser
who *can* `UPDATE`/`DELETE`). `sentinel_app` itself cannot mutate rows. The chain makes
such tampering **evident** (a broken link); the cosign'd daily root makes it **externally
provable**. It does not (and cannot) prevent a superuser from rewriting the entire chain
consistently — that residual is accepted and is the reason the external signed anchor
remains.

## Design decisions (locked)

| Decision | Choice | Rationale |
|---|---|---|
| Mechanism | **Per-event `prev_event_hash` chain** | Continuous, sub-second tamper-evidence (vs. only shrinking the window with more-frequent roots). |
| Scope | **Per-tenant chain** | Fits multi-tenant + RLS: a tenant verifies its own chain without reading other tenants' rows; inserts for different tenants don't contend on one lock. |
| Enforcement | **`BEFORE INSERT` DB trigger** | Matches CLAUDE.md's hard constraint "audit log append-only at the Postgres role level, **not app code**." Enforced for any writer, not just `audit_logger.py`. |
| Hash chained | **The app-computed `event_hash` as-is** | Trigger does **not** recompute `event_hash` in plpgsql — avoids write-vs-verify hash drift (the existing SQL backfill already diverges from the Python `canonical_event_digest`). |
| Genesis | **Per-tenant genesis sentinel** | First chained row's `prev_event_hash = sha256(domain ‖ "genesis" ‖ tenant_id)`, not NULL — makes deletion of a tenant's first row detectable. |
| History | **No backfill** | Legacy rows keep `prev_event_hash IS NULL` = "not chained / not applicable." The chain begins at the first post-migration insert per tenant. |

## Components

### 1. Migration (`migrations/versions/<new>_audit_event_chain.py`)
- Adds a `BEFORE INSERT ... FOR EACH ROW` plpgsql trigger function on `audit_log`:
  1. `PERFORM pg_advisory_xact_lock(<key derived from NEW.tenant_id>)` — serializes
     inserts **per tenant**; xact-scoped, auto-released at commit.
  2. `SELECT event_hash INTO last_hash FROM audit_log WHERE tenant_id = NEW.tenant_id
     ORDER BY id DESC LIMIT 1` — RLS auto-scopes to the inserting tenant (the writer has
     already `set_config('app.tenant_id', …)`).
  3. `NEW.prev_event_hash := COALESCE(last_hash, <genesis sentinel for NEW.tenant_id>)`.
  4. Trigger leaves `NEW.event_hash` untouched.
- `down_revision` chains from the **single current head** (see Risks — two heads observed).
- Idempotent guards consistent with the repo's other migrations (`CREATE OR REPLACE
  FUNCTION`, `DROP TRIGGER IF EXISTS` then `CREATE TRIGGER`).
- `downgrade()` drops the trigger + function only (never touches data).

### 2. Write path (`audit_logger.py`)
- Remove the hard-coded `prev_event_hash` `NULL` literal from the `INSERT` (and the
  "stays NULL by design" comment); the trigger now populates it. No other change — the
  app still computes `event_hash` via `canonical_event_digest`.

### 3. Verifier (`scripts/verify_audit_chain.py`)
- Add a chain-walk per tenant, ordered by `id`:
  - Recompute each row's `event_hash` from its columns (existing `canonical_event_digest`).
  - Assert `row.prev_event_hash == previous_row.event_hash`; for the first chained row,
    assert it equals the tenant's genesis sentinel.
  - Rows with `prev_event_hash IS NULL` are treated as pre-chain (skipped, reported as
    "not chained"), not as tampering.
  - Report the first broken link (tenant, row id, expected vs. found). Fail closed.

### 4. `audit_merkle.py`
- Add a small pure helper for the genesis sentinel + (if useful) a `verify_event_chain`
  pure function over an ordered list of `(event_hash, prev_event_hash)` tuples, so the
  link logic is unit-testable without a DB. Keep it dependency-free like the rest of the
  module.

## Testing

Pure unit tests (`tests/test_audit_merkle.py`, no DB):
- genesis sentinel is deterministic + tenant-specific;
- a well-formed chain verifies;
- modifying a row's content (→ different recomputed `event_hash`) breaks the next link;
- deleting a row breaks the link; reordering breaks it;
- per-tenant independence (interleaved tenants each verify);
- legacy `NULL` prev rows are reported "not chained," not tampered.

Integration test (under the `integration` workflow, which has Postgres):
- two concurrent inserts for the same tenant produce a single linear chain (advisory
  lock serializes), not a fork;
- inserts across different tenants build independent chains;
- end-to-end `verify_audit_chain.py` passes on a freshly written ledger.

## Merge gate (cannot be self-served)

This PR touches `audit_logger.py`, `audit_merkle.py`, `scripts/verify_audit_chain.py`,
and `migrations/**` — all on the `audit-schema-guard` protected list. The check
(`.github/scripts/audit_schema_guard.py`) **requires** two distinct PR-body trailers:

```
Audit-Reviewed-by: <Marcus review bot> (automated)
Audit-Approved-by: Mir
```

Consequence: the implementation can land green on all *other* CI (lint/typecheck/unit/
integration/etc.), but the PR **stays blocked** until the independent Marcus review (a
different model than the executor) runs and the human maintainer (Mir) approves. This is
the intended ADR-011 mistake-catching + tamper-evident-trail gate, not a step to bypass.

## Risks / edges to resolve during implementation

1. **NULL-tenant / system events.** The audit_log RLS policy is
   `USING/WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::bigint)`.
   `tenant_id = NULL` does not satisfy `WITH CHECK`, so confirm how system (NULL-tenant)
   rows are inserted today (likely `DEFAULT_TENANT_ID` is set, or they go through an
   owner/bypass path). Decide chain scope for NULL tenant: a reserved system-tenant
   advisory-lock key + genesis, or explicitly exclude NULL-tenant rows from chaining.
   Must not regress current system-event writes.
2. **Two alembic heads** (`001` and `20260530_002_mfa_secret_text` observed). The new
   migration must descend from the single real head; keep `integration-migrations` green.
   If there is a genuine multi-head, reconcile (merge revision) as part of this work or
   first.
3. **Performance.** Per-tenant advisory lock + `ORDER BY id DESC LIMIT 1` on each insert.
   The `idx_audit_tenant_timestamp_desc` index exists; confirm the last-row lookup uses an
   index on `(tenant_id, id DESC)` (add if the planner needs it) so high-volume tenants
   don't serialize on a slow scan.
4. **Advisory-lock key collisions.** Derive the bigint key from `tenant_id` in a way that
   reserves a distinct constant for the system/NULL scope and avoids collision with real
   tenant ids.
5. **Verify-time ordering.** The chain is ordered by `id` (the sequence), which the
   trigger uses for "last row." The verifier must order identically; do not order by
   `timestamp` (clock skew / equal timestamps).

## Out of scope

- Re-hashing or backfilling historical rows.
- Changing the nightly root / cosign flow (the chain complements it).
- Recomputing `event_hash` inside the database.
