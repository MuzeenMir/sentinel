# Retro independent ("Marcus") review — D4 per-event audit hash chain

- **Subject:** D4 / SEC-08, per-event audit hash chain. Merged squash commit `503624b` (PR #90).
- **Reviewer:** marcus-agent (automated, `claude-opus-4-8`).
- **Date:** 2026-06-26
- **Type:** Retro review (D4 was admin-merged past a **red** `audit-schema-guard` with no review trailers; this record closes that audit-trail gap).

## ⚠️ Independence status: DEGRADED — NOT satisfied

D4 was authored by Claude (Opus 4.8 + Sonnet 4.6 subagents, per the commit
trailers). This review ran on Claude/Opus — **same-model review**. It catches
mistakes against the rubric but does **not** meet the different-model rule;
it is **not** cross-model-independent. With Codex/"Kai" retired, no cross-model
reviewer is currently available (see **ADR-022**). Read this as a mistake-catching
pass, not the independent control the gate was originally designed to be.

## Scope reviewed

`audit_logger.py`, `audit_merkle.py` (`chain_genesis`), the trigger migration
`20260624_001_audit_event_chain.py`, and `verify_audit_chain.py`
(`find_chain_breaks` + report/exit wiring). Design docs and tests skimmed, not
re-executed.

## Findings (rubric)

**Migration**
- ✅ Single alembic head — only this file has `down_revision = 20260530_002_mfa_secret_text`; no fork.
- ✅ Reversible — `downgrade()` drops trigger/function/index only; the pre-existing `prev_event_hash` column is untouched → no data loss.
- ✅ Idempotent — `IF NOT EXISTS` / `CREATE OR REPLACE` / `DROP … IF EXISTS`.
- ✅ `version_num` = `20260624_001_audit_chain` (24 chars ≤ 32).
- ✅ No `AccessExclusiveLock` from a volatile default (no `ADD COLUMN DEFAULT`).

**Genesis byte-parity**
- ✅ Hex `73…7600` decodes to `sentinel.audit.chain.genesis.v1\x00`, matching `audit_merkle._CHAIN_GENESIS_DOMAIN`. plpgsql `digest(decode(hex) || convert_to(key,'UTF8'),'sha256')` == Python `sha256(_CHAIN_GENESIS_DOMAIN + key.encode())`; NULL tenant → `'system'` on both sides. Asserted by the real-PG integration test.

**Concurrency / chain integrity**
- ✅ Per-tenant `pg_advisory_xact_lock(hashtextextended(...))` — bigint-safe single-arg form, xact-scoped, serializes same-tenant writers so concurrent inserts cannot fork the chain; distinct tenants do not contend.
- ✅ `WHERE tenant_id IS NOT DISTINCT FROM NEW.tenant_id` + `ORDER BY id DESC LIMIT 1`, backed by the new `(tenant_id, id DESC)` index.

**Append-only + RLS**
- ✅ Migration grants nothing — no UPDATE/DELETE grants; append-only invariant intact.
- ✅ No RLS policy change; no `BYPASSRLS`/superuser regression. Trigger SELECT runs under the inserter's RLS, correctly scoping to the tenant.

**Verifier**
- ✅ `find_chain_breaks` detects `genesis_mismatch`, `broken_link`, and `unchained_row_after_chain_start` (mid-chain deletion / null-ing caught). `report.ok` and the process exit (`return 1`) both gate on `chain_breaks` — fail-closed.

**Domain separation / PII**
- ✅ Distinct chain-genesis domain vs event/daily-root domains. Chain-break log emits tenant_id + row id + hashes only — no PII.

## NITs (non-blocking)

1. `CREATE INDEX` (non-`CONCURRENTLY`) takes a write-blocking `SHARE` lock during build — unavoidable inside Alembic's transaction, but run on a large `audit_log` in a maintenance window.
2. **Inherent limitations (correctly out of D4 scope; document for auditors):** the per-event chain does not catch tail-truncation (deleting the last row / a whole tenant), and the hash is unkeyed (anyone with DB write can forge a self-consistent row). Tamper-evidence for those cases comes from the **cosign-signed daily Merkle roots**, not the chain. Chain + signed roots are complementary; neither alone is a standalone integrity guarantee. The verify runbook should state this.

## Verdict

**PASS on the merits** (no BLOCK, no CHANGES-REQUESTED). The change is correct,
reversible, fail-closed, and byte-parity-verified.

**Independence gate NOT satisfied** (same-model). Recorded honestly per ADR-022.

```
Audit-Reviewed-by: marcus-agent (automated, claude-opus-4-8; SAME-MODEL — independence degraded, no cross-model reviewer available)
```

`Audit-Approved-by:` is intentionally absent — that is Mir's, and the maintainer
must consciously decide whether a same-model retro review is acceptable to close
#90's trail. This record does not retroactively turn the gate green; #90 remains
merged-via-admin-override.
