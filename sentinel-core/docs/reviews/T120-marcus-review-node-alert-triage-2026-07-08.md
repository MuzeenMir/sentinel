# Marcus review — migration `20260707_001_node_alert_triage`

**PR:** #120 (Month-2 offline spine — auto-triage worker, detector scenarios, approval queue)
**Artifact under review:** `sentinel-core/backend/migrations/versions/20260707_001_node_alert_triage.py`
**Reviewer:** Claude Fable 5, acting as the Marcus audit-review agent (automated)
**Model:** `claude-fable-5`
**Independence:** **SAME-MODEL** — Codex/Kai are retired; only Claude-family models remain. Per ADR-022 this is a best-effort mistake-catching gate with explicit same-model disclosure, **not** cross-model-independent review and **not** human separation of duties. Maintainer approval (`Audit-Approved-by: Mir`) is a distinct, required gate.
**Date:** 2026-07-08

## Why this is gated

`audit-schema-guard` fires on **every** file under `sentinel-core/backend/migrations/`
(match-by-path). This migration adds an application feature table
(`node_alert_triage`) — it does **not** touch the audit ledger
(`audit_logger.py` / `audit_merkle.py`), does **not** alter any existing audit
schema, and defines **no** `ROW LEVEL SECURITY` / `CREATE POLICY`. It is gated by
path convention, not because it changes audit/RLS surface.

## Verdict: **PASS on the merits** (approval trailer still required from Mir)

Checked against the migration-review rubric:

| Check | Result |
|-------|--------|
| Single Alembic head after apply | ✅ head = `20260707_001_node_alert_triage`; `down_revision` chains to `20260703_001_node_alerts_grant` |
| Reversible | ✅ `downgrade()` drops the table; no data-lossy side effects beyond the feature table itself |
| Applies cleanly | ✅ verified against the live stack (`docker compose run --rm db-migrate` ran the upgrade) |
| Least privilege for the runtime role | ✅ `sentinel_app` granted `SELECT, INSERT, UPDATE` only; **no DELETE** (triage verdicts are part of the incident record); grant wrapped in a `pg_roles` existence guard |
| No audit-ledger / append-only tampering | ✅ does not touch `audit_log`, the hash chain, or any append-only trigger |
| No RLS policy change | ✅ none defined or altered |
| FK integrity | ✅ `alert_id` → `node_alerts(id)` `ON DELETE CASCADE`, `UNIQUE` (one triage row per alert) |
| Sequence usage grant | ✅ `USAGE, SELECT` on `node_alert_triage_id_seq` so INSERT as `sentinel_app` works |

### Notes / non-blocking
- `CREATE INDEX` is non-concurrent, consistent with the sibling `node_alerts`
  migration; acceptable for a fresh table on the single-node target.
- The table has **no `tenant_id` column** — the node path is single-tenant by
  design (`DEFAULT_TENANT_ID=1`), matching `node_alerts`. Reads via
  `triage_store.list_pending_proposals` therefore have no cross-tenant boundary
  (see the module docstring); this addresses the background security-review note.

## Required to satisfy the gate
- `Audit-Reviewed-by: Claude Fable 5 (automated, claude-fable-5; SAME-MODEL)` — recorded on the PR body.
- `Audit-Approved-by: Mir` — **owed from the human maintainer.** The gate correctly
  stays RED until this is present.
