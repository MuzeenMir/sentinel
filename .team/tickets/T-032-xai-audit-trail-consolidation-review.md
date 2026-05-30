# T-032 [ds] — review/migrate XAI AuditTrail under Phase 2 consolidation

Owner: Backlog
Reviewer: Marcus + Mir if it becomes an audit-schema change
Priority: P2
Filed: 2026-05-29
Phase: 2

## Context

T-031 retires Redis storage for the shared production `audit_logger.audit_log()`
path. `sentinel-core/backend/xai-service/reports/audit_trail.py` remains a
separate Redis-backed explanation trail for XAI records and is not covered by
the T-031 PG append-only claim.

## Acceptance

- Decide whether XAI explanation trails become PG-backed audit rows, separate
  XAI provenance records, or are removed during XAI consolidation.
- Remove or update Redis-backed `AuditTrail` claims so no product copy implies
  it is protected by the PG `audit_log` role-level REVOKE matrix.
- Add regression tests for the chosen storage path.
