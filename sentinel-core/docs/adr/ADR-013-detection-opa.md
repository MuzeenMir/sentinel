# ADR-013 — OPA/Rego for Detection Rule Evaluation

Status: Proposed
Date: 2026-06-01

## Context

Phase 1 moved detections into reviewed Sigma and Python files, but OPA bundles
were intentionally deferred because policy bundles trigger the two-person review
path. Phase 2 needs the detection surface to become declarative and reviewable
without silently changing existing detector behavior.

## Decision

SENTINEL will evaluate detection Rego through an OPA sidecar owned by
policy-orchestrator. Rego rules live under
`sentinel-core/backend/policy-orchestrator/rego/`, and
`policy-orchestrator/detection_rules.py` is the fail-closed HTTP client for
`/v1/data/sentinel/detections/findings`.

The first bundle ports the two seeded Python detectors to Rego and keeps a local
parity test so CI proves old and new rule behavior match on representative
events. Runtime OPA outages are security failures, not empty allow results.

## Consequences

- Detection rules can move toward OPA bundle promotion with normal code review
  plus the existing two-person OPA review rule.
- Policy-orchestrator owns the OPA evaluation boundary; detector authors own the
  Rego content and parity tests.
- CI does not require a local OPA binary yet. Unit tests validate sidecar request
  behavior, fail-closed handling, bundle metadata, and seeded detector parity.
