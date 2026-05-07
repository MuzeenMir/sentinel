# SENTINEL Revamp — Specification Set v2

This folder contains the **v2 specification set** that supersedes the v1 documents in
`docs/specifications/` for all work going forward. The v1 documents remain in-place as
the historical record of how SENTINEL was originally scoped; they are **not** to be
treated as authoritative for current development.

## Why v2 exists

A 2026-04-18 audit established that SENTINEL v1 is ~60% real, ~40% scaffolding. The v2
revamp:

1. **Narrows scope** to a defensible beachhead (server + endpoint hardening with AI-
   assisted detection-and-response) rather than the catch-all "enterprise platform"
   framing.
2. **Consolidates 11 microservices into 4** (`collector`, `analyzer`, `controller`,
   `console`) plus one cross-cutting `llm-gateway`.
3. **Replaces in-house sensors with proven upstream projects** (Falco, Suricata,
   Wazuh) so engineering effort goes into the *brain* on top, not into reinventing
   kernel-level packet capture.
4. **Adds AI-assisted SOC capabilities** built on Gemma 4 + TurboQuant (released
   2026-Q1) for triage, narrative correlation, and on-device explanation — with strict
   advisory-only guardrails.
5. **Demotes DRL from product feature to research track** until classical ML and rules
   are saturated.
6. **Hardens multi-tenancy, observability, CI gates, and supply-chain provenance**
   that were partial in v1.

## Document index

| Document | ID | Purpose |
|---|---|---|
| [SRS-002.md](SRS-002.md) | SENTINEL-SRS-002 | Revamp Software Requirement Specification — what v2 must do (functional + non-functional + AI safety + LLM operational requirements). IEEE 830 adapted. |
| [SDD-002.md](SDD-002.md) | SENTINEL-SDD-002 | Revamp Software Design Document — target architecture, component design, LLM gateway internals, sensor integration, data flow. IEEE 1016 adapted. |
| [SDP-002.md](SDP-002.md) | SENTINEL-SDP-002 | Revamp Software Development Plan — phases 0–6, milestones, risk register, quality gates, decommissioning plan. |
| [GIT-RESTRUCTURE.md](GIT-RESTRUCTURE.md) | SENTINEL-GIT-001 | Git repository restructure — branch model, commit conventions, protection rules, hook setup, migration runbook. |
| [CLAUDE-DESIGN-WORKFLOW.md](CLAUDE-DESIGN-WORKFLOW.md) | SENTINEL-DESIGN-001 | Console UX workflow with Claude Design — brief→Design→implementation loop, per-phase brief catalog, design-system snapshot, visual regression in CI. |

## Companion v1 documents (historical / referenced)

The v2 set deliberately does **not** duplicate content that remains valid from v1.
Where v2 is silent on a topic, the v1 document still applies. Specifically:

- **[v1 SRS](../specifications/SRS.md)** — v2 SRS overrides Sections 2 (Scope), 3
  (Functional Requirements) wholesale. v1 Section 4 (Non-Functional Requirements)
  remains baseline; v2 raises specific NFRs.
- **[v1 SDD](../specifications/SDD.md)** — v2 SDD overrides Section 4 (Component
  Design) wholesale. v1 Section 7 (Database Schema) is augmented (RLS additions),
  not replaced.
- **[v1 SAD](../specifications/SAD.md)** — v2 introduces no new ADR template; existing
  ADR conventions continue. New ADRs from v2 work go in `docs/adr/`.
- **[v1 STP](../specifications/STP.md)** — extended in SDP-002 §7 (Quality Gates).
- **[v1 SDP](../specifications/SDP.md)** — fully replaced by SDP-002.
- **[v1 SECURITY_ARCHITECTURE](../specifications/SECURITY_ARCHITECTURE.md)** — extended
  in SDD-002 §10 (LLM threat model additions).
- **[v1 API_SPECIFICATION](../specifications/API_SPECIFICATION.md)** — to be reissued
  as `API-SPECIFICATION-002.md` after Phase 1 service consolidation lands. Until then,
  v1 is authoritative for endpoints that still exist.
- **[v1 DEPLOYMENT_AND_OPERATIONS](../specifications/DEPLOYMENT_AND_OPERATIONS.md)** —
  augmented in SDP-002 Phase 0 (Stabilize) and Phase 1 (Consolidation).

## Document lifecycle

These are **living documents**. Update them when:

- A phase in SDP-002 closes (mark milestones complete, capture lessons learned).
- A requirement in SRS-002 changes (raise the version, log the change in §1.6 Change
  History).
- A design decision in SDD-002 is made (add an ADR in `docs/adr/`, link it from the
  affected SDD section).
- A guardrail proves insufficient or excessive (update the AI Safety / LLM
  Operational sections of SRS-002 and the corresponding SDD-002 component).

Each document carries a Document ID, a Version, a Last Reviewed date, and a Change
History table. Treat these like code: no silent edits, every change has a commit
message and a section bump.

## Reading order

1. **Start here** (this README) — sets context and scope.
2. **SRS-002** — what the system must do.
3. **SDD-002** — how it does it.
4. **SDP-002** — how we get there.
5. **GIT-RESTRUCTURE** — how we manage the code while we get there.
6. **CLAUDE-DESIGN-WORKFLOW** — how the console UX gets designed alongside each phase.

A first-time reader should be able to read all five documents in under two hours.
