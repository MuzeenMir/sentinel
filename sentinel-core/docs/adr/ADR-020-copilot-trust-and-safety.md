# ADR-020 — Copilot trust & safety architecture

- **Status:** Proposed
- **Date:** 2026-06-04
- **Deciders:** SENTINEL backend CODEOWNERS
- **Relates to:** ADR-012 (LLM analyst copilot), ADR-021 (EU data residency), Plan CLAUDE (Phase 3)

## Context

Wedge #2 (the LLM analyst copilot) is the strategic differentiator for the EU
regulated mid-market SOC persona. Such buyers audit *how* an AI feature is kept
safe and auditable before they trust it near enforcement. This ADR records the
trust & safety properties built on top of the Phase-2 copilot, what is verified,
and — honestly — what is not yet shipped.

## Decision — the trust surface

| Property | Mechanism | Where | Status |
|---|---|---|---|
| **Input is untrusted** | `entity_id` allowlist `^[A-Za-z0-9._-]{1,128}$` validated before any upstream URL/param use (anti-SSRF / path-injection); reads fail soft | `tools.py` | ✅ shipped |
| **Identity is server-derived** | rate-limit + tenant keyed only off a gateway-authenticated request (`X-Internal-Service-Token` via `hmac.compare_digest`), never a client body/header field | `app.py` | ✅ shipped |
| **Grounded + verifiable citations** | every cited `[type:id]` must map to a real tool-returned record; provenance binds each id to `sha256(source)` + fetch time; forged → rejected, stale → rejected | `grounding.py`, `provenance.py`, `copilot.py` | ✅ shipped |
| **No auto-execution** | proposals are HMAC-signed, single-use (nonce), TTL-bound; `/copilot/confirm` verifies + audits but **never executes**; the UI requires an explicit human "Confirm in enforcement" | `proposals.py`, `app.py`, `ProposalCard.tsx`/`ConfirmDialog.tsx` | ✅ shipped |
| **Copilot is inside the ledger** | every prompt (metadata only, no PII), completion, tool-call, proposal, and confirm emits an audit event; cost + cache-hit recorded with the answer | `copilot.py`, `audit.py`, `telemetry.py` | ✅ shipped |
| **Observability** | OTel spans per model/tool call (no-op safe without an exporter) | `telemetry.py` | ✅ shipped |
| **Inference residency seam** | provider/region/base_url config; on-prem adapter interface | `residency.py` | ✅ shipped (see ADR-021) |
| **Tenant isolation of copilot state** | per-tenant scoping of sessions/messages/proposals | `persistence.py` | ⚠️ **partial** — see below |
| **Adversarial red-team CI gate** | injection / jailbreak / tool-poisoning / citation-forgery / SSRF-arg corpus run fail-closed in CI with published residual | `redteam.py`, `evals/redteam/*.jsonl`, `llm-gateway-redteam.yml` | ✅ shipped |

## Honest claim boundaries (do NOT over-claim)

- **Grounding reduces, does not eliminate, hallucination.** It enforces a
  *verifiable* contract (cited ids exist, hash-match a fetched source, are
  fresh). The red-team gate (`redteam.py` + `llm-gateway-redteam.yml`) runs a
  corpus of injection / forgery / SSRF-arg attacks fail-closed; the current
  residual is **0/13** (every known attack neutralized), published in CI. Note
  this measures *defense coverage of known attack classes*, **not** a
  hallucination rate on free-form generation — expand the corpus as new vectors
  are found, and do not represent 0 residual as "cannot hallucinate."
- **Copilot session state is Redis-only by design today.** Moving it to Postgres
  (for RLS tenant isolation) trips the `audit-schema-guard` required check, which
  needs a genuine independent (Marcus, different-model) review of the migration
  that must not be fabricated (see [[project_two-person-rule-not-github-enforced]]).
  So full RLS isolation (Plan CLAUDE C3) is **gated on that review**, or ships as
  interim Redis keyspace tenant-scoping first.
- **Secret encryption is a single app-layer KEK.** Per-tenant DEK / KMS is in
  flight separately (Plan KAI K3); the copilot does not yet benefit from it.
- **The audit ledger is daily signed Merkle roots, not a per-event hash chain**
  (RLS / no-migration constraint stands).
- Inference is Anthropic-API-backed; **not** EU-resident by default (ADR-021).

## Remaining integration / follow-ups

- Land copilot tenant isolation (C3) — either a Marcus-reviewed RLS migration or
  interim Redis keyspace scoping (gated on the `audit-schema-guard` two-person
  review).
- **Gateway proxy route:** the admin-console now calls `/api/v1/copilot/*`; the
  api-gateway must proxy those to the `llm-gateway` `/copilot/*` endpoints,
  injecting the internal service token + verified `X-Actor`/`X-Tenant-Id`. The
  frontend half is done (PR #56); the gateway half is authored as a Kai task
  (`.team/prompts/2026-06-04-kai-gateway-copilot-proxy.md`) since api-gateway is
  KAI-owned — not yet merged.
- Expand the red-team corpus as new attack vectors are discovered.

## Consequences

- Positive: the copilot's safety-critical invariants (untrusted input, verifiable
  grounding, no auto-exec, full audit) are enforced in code and tested.
- Positive: every gap above is explicit, so trust claims stay honest.
- Negative: until the red-team gate and RLS isolation land, the copilot is
  "advisory, grounded, audited" — not yet "adversarially measured" or
  "RLS-tenant-isolated."

## References

- llm-gateway: `tools.py`, `app.py`, `grounding.py`, `provenance.py`,
  `proposals.py`, `copilot.py`, `audit.py`, `telemetry.py`, `residency.py`
- admin-console: `CopilotPanel.tsx`, `ProposalCard.tsx`, `ConfirmDialog.tsx`,
  `pages/CopilotPage.tsx`, `services/copilot.ts`
- `.team/specs/2026-06-03-plan-CLAUDE-copilot-production-hardening.md`
