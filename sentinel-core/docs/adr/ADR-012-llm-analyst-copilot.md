# ADR-012: LLM Analyst Copilot (Wedge #2)

- **Status:** Proposed
- **Date:** 2026-06-01
- **Deciders:** Mir (approver); authored by Claude; reviewed by the independent
  review agent (must run a different model than the executor — see ADR-011 /
  `.team/agents/marcus-audit-reviewer.md`)
- **Phase:** 2 — first real LLM inference in the platform.
- **Supersedes the Phase-1 `llm-gateway` 410 shell.**

## Context

SENTINEL's defensible wedge set is reversible enforcement (#1, shipped),
cryptographic audit ledger (#3, shipped), and the **LLM analyst copilot (#2)**.
#2 was the only top-3 wedge not started; `llm-gateway` returned 410. A grounded
analyst copilot is what differentiates SENTINEL from generic XDR for the EU
regulated mid-market SOC persona.

Hard platform constraint (CLAUDE.md): *no LLM output reaches enforcement
adapters; write actions require human approval.*

## Decision

Build a grounded, tool-using analyst copilot in `llm-gateway` (Flask, matching
the existing service stack; Anthropic API for inference). It:

1. **Summarizes incidents** from real backend data (threat score via ai-engine,
   audit events via api-gateway, enforcement state via policy-orchestrator),
   fetched through a tool registry over HTTP.
2. **Answers follow-ups** with citations to source record ids, over a
   Redis-backed session.
3. **Proposes — never executes — reversible actions.** The `propose_reversible_action`
   tool returns a draft (with a TTL) for a human to confirm via the existing
   policy-orchestrator API. It makes no enforcement call.
4. **Logs itself into the audit ledger**: every prompt, completion, tool call,
   proposal, and answer is written via the shared `audit_logger` (imported,
   never edited).

Grounding is enforced in code: every cited `[type:id]` must come from a tool
result; ungrounded answers trigger a bounded repair round, then a safe fallback.

Key invariants are unit-tested: no hallucinated ids, cite-when-data-exists,
propose-never-executes, bounded iterations and token budget.

## Consequences

**Positive:** real product wedge; grounded + cited output; advisory-only by
construction; full audit coverage; cost controls (Haiku classify / Opus
synthesize, prompt caching, token caps); deterministic, network-free tests.

**Negative / costs:** dependency on the Anthropic API (see data-residency
caveat); residual hallucination is reduced, not eliminated; Redis-only session
state (ephemeral).

## Honest claim boundaries (do NOT over-claim)

- **Advisory only.** The copilot proposes; a human confirms and executes. It
  cannot enforce anything. (`test_propose_never_executes`, endpoint assertion.)
- **Grounded, not infallible.** Grounding blocks hallucinated *citations* and
  ungrounded narration; it does not guarantee perfect interpretation. The eval
  harness publishes a residual-hallucination rate rather than hiding it.
- **Inference is Anthropic-API-backed — not EU-resident.** For the EU regulated
  persona this is a gap; on-prem / EU-region inference is a Phase-3 follow-up,
  not silently shipped as "EU-resident".
- **Session state is Redis-only (ephemeral, TTL'd).** Durable Postgres
  persistence (copilot_sessions/messages/proposals) + Alembic migration is a
  **tracked follow-up PR** — deliberately deferred because new audit-adjacent
  schema would trip `audit-schema-guard`, which requires a genuine two-person
  review stamp that must not be fabricated (see ADR-011, two-person rule).
- Per the doc-honesty rule: if any CI check contradicts a claim here, fix the
  claim or fail the PR — do not publish with caveats.

## Alternatives considered

- **Let the model call enforcement directly** — rejected; violates the hard
  no-LLM-to-adapter constraint.
- **PG persistence now** — rejected for this PR to avoid an unstampable
  audit-schema migration; deferred to a follow-up with real review.
- **Pre-fill prompts with data vs. tool-calling** — both supported: summarize
  pre-fetches for determinism/cost; ask uses tool-calling for follow-ups.

## Follow-ups

1. Durable PG persistence + Alembic migration (with two-person audit stamp).
2. Root `docker-compose` wiring for `llm-gateway` (infra owner).
3. Live nightly eval against the Anthropic API (gated on `ANTHROPIC_API_KEY`).
4. EU data-residency story for inference.
5. Rebase this branch onto current `origin/main` and re-verify the
   `audit_log(...)` signature against the post-T-031 (PG) logger.
