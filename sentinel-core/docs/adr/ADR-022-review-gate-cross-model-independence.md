# ADR-022 — Independent review gate: cross-model independence is currently unavailable

- **Status:** Proposed (Mir ratifies on merge; flip to Accepted in the merging PR)
- **Date:** 2026-06-26
- **Deciders:** Mir (sole human owner). **Independent review: NOT available** — see the disclosure in Context; this ADR could not itself be cross-model reviewed.
- **Supersedes:** None — amends ADR-011 §2 and its Consequences (the "different model than the executor" claim).
- **Superseded by:** None

## Context

ADR-011 reframed the old "two-person rule" as an **independent review gate** and rested its remaining honest value on one concrete property (§2, Consequences): *"Marcus runs on a **different model than the executor** … Different-model review delivers real mistake-catching value now."* That property assumed the team layout in ADR-011 §Context: **Kai (executor, Codex) + Marcus (reviewer, a different model)**.

That layout no longer exists. **Codex and the "Kai" executor have been retired**, and the available models are all one family (Claude: Opus 4.8, Sonnet 4.6, Haiku 4.5, Fable 5). Concretely:

- D4 (per-event audit hash chain, PR #90, squash `503624b`) was authored by **Claude Opus 4.8 + Claude Sonnet 4.6** and admin-merged past a **red** `audit-schema-guard` with **no** `Audit-Reviewed-by` / `Audit-Approved-by` trailers.
- The retro Marcus review of D4 (2026-06-26) could only be performed **same-model** (Claude reviewing Claude-authored code). It found the change correct on the merits, but explicitly recorded that the independence gate was **not** satisfied.

Continuing to assert "a different model reviews" when no such model is reliably available would be a **false independence claim** — the exact anti-over-claim failure ADR-011 itself set out to remove. This ADR fixes the wording so the gate stops promising independence it cannot currently deliver.

## Decision

1. **Downgrade the independence claim.** The control is a **mistake-catching review gate + tamper-evident audit trail.** It is run **best-effort on a different model than the author when one is available, otherwise same-model with explicit disclosure.** It is **NOT cross-model-independent** and **NOT** human separation of duties.
2. **Operational rule (best-effort independence).** When the authoring model/tier is known and a different competent model is available, run the review on a **different model than the author** (e.g., author Opus → review Sonnet). When no different model is available, same-model review is permitted **only with disclosure** (never silently).
3. **Trailer honesty (tightened).** `Audit-Reviewed-by:` MUST name the reviewing model and flag same-model when applicable, e.g.
   `Audit-Reviewed-by: marcus-agent (automated, claude-opus-4-8; SAME-MODEL)`.
   A bare `Audit-Reviewed-by: marcus-agent (automated)` that implies independence the review did not have is **prohibited**. `Audit-Approved-by: Mir` is unchanged (the human maintainer's, never written by an agent).
4. **The `audit-schema-guard` mechanism is unchanged** — it still requires both trailers on migrations / audit-ledger source / RLS. What changes is the **honesty of what `Audit-Reviewed-by` asserts**, not the check.
5. **Restoration path.** The stronger cross-model independence claim may be **restored by a future ADR** if a genuinely independent reviewer (ideally a non-Claude model) is reinstated as the Marcus runner.

## Consequences

- **Positive:** the project stops carrying a false "different model reviews" claim; the gate's stated value matches reality (mistake-catching + cryptographically tamper-evident ledger + single-maintainer approval). Disclosure-in-trailer makes the strength of each review auditable after the fact.
- **Negative:** until/unless a non-Claude reviewer returns, a same-model review can share the author model's blind spots — weaker mistake-catching than cross-model review. This is now stated, not hidden.
- **Disclosed circularity:** this ADR changes the review gate, and **no cross-model reviewer exists to independently review it**. That limitation is disclosed here rather than papered over; ratification rests on Mir's human judgment.
- **Carried residual (from ADR-011):** `enforce_admins=false` still lets an admin bypass `audit-schema-guard` (required for the GPG admin-squash workflow). Unchanged by this ADR.

## Alternatives considered

- **Wire a different Claude tier as a standing reviewer (Opus↔Sonnet).** Adopted as the *best-effort* operational rule (Decision §2), but **not** claimed as true independence — same vendor/family, correlated failure modes. Honest framing required either way.
- **Re-add an external non-Claude reviewer now.** Out of scope here (none is provisioned); kept as the explicit restoration path (Decision §5).
- **Leave ADR-011 as-is.** Rejected — it would keep asserting cross-model independence that is no longer deliverable, a false claim.
- **Drop the gate entirely.** Rejected — the mistake-catching review and the tamper-evident trail remain worth keeping.

## References

- ADR-011 — independent review gate (amended here; see its 2026-06-26 Consequences addendum).
- ADR-000 §7 — Accepted ADRs are immutable except Consequences addenda; new information lands in a new ADR (this one).
- Retro Marcus review of D4, 2026-06-26 (same-model; PASS on merits, independence not satisfied).
- `.team/agents/marcus-audit-reviewer.md` — review-agent spec (independence section updated to match).
- `.github/workflows/audit-schema-guard.yml`, `.github/scripts/audit_schema_guard.py` — the enforcing check (mechanism unchanged).
