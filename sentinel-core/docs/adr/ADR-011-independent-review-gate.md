# ADR-011 — Reframe the "two-person rule" as an "independent review gate"

- **Status:** Accepted
- **Date:** 2026-05-31
- **Deciders:** Mir (sole human owner); independent review by marcus-agent (automated)
- **Supersedes:** None — amends ADR-000 §5 ratification rule (the "two-person rule" clause)
- **Superseded by:** None

## Context

The team is **one human (Mir) plus two AI agents** — Kai (executor, Codex) and Marcus (reviewer). A "two-person rule" exists for two reasons: (1) prevent a malicious insider / collusion via separation of duties, and (2) catch honest mistakes. Reason (1) requires **two accountable humans**; with a single human it is not satisfiable, and there is currently no adversary/insider in the threat model. Reason (2) — catching mistakes in security-critical changes — remains real regardless of headcount.

In practice the rule was unenforceable and was bypassed: audit-schema PRs (#46, #48) were admin-squashed with no human review, and the `audit-schema-guard`'s first run nearly shipped a *false* `Audit-Approved-by: Mir` trailer. Continuing to label this a "two-person rule" — and marketing it to regulated buyers — would be a **false compliance claim** (separation of duties an auditor would reject on inspection), which contradicts the project's anti-over-claim discipline.

## Decision

1. Rename the control **"two-person rule" → "independent review gate."**
2. **Marcus is an automated review agent**, not a person. It runs on a **different model than the executor** (one model writes, a different model reviews) to provide genuine *mistake-catching* independence. Spec: `.team/agents/marcus-audit-reviewer.md`.
3. Trailers are honest and non-impersonating:
   - `Audit-Reviewed-by: marcus-agent (automated)` — the independent automated review.
   - `Audit-Approved-by: Mir` — the human maintainer's approval.
   The `audit-schema-guard` check (enforced on migrations / audit-ledger source / RLS) continues to require both, unchanged.
4. This is a **mistake-catching quality gate + tamper-evident audit trail, NOT human separation of duties.** It must **not** be marketed as a regulatory two-person control.
5. A genuine human two-person rule is **deferred** until either a second human joins the team or a customer contractually requires it; only then is a second human reviewer identity provisioned in CODEOWNERS.

## Consequences

- **Positive:** the project stops carrying a false compliance claim; the wedge-buyer trust story rests on things that are actually true (independent automated review + cryptographically tamper-evident ledger + single-maintainer approval). Different-model review delivers real mistake-catching value now.
- **Negative:** loses the "two-person rule" marketing line (which was not honestly defensible anyway).
- **Residual gap:** `enforce_admins=false` (required for the GPG admin-squash merge workflow) means an admin can still bypass the `audit-schema-guard`. Making the gate absolute requires commit-signing so `enforce_admins=true` becomes viable — tracked separately, not in this ADR.
- **Supersession:** this ADR is the operative definition. The "two-person rule" wording in `CLAUDE.md`, `CODEOWNERS`, `.github/pull_request_template.md`, and the revamp specs (`SRS-002`, `SDD-002`, `CLAUDE-DESIGN-WORKFLOW`) is reframed to "independent review gate" in the same PR. ADR-000 §5 is amended by this ADR (ADR-000 itself remains immutable per its own rule). Historical review records (e.g. `phase-0-critical-fixes.md`) are left as point-in-time records.

### Addendum — 2026-06-26 (amended by ADR-022)

The "**runs on a different model than the executor**" property in Decision §2 and the "Different-model review delivers real mistake-catching value now" line above are **no longer reliably available**: Codex and the "Kai" executor have been retired, leaving only one model family (Claude). **ADR-022** downgrades the claim accordingly — the gate is now *best-effort different-model, otherwise same-model with explicit disclosure in the `Audit-Reviewed-by` trailer*, and is **not** cross-model-independent. The `audit-schema-guard` mechanism (both trailers required) is unchanged. Per ADR-000 §7 this addendum does not edit the original Decision/Context; see ADR-022 for the operative rule.

## Alternatives considered

- **Make a bot the "second person."** Rejected — an AI agent is automation, not an accountable human; claiming it as separation of duties is the exact false control this ADR removes.
- **Keep the label, add a real second human now.** Deferred — no second human exists yet; revisit when one does or a customer requires it.
- **Drop the gate entirely.** Rejected — the mistake-catching value (different-model review) and the audit trail are worth keeping.

## References

- ADR-000 §5 (ratification / "two-person rule" clause) — amended here.
- `.team/agents/marcus-audit-reviewer.md` — the review-agent spec.
- `.github/workflows/audit-schema-guard.yml`, `.github/scripts/audit_schema_guard.py` — the enforcing check.
