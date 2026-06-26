# Next steps / Phase-1 roadmap — 2026-06-26

Companion to the [2026-06-19 code audit](./CODE-AUDIT-main-2026-06-19.md) and its
**Remediation closure (2026-06-26)** section. The audit's Wave A–D backlog is materially complete at
**v1.8.0**; this file tracks the work that is genuinely *remaining* — the items deliberately left
open in that closure, plus the larger Phase-1 structural goals the audit flagged (ARC-01/02) and the
parked Phase-0 follow-up (G6).

None of these are started here. Each is sized and ordered so a future session can pick one up.

## 1. A5.3 — make the red-team gate a required check *(S, optional CI hardening)*

The red-team detector (`sentinel-core/backend/llm-gateway/redteam.py` + `safety.py`) is now real:
intent-shaped regexes plus a held-out paraphrase corpus (`evals/redteam/injection_heldout.jsonl`)
that cannot pass by matching itself. The remaining gap is that the gate is **not required**.

It cannot simply be added to `branch-protection.json` as-is: `llm-gateway-redteam.yml` is
**path-filtered** to `sentinel-core/backend/llm-gateway/**`, so a required path-filtered check leaves
every non-LLM PR waiting forever on a status that never reports.

**Approach:** restructure the trigger so the job runs on *all* PRs and fast-passes (no-op exit 0)
when `llm-gateway/**` is untouched — mirror how `audit-schema-guard` stays green on unrelated PRs —
then add `llm-gateway-redteam` to `.github/branch-protection.json`. Verify a non-LLM PR goes green
quickly. Leave the **eval** gate (CI-03) non-required by design.

## 2. A6.3 — graduate `detection_engine` / `plugins` from experimental *(M)*

Both subsystems are currently marked EXPERIMENTAL/OFFLINE in their module docstrings with zero
runtime importers (audit SUB-01/02; closure took the "mark experimental" alternative).

**Approach:** wire `detection_engine.load_registry()` / `DetectionRegistry` into the ai-engine or
data-collector ingest path, and add a runtime consumer that calls `plugins.discover_plugins()` /
`start_all()`. Remove the EXPERIMENTAL markers only once a service actually consumes them at runtime,
and update the docs that currently describe them as staged-not-live.

## 3. Phase-1 structural — ARC-01 / ARC-02 *(L, multi-week)*

The audit's architecture findings remain the real forward work:

- **ARC-01 — service consolidation 11→4+1.** Collapse the 13 discrete backend services into
  `console` / `controller` / `analyzer` / `collector` + `llm-gateway` per the revamp target in
  `sentinel-core/docs/revamp/`. Do not market as achieved until services actually merge.
- **ARC-02 — shared `backend/_lib/` buildout.** Only `net.py` + `tenancy.py` exist today; the
  planned `cim` / `otel` / `audit` / `llm_client` modules are not there. Build them out and migrate
  services onto them.
- **`USE_V2_*` strangler routing.** Currently vestigial — only one flag is load-bearing
  (policy-orchestrator). Make the strangler routing real before describing it as the migration path.

These are gated by the revamp SDD/SDP and should be planned as their own phase, not folded into a
docs pass.

## 4. G6 — runtime capability-cap verification *(S, parked since Phase 0)*

Container capability-cap behavior was never verified on a real Docker host (apt mirror was dead on
the Phase-0 host). CI asserts the *posture* (`validate_compose_security.py` enforces the
`PRIVILEGED_ALLOWED` allowlist and, since SEC-07, `cap_drop`/`no-new-privileges`/digest-pinning), but
actual Linux capability enforcement at runtime is still unconfirmed. Re-run on a working-apt Docker
host and record the result in `phase-0-critical-fixes.md`.

## Suggested order

1 (quick CI trust win) → 4 (close the last Phase-0 verification gap) → 2 (graduate experimental
subsystems) → 3 (the multi-week structural phase, planned separately).
