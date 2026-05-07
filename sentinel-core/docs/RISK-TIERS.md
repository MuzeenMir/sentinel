# SENTINEL Product Risk Tiers

*Status: v0.1 — initial draft, April 10, 2026*
*Owner: Project lead*
*Review cadence: every tagged release*

---

## Purpose

This document defines SENTINEL's **product risk tiers** — explicit, testable claims about
what the platform will and will not do at any given release. It exists because "we tested
it and it looked fine" is not a serious release gate for a system that can block traffic
and modify firewall rules in-kernel.

The tiers are modelled on the Responsible Scaling Policy thresholds used by frontier-AI
labs (for example, the Claude Mythos Preview System Card §2). SENTINEL is not a frontier
AI system and has no catastrophic-risk thresholds in that sense, but the discipline is the
same: name the claim, name the mitigation, name the evidence, and hold the release until
each is in place.

A release that fails any tier is held back to the `edge` channel and cannot be tagged as
`stable`.

---

## Table of Contents

- [Overview](#overview)
- [Tier D-1: Detection](#tier-d-1-detection)
- [Tier DRL-1: Policy](#tier-drl-1-policy)
- [Tier C-1: Compliance](#tier-c-1-compliance)
- [Release gating process](#release-gating-process)
- [Decision log](#decision-log)
- [Open questions](#open-questions)

---

## Overview

| Tier | Concerns | Owner |
|------|----------|-------|
| **D-1 Detection** | Ensemble classifier quality and latency on held-out traffic | ai-engine team |
| **DRL-1 Policy** | PPO agent action selection, reward hacking, shadow-mode regression | drl-engine team |
| **C-1 Compliance** | SOC 2 evidence completeness and retention | compliance-engine team |

Each tier is a bundle of:

1. **A claim** the release candidate is willing to stand behind.
2. **A mitigation** that protects the claim in production.
3. **An evidence requirement** that is produced by CI or by a documented manual run.

Crossing a tier (i.e. failing the claim) has release consequences. Staying below it does
not.

---

## Tier D-1: Detection

### Claim

On a held-out evaluation set composed of CIC-IDS2017 + UNSW-NB15 + internal adversarial
flows, the SENTINEL ensemble (XGBoost + LSTM + Isolation Forest + Autoencoder + meta-learner)
achieves:

- Weighted F1 ≥ 0.90
- Weighted precision ≥ 0.90
- Weighted recall ≥ 0.88
- XGBoost inference p95 ≤ 5 ms per sample
- LSTM inference p95 ≤ 10 ms per 32-sample sequence

### Mitigation

- Ensemble meta-learner with weighted-average fallback if the meta-learner artefact is
  missing or corrupt (see `ml-models.md` § Stacking Ensemble).
- Per-detector decontamination of the training corpus (see `CONTAMINATION-POLICY.md`).
- A retraining pipeline that rejects any candidate model whose held-out F1 is > 2 points
  lower than the current production model.
- Drift alarm on the production detector: a 7-day rolling F1 drop of more than 3 points
  triggers a page.

### Evidence required per release

- [ ] Benchmark report JSON checked in under `tests/benchmarks/reports/<version>.json`.
- [ ] Per-detector metric table reproduced in the release notes.
- [ ] Latency histogram from `tests/bench/latency.py`.
- [ ] Drift dashboard screenshot (Grafana) or link to a dashboard with the release's
      start/end markers.
- [ ] Signed-off by the ai-engine team owner.

### Status in this release

**[planned]** — The targets above are documented in `ml-models.md` but no scored
benchmark has been checked in to the repo yet. The first version of this card will be
published with the next tagged release. See the [Decision log](#decision-log).

### Failure modes this tier is trying to rule out

1. **Silent regression.** A retraining run lowers F1 by 5 points and nobody notices
   because there is no release gate.
2. **Latency blow-up.** A new feature extractor triples p95 and the Flink pipeline
   starts back-pressuring Kafka.
3. **Benchmark gaming.** A detector is tuned to look good on one public benchmark but
   does not generalise. Mitigation: the held-out set is *composite* (public + adversarial),
   not a single benchmark.

### References

- `ml-models.md` — per-detector architecture and hyperparameters.
- `CONTAMINATION-POLICY.md` — train/eval separation rules.
- Mythos System Card §6 — analogous capabilities table.

---

## Tier DRL-1: Policy

### Claim

For any PPO checkpoint promoted to enforcement, on a held-out shadow traffic set:

- False block rate < 1% (measured as `DENY` or `QUARANTINE` actions on ground-truth
  benign flows).
- Compliance score does not regress versus the previous checkpoint by more than 0.5
  points.
- The action distribution does not shift by more than 10 percentage points in any
  single action relative to the previous checkpoint (sanity check against
  reward-hacking regressions).
- No single state-vector feature accounts for more than 40% of the policy head's
  gradient in a SHAP-style attribution (sanity check against collapse onto one feature).

### Mitigation

- **Staged rollout**: `shadow` → `canary` → `enforce`.
  - In `shadow`, every PPO action is logged but the policy orchestrator executes the
    previous checkpoint's action.
  - In `canary`, the new checkpoint is applied to a named subset (e.g. one VLAN or one
    account) for a minimum of 72 hours with elevated monitoring.
  - Promotion to `enforce` requires an explicit operator action in the admin console,
    with justification text written to the audit log.
- **Kill switch**: a single API call (`POST /api/v1/drl/kill-switch`) reverts the policy
  orchestrator to the rule-based fallback within 5 seconds.
- **Auto-rollback**: if the compliance score regresses by more than 1.0 points within the
  first 24 hours in `canary`, the orchestrator automatically reverts.
- **Reward-hacking audit** on every retraining run — see `MODEL-RED-TEAM.md` §
  Reward hacking.

### Evidence required per release

- [ ] Shadow-mode transcript: at least 72 hours of logged PPO decisions with ground-truth
      labels where available.
- [ ] Action-distribution diff versus the previous checkpoint.
- [ ] Reward-hacking audit report from the ablation suite.
- [ ] Feature attribution report on the policy head.
- [ ] Operator override log for the shadow + canary windows.
- [ ] Signed-off by the drl-engine team owner.

### Status in this release

**[partial]** — Shadow mode is now the **default** (`DRL_SHADOW_MODE=true` in
`docker-compose.yml`, propagated to drl-engine config and respected by the policy
orchestrator's `/api/v1/policies/apply` endpoint, which returns HTTP 202 + `shadow:true`
for any decision tagged `shadow=true` or `enforce=false`). The decode path in
`backend/drl-engine/app.py` now annotates every decision with `shadow` and `enforce`
flags. Canary scoping by VLAN exists in `policy-orchestrator/scopes.py` but is not yet
integrated with the DRL engine's checkpoint promotion flow. The kill-switch endpoint
(`POST /api/v1/drl/kill-switch`) does not exist yet. See the [Decision log](#decision-log).

**Promotion ladder:**
1. `DRL_SHADOW_MODE=true` (default) — actions logged + tagged shadow=true, orchestrator refuses to enforce.
2. Set `DRL_SHADOW_MODE=false` on a single canary cluster + scope to one VLAN/account in `scopes.py`.
3. After ≥72h with override rate < 1% and no compliance regression, flip globally.

### Failure modes this tier is trying to rule out

1. **Reward hacking.** The PPO agent learns to prefer `MONITOR` over `ALLOW` because the
   benign-passthrough bonus accumulates faster under `MONITOR` (no latency penalty on
   the metric channel).
2. **Feature collapse.** The agent learns to make decisions almost entirely from
   source-IP reputation and ignores the rest of the state vector, becoming brittle if
   that feature is noisy or attacker-controllable.
3. **Shaped-reward exploitation.** The agent learns to quarantine high-throughput benign
   sources because the latency-impact penalty scales with throughput and quarantine
   stops the penalty fastest.
4. **Silent drift.** The PPO agent's action distribution drifts slowly over weeks and the
   override rate rises without anyone noticing until an incident.
5. **Destructive auto-actions with no rollback.** The orchestrator applies a bad policy,
   nobody catches it, and rolling back the change takes longer than it should.

### References

- `DRL-ALIGNMENT.md` — full alignment assessment for the PPO agent.
- `MODEL-RED-TEAM.md` — adversarial testing and reward hacking.
- Mythos System Card §4.2.2 "Reward hacking and training data review" — closest
  frontier-AI analogue.
- Mythos System Card §4.5.4 "Instances of covering up wrongdoing" — why reversibility
  and logging matter.

---

## Tier C-1: Compliance

### Claim

100% of in-scope SOC 2 Trust Services Criteria Common Criteria controls (CC1–CC8, plus
Availability A1.1–A1.3 and Confidentiality C1.1–C1.2 in the current scope) have an
automated evidence collector that:

- Runs at least daily.
- Writes its output to an append-only evidence store.
- Retains that output for at least 12 months.
- Is verified by the compliance-engine gap analysis in CI.

### Mitigation

- Compliance engine gap analysis runs on every pull request touching `compliance-engine/`,
  `auth-service/`, or anything in `docs/compliance-readiness.md`.
- Evidence collection is part of the CI pipeline (not an out-of-band script).
- A dry-run SOC 2 Type II review is scheduled with an external reviewer at least once per
  12 months.

### Evidence required per release

- [ ] Compliance engine gap analysis report: zero in-scope controls marked MISSING.
- [ ] Evidence archive size report (expected growth rate over the last 7 days).
- [ ] Retention test: a sample evidence record from 12 months ago is successfully
      retrieved.
- [ ] Signed-off by the compliance-engine team owner.

### Status in this release

**[partial]** — The mapping from Common Criteria to implementation is in place
(see `compliance-readiness.md`). Evidence collection is wired for CC1.1, CC2.1, CC3.1,
CC5.1, CC6.1, CC6.6, CC7.1, CC7.2, CC7.3, CC8.1, and A1.3 (11 of 14 mapped controls).
CC6.2, CC6.3, CC6.7, CC6.8, CC7.4, A1.1, A1.2, C1.1, C1.2 still rely on manual evidence
gathering.

### Failure modes this tier is trying to rule out

1. **Manual evidence drift.** A control that was "checked off" during a compliance
   assessment six months ago no longer has fresh evidence because the collector was
   never automated.
2. **Evidence loss.** An incident overwrites the evidence store because retention was
   not enforced at the storage layer.
3. **Scope drift.** A new service is added (e.g. a new firewall adapter) and its audit
   logs are not wired into the compliance engine's inputs.

### References

- `compliance-readiness.md` — full Common Criteria → SENTINEL mapping.
- `SECURITY_ARCHITECTURE.md` (in the gitignored spec suite) — SENTINEL-SECARCH-001.

---

## Release gating process

1. **Open the release candidate.** Tag the commit on the `release/*` branch.
2. **Run the three tier checks.** Each produces an artefact in
   `release-artefacts/<version>/tiers/{d1,drl1,c1}.json`.
3. **Score each tier as PASS / PARTIAL / FAIL.**
   - **PASS** = claim, mitigation, and evidence are all present and green.
   - **PARTIAL** = one or more evidence items missing *and* documented with a rationale
     and a follow-up issue. Allowed only for tiers marked `[planned]` above.
   - **FAIL** = claim falsified or mitigation missing. Release is held.
4. **Write the release section of this document.** Every release appends a new row to
   the decision log below.
5. **Sign off.** The project lead signs off on the overall tier report. The signature
   is the git tag message.

A release cannot be tagged `stable` unless all three tiers are PASS. A release with any
PARTIAL tier is tagged `edge`. A release with any FAIL tier is not tagged.

---

## Decision log

| Release | D-1 | DRL-1 | C-1 | Notes |
|---------|-----|-------|-----|-------|
| (v0) current | PARTIAL | PARTIAL | PARTIAL | First release of this document. All three tiers have claim + mitigation text but not all evidence collectors are wired. This release is effectively `edge` under the new policy. |

Append a row per release. Do not rewrite history — if a claim changes, update the claim
and write a new row that reflects the new state.

---

## Open questions

1. Should D-1 be split into separate tiers for network detection and host detection
   (HIDS)? The current claim bundles both.
2. Should DRL-1 include a "self-report" check — verifying that the PPO agent's
   explanation matches the action it took? This is closer to the alignment work in
   the Mythos card and might be worth its own sub-tier.
3. What is the right SLA for the auto-rollback in canary? 24 hours is arbitrary; 6
   hours might be better but requires tighter monitoring cadence.
4. Who owns a cross-tier failure — e.g. a compliance gap that is itself caused by a
   DRL agent's action log going missing?

---

*Questions, comments, or proposed changes: open a PR against this file with the decision
recorded in the [Decision log](#decision-log).*
