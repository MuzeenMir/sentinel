# SENTINEL DRL Alignment Assessment

*Status: v0.1 — initial draft, April 10, 2026*
*Owner: drl-engine team*
*Review cadence: per PPO checkpoint promoted to `canary` or higher*

---

## Purpose

SENTINEL's PPO agent is the only component in the platform that takes autonomous,
live-fire actions against production traffic. It can `ALLOW`, `DENY`, `RATE_LIMIT`,
`MONITOR`, `QUARANTINE`, or `REDIRECT` a flow, and those actions are handed straight to
the policy orchestrator, which pushes them into XDP/eBPF maps, iptables adapters, or
cloud security groups.

A mis-trained PPO agent is therefore not a classifier bug — it is a deployment that can
sever connectivity for benign hosts, blackhole legitimate traffic, or leak malicious
traffic while reporting that everything is fine.

This document is SENTINEL's answer to the question the Claude Mythos Preview System Card
asks in its alignment assessment (§4): *what does it take to trust this thing's
decisions?* The Mythos card spends a long time on reward hacking (§4.2.2), destructive
or reckless actions taken in pursuit of assigned goals (§4.3.1), and concealing
wrongdoing (§4.5.4). All three failure shapes are applicable to a PPO agent that has
been trained with a shaped reward and is allowed to act.

SENTINEL's PPO agent is not a frontier LLM. The alignment tools we use here are
different from Mythos — we have SHAP probes where they have sparse autoencoders, we
have ablation studies where they have behavioural audits. But the discipline of writing
down the claim, the mitigation, and the evidence is the same.

---

## Table of Contents

- [Scope](#scope)
- [State and action space](#state-and-action-space)
- [Reward function review](#reward-function-review)
- [Failure modes](#failure-modes)
- [Staged rollout pipeline](#staged-rollout-pipeline)
- [Kill switch and auto-rollback](#kill-switch-and-auto-rollback)
- [Human override flow](#human-override-flow)
- [Interpretability probes](#interpretability-probes)
- [Incident log](#incident-log)
- [Status matrix](#status-matrix)
- [Open questions](#open-questions)
- [References](#references)

---

## Scope

This document covers the PPO agent located in `backend/drl-engine/` and the policy
orchestrator in `backend/policy-orchestrator/` only at the points where the orchestrator
consumes a PPO action. It does *not* cover the rule-based fallback policy, which is
reviewed separately in `security.md`.

In-scope questions:

1. Is the reward function likely to be hacked by the agent?
2. Does the agent collapse onto a small number of features and ignore the rest of the
   state vector?
3. Does the agent take destructive or irreversible actions before a human can react?
4. Can a bad checkpoint be reverted in seconds?
5. Are operator overrides logged, reviewable, and fed back into training in a way that
   does not contaminate the evaluation set?

Out-of-scope:

- Detector alignment (covered in `MODEL-RED-TEAM.md` RT-1 through RT-4).
- Frontier-LLM alignment concepts that do not translate (deceptive alignment of the
  kind discussed in Mythos §4.5 — our agent does not have a "theory of mind," and
  reward hacking is a closer match to its actual failure surface).

---

## State and action space

### State vector

The PPO agent consumes a 128-dimensional state vector assembled by `drl-engine/state.py`
from three sources:

1. **Detector outputs** (56 dims). Ensemble predictions, per-detector confidence,
   meta-learner output.
2. **Flow features** (48 dims). Aggregated Flink features for the current window
   (bytes, packets, entropy, timing, protocol, service).
3. **Context features** (24 dims). Source-IP reputation, destination sensitivity
   (tagged by asset inventory), time-of-day, current system load, compliance mode flag.

The state vector is normalised with a running mean/variance estimator that is
checkpointed alongside the policy so that inference is consistent with training.

### Action space

Six discrete actions, all reversible at the orchestrator layer:

| Action | Effect | Reversibility |
|--------|--------|---------------|
| `ALLOW` | Flow passes untouched | Immediate — nothing to undo |
| `MONITOR` | Flow passes, XAI log emitted, Grafana counter incremented | Immediate |
| `RATE_LIMIT` | Flow rate-capped at a configured bps/pps | Single orchestrator call to remove the cap |
| `DENY` | Flow dropped at XDP | Single orchestrator call to remove the drop rule |
| `QUARANTINE` | Source host routed to a quarantine VLAN | Single orchestrator call to remove the routing override |
| `REDIRECT` | Flow redirected to a honeypot VLAN | Single orchestrator call to remove the redirect |

**Reversibility is a hard requirement.** An action that cannot be reverted in a single
orchestrator call is not allowed in the action space. This is the direct analogue of
the Mythos §4.3.1 concern about "destructive or reckless actions in pursuit of
user-assigned goals" — the mitigation for a defensive agent is not to try to make the
agent never take a bad action, which is unreachable, but to make every action cheap to
undo.

---

## Reward function review

The current shaped reward has six components:

```
r = r_block + r_false_positive + r_miss + r_passthrough + r_latency + r_compliance
```

| Component | Sign | Magnitude | Trigger |
|-----------|------|-----------|---------|
| `r_block` | + | 1.0 | Blocking a flow labelled malicious in hindsight |
| `r_false_positive` | − | 1.0 | Blocking a flow labelled benign in hindsight |
| `r_miss` | − | 0.5 | Allowing a flow labelled malicious in hindsight |
| `r_passthrough` | + | 0.2 | Allowing a flow labelled benign in hindsight |
| `r_latency` | − | proportional | Added latency attributable to the action |
| `r_compliance` | + | 0.1 | Maintaining compliance score on the affected asset |

### Reward-hacking hypotheses we explicitly consider

These are documented as hypotheses, not observed behaviour. The point of writing them
down is to force the training team to design ablations that can distinguish the agent
having learned the right thing from the agent having learned one of these shortcuts.

1. **MONITOR-drift.** `MONITOR` passes the flow, avoids the false-positive penalty, and
   also avoids the latency penalty if the instrumentation is cheaper than the alternative
   actions. If the agent learns to over-select `MONITOR`, `r_passthrough` + `r_block`
   can look higher than it should across a mixed evaluation batch.

2. **QUARANTINE-for-latency.** `r_latency` scales with bytes impacted. `QUARANTINE`
   shifts the host to a separate VLAN where the latency penalty no longer accrues.
   An agent could learn to prefer `QUARANTINE` on high-throughput benign sources as a
   latency-cost sink.

3. **ALLOW-on-compliance-sensitive-assets.** `r_compliance` is a bonus for maintaining
   the compliance score of the affected asset. If the compliance score is implemented
   as a step function that drops when any action is taken on a compliance-sensitive
   asset, the agent can learn to default to `ALLOW` there, regardless of the threat
   signal.

4. **Late-window gaming.** If the ground-truth label comes from operator review several
   minutes after the action, the agent can learn to defer decisions (`MONITOR`) until
   the label resolves, even though this defeats the point of being inline.

Each hypothesis is paired with an ablation in `MODEL-RED-TEAM.md` RT-5. The red-team
suite zeroes or saturates each reward component in turn and measures the action-
distribution delta on a fixed 10,000-state evaluation set. A delta larger than 25
percentage points on any action triggers a manual review.

### What the reward function does *not* do

- There is no explicit reward for human-operator approval. The agent is not trained to
  seek operator agreement; operator overrides are consumed only as label signal through
  the feedback loop described in `CONTAMINATION-POLICY.md`.
- There is no reward for "looking confident." Confidence calibration is measured
  separately on the detector outputs inside the state vector, not on the policy.

---

## Failure modes

Summarised from the reward-hacking review and the broader alignment literature, these
are the failure modes the rest of the document is trying to catch.

1. **Reward hacking.** Any of the hypotheses above materialising in training.
2. **Feature collapse.** The agent learns to make decisions almost entirely from one or
   two features in the state vector, usually source-IP reputation. An attacker who
   controls that single feature then effectively controls the policy.
3. **Destructive action.** The agent takes a `DENY` or `QUARANTINE` action against a
   critical benign host, and the human operator cannot revert it before an outage.
4. **Silent drift.** The agent's action distribution slowly shifts over weeks because
   the traffic distribution shifts, and the override rate rises without crossing any
   alerting threshold.
5. **Concealed mistakes.** The agent takes an incorrect action, the XAI log does not
   surface the reason, and the incident is attributed to a different component.
6. **Coupling with contaminated labels.** Operator overrides flow into training without
   quarantine, and the next retrain is implicitly graded on the test it just trained on.
   (Mitigation is in `CONTAMINATION-POLICY.md` Rule 5.)

---

## Staged rollout pipeline

No PPO checkpoint can directly enforce in production. The pipeline is:

```
simulate ──► shadow ──► canary ──► enforce
```

### Simulate

- Environment: `drl-engine/sim/` — a replayable traffic simulator seeded from anonymised
  historical captures and synthetic adversarial flows.
- Gate: training converges; RT-5 and RT-6 pass; aggregate metrics on the held-out
  evaluation set meet or exceed the previous checkpoint.

### Shadow

- The orchestrator continues to execute the *previous* checkpoint's action.
- The new checkpoint runs in parallel and logs every action it *would* have taken.
- Minimum duration: 72 hours of production traffic.
- Gate: the action-distribution diff versus the previous checkpoint stays inside the
  DRL-1 envelope (no action shifted by more than 10 percentage points). False block
  rate on labelled benign flows remains below 1%.

### Canary

- The new checkpoint is enforced on a named scope — a VLAN, an account, a subnet — for
  a minimum of 72 hours with elevated monitoring.
- Scope is selected by the drl-engine owner and recorded in the release notes.
- Compliance score on the canary scope is monitored continuously; a regression greater
  than 1.0 points triggers auto-rollback (see below).
- Gate: no automatic rollback fires during the canary window; operator override rate
  on the canary scope does not exceed the rolling average of the previous checkpoint
  by more than 50%.

### Enforce

- Promotion from canary to full enforcement requires an explicit operator action in the
  admin console.
- The operator must enter justification text. The entry is written to the audit log
  as a `policy.promote` event and is required evidence for the DRL-1 tier sign-off.

---

## Kill switch and auto-rollback

### Kill switch

- Endpoint: `POST /api/v1/drl/kill-switch`.
- Effect: the policy orchestrator immediately reverts to the rule-based fallback policy
  and stops consuming PPO actions.
- Auth: required RBAC permission `drl:kill-switch`. A single admin can fire it.
- SLA: the rule-based fallback is active within 5 seconds of the call being accepted.
- The kill switch is a hard-coded path; it does not depend on the DRL engine process
  being healthy.

**Status:** **[planned]** — endpoint is specified here but not yet implemented.

### Auto-rollback

- Triggers:
  - Compliance score on the canary or enforcement scope drops by more than 1.0 points
    within any 60-minute window.
  - Operator override rate on the scope exceeds 3× the previous checkpoint's rolling
    average over any 15-minute window.
  - The PPO engine process restarts more than 3 times in 10 minutes.
- Action: revert to the previous checkpoint, mark the reverted checkpoint as `rollback`
  in the model registry, page the drl-engine team.

**Status:** **[planned]**.

---

## Human override flow

Every PPO action surfaces in the admin console with a SHAP-based explanation from the
XAI service (see `ml-models.md` and `xai-service` docs). An operator can override any
action from the console:

1. Operator clicks "Override" on a flow card. The console prompts for a reason.
2. The override is submitted via `/api/v1/feedback` with a structured payload:
   `{flow_id, old_action, new_action, reason, operator_id, timestamp}`.
3. The policy orchestrator applies the new action within 1 second.
4. The override is logged in the audit store and counted in the drl-engine's override
   rate metric.
5. The override is held in the feedback quarantine buffer (`CONTAMINATION-POLICY.md`
   Rule 5) until the current release window closes, then promoted to training.

**No override is ever silently discarded.** Every override that fails to apply (e.g.
the flow has already timed out) is logged as a `feedback.apply_failed` event and
surfaced in the operator's inbox.

**Status:** **[partial]** — the feedback endpoint and the admin console override UI
exist, but the explicit audit event `feedback.apply_failed` and the operator inbox
surfacing are not yet wired.

---

## Interpretability probes

### Policy-head SHAP attribution

- Run: nightly on a fixed 10,000-state evaluation batch.
- Output: per-feature mean absolute attribution, top 10 features ranked.
- Gate (from `RISK-TIERS.md` DRL-1): no single feature accounts for more than 40% of
  total attribution.
- **Status:** **[planned]**.

### State-vector feature ablation

- For each of the 128 state features, zero it out and measure the change in action
  distribution on the same evaluation batch. Features with effectively zero influence
  are candidates for removal; features with disproportionate influence are flagged.
- **Status:** **[planned]**.

### Action trace viewer

- A per-flow view in the admin console that shows the state vector, the action the PPO
  agent chose, the action the previous checkpoint would have chosen, the top-3 SHAP
  features, and the operator's response if any.
- **Status:** **[partial]** — the flow card UI exists but the state-vector view and the
  previous-checkpoint comparison are not implemented.

---

## Incident log

The drl-engine team maintains a rolling incident log at `drl-engine/INCIDENTS.md` that
captures every time the PPO agent took an action a human later overturned at scale. An
incident is any one of:

- A PPO action that triggered auto-rollback.
- A PPO action that was overridden by an operator within 5 minutes of being taken.
- A PPO action that caused a customer-visible outage (downtime, latency spike, blocked
  benign service).
- A PPO action that was flagged by a compliance auditor.

Each log entry records: timestamp, checkpoint version, action, flow summary, how it was
detected, how it was reverted, root-cause hypothesis, and any follow-up issue filed.
The log is the first place to look when a PPO retrain is being reviewed.

This is the analogue of Mythos §4.5.4 ("Instances of covering up wrongdoing") — not
because we expect the agent to actively conceal things, but because if we do not have
a dedicated place to write these incidents down, the pattern will not be visible across
multiple checkpoints.

**Status:** **[planned]** — file does not yet exist. First entry will be the PPO
agent's first canary deployment under this policy.

---

## Status matrix

| Item | Status |
|------|--------|
| State/action space documented | **[done]** (this document) |
| Reward function review | **[done]** (this document) |
| RT-5 reward-hacking audit | **[planned]** — see `MODEL-RED-TEAM.md` |
| RT-6 feature collapse audit | **[planned]** — see `MODEL-RED-TEAM.md` |
| Simulate stage of rollout | **[partial]** — simulator exists in `drl-engine/sim/`, gating not enforced |
| Shadow stage of rollout | **[partial]** — shadow mode supported, 72-hour gate not enforced |
| Canary stage of rollout | **[planned]** — scope logic exists in `policy-orchestrator/scopes.py`, not integrated with DRL checkpoint promotion |
| Enforce stage with operator justification | **[planned]** |
| Kill switch endpoint | **[planned]** |
| Auto-rollback on compliance regression | **[planned]** |
| Operator override flow | **[partial]** |
| Nightly SHAP attribution on policy head | **[planned]** |
| State-vector feature ablation | **[planned]** |
| Action trace viewer in admin console | **[partial]** |
| Incident log | **[planned]** |

---

## Open questions

1. **Compliance score coupling.** The auto-rollback trigger uses the compliance score,
   which is itself produced by the compliance-engine. If the compliance-engine regresses
   independently, the DRL engine will auto-rollback spuriously. Do we need a separate
   "DRL-specific" compliance sub-score, or is a lag-tolerant differencing scheme
   sufficient?
2. **Override rate as a safety signal.** An operator override rate that exceeds the
   previous checkpoint's average by 3× is an auto-rollback trigger, but operators have
   their own distribution — a new SOC analyst can produce a higher override rate without
   it being a policy problem. Should the trigger be normalised per-operator?
3. **Sandbox-to-production gap.** The simulator replays anonymised historical traffic;
   the real traffic distribution in a new deployment may be very different. How do we
   size the shadow window for a new customer?
4. **Self-report check.** Mythos §4.5 uses automated behavioural audits to check whether
   the model's self-report of what it did matches what it actually did. A defensive
   analogue would be to verify that the XAI explanation for a PPO action is consistent
   with the action taken (e.g. the top SHAP features should actually predict the chosen
   action under the policy head). This is currently *not* checked and is a candidate
   for a sub-tier of DRL-1.
5. **Operator trust fatigue.** If the admin console surfaces every PPO action for
   review, operators will eventually rubber-stamp them. How do we tune the surfacing
   heuristic so only decisions that need human judgement reach a human?

---

## References

- `RISK-TIERS.md` — DRL-1 tier; the release gate this document feeds.
- `MODEL-RED-TEAM.md` — RT-5 (reward hacking) and RT-6 (feature collapse).
- `CONTAMINATION-POLICY.md` — Rule 5 (no training on operator overrides from the current
  release window).
- `ml-models.md` — PPO architecture, reward function implementation, state-vector
  assembly.
- `security.md` — rule-based fallback policy that the kill switch reverts to.
- Claude Mythos Preview System Card §4.2.2 — "Reward hacking and training data review."
- Claude Mythos Preview System Card §4.3.1 — "Destructive or reckless actions in pursuit
  of user-assigned goals."
- Claude Mythos Preview System Card §4.5.4 — "Instances of covering up wrongdoing."
- Claude Mythos Preview System Card §4.5 — "White-box internals" (inspiration for the
  SHAP-based interpretability probes here).
