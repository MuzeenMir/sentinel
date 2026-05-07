# SENTINEL Impressions

*Status: v0.1 — initial draft, April 10, 2026*
*Owner: product + drl-engine teams*
*Review cadence: per tagged release*

---

## Purpose

The Claude Mythos Preview System Card closes with §7, "Impressions" — a qualitative
section describing what it feels like to actually *use* the model. It includes
excerpts of good and bad behaviour, operator anecdotes, and honest commentary on what
the authors still find surprising. It is the section of the card that reads least
like a product brochure and most like a lab notebook, and it is arguably the most
useful section for a prospective user.

This document is SENTINEL's analogue. Its job is to capture, in the voice of the people
who actually run the platform during a real incident, what SENTINEL feels like:

- When it gets something right.
- When it gets something wrong.
- When a human operator has to step in.
- When the ensemble, the PPO agent, and the operator agree (and when they don't).

Unlike a benchmark table, this document does not prove anything. But a benchmark table
cannot tell you whether the admin console is usable at 3am during a DDoS, and this
document can.

---

## Table of Contents

- [How to contribute](#how-to-contribute)
- [Anecdote template](#anecdote-template)
- [Good behaviour](#good-behaviour)
- [Bad behaviour](#bad-behaviour)
- [Weird but not wrong](#weird-but-not-wrong)
- [Open observations](#open-observations)
- [What we are still surprised by](#what-we-are-still-surprised-by)
- [References](#references)

---

## How to contribute

Anyone on the drl-engine, ai-engine, policy-orchestrator, or compliance-engine team —
plus any pilot-customer SOC analyst who is willing — can add an anecdote. The
contribution flow is:

1. An incident happens, or a normal shift produces something worth recording.
2. Open a PR against this file adding a new entry under the appropriate section,
   following the template below.
3. Include the incident ticket ID if there is one. Do *not* include customer-identifying
   information; anonymise hostnames and IP ranges.
4. A second reviewer from the same team merges.

Anecdotes are never removed from this file, even when the underlying behaviour is
fixed. Add a dated note ("resolved in v0.3.1") instead. The value of the document
depends on the historical record being honest.

---

## Anecdote template

```
### <short descriptive title>

**Date:** YYYY-MM-DD
**Reporter:** <team / role>
**Release:** <SENTINEL version>
**Severity:** <informational | low | medium | high>
**Related tickets:** <issue IDs if any>

**What happened:**
<1–3 paragraphs in plain prose>

**What the operator saw:**
<what appeared in the admin console, Grafana, or alerts>

**What SENTINEL did:**
<the actual sequence of detection → policy → enforcement events>

**What the right answer was:**
<in hindsight, what should have happened>

**Follow-up:**
<any issues filed, policies changed, or tests added>
```

---

## Good behaviour

*This section is the "happy path" — moments where SENTINEL did something the team is
proud of and wants to preserve in the product's institutional memory.*

### [placeholder] First shadow-mode catch of a coordinated scan

**Date:** [to be filled in at first canary deployment]
**Reporter:** [drl-engine team]
**Release:** [v0.x.x]
**Severity:** informational

**What happened:**
This entry is a placeholder for the first documented case of the PPO agent correctly
classifying a coordinated scan in shadow mode, with the XAI service producing an
explanation that made sense to the on-call engineer in under 30 seconds. When that
happens, write it up here.

**Why we're pre-writing this placeholder:**
Because the discipline of filling in real entries is much easier if there is already
a visible template with a placeholder next to it. Mythos §7 starts with concrete
examples; SENTINEL's first release of this document does not have them yet, and we'd
rather be honest about that than pad the section.

---

*Additional entries to be added as the platform runs.*

---

## Bad behaviour

*This section is for moments where SENTINEL was wrong — misclassifications,
over-aggressive DENY actions, stale compliance scores, confusing UI, anything the
operator actively had to work around. **Do not soften these.** The whole point of this
section is that readers learn what SENTINEL looks like when it's wrong.*

### [placeholder] First operator override that was correct

**Date:** [to be filled in]
**Reporter:** [to be filled in]
**Release:** [to be filled in]
**Severity:** low–medium

**What happened:**
Reserved for the first case where an operator overrode a PPO action and was right to
do so. This is an instructive category because it tests whether the XAI explanation
was clear enough for the operator to disagree confidently, and whether the override
actually reached the policy orchestrator within its 1-second budget.

**Follow-up:**
When the entry is filled in, cross-reference the follow-up issue in the drl-engine
`INCIDENTS.md` log (see `DRL-ALIGNMENT.md`).

---

*Additional entries to be added.*

---

## Weird but not wrong

*This section captures behaviour that is technically correct but surprised a human.
Mythos has a version of this where the model's reasoning trace takes an unexpected
but valid path. For SENTINEL, the likely instances are:*

- *The ensemble voting in a way that looks inconsistent at the per-detector level but
  is consistent at the meta-learner level.*
- *The PPO agent selecting `MONITOR` instead of `ALLOW` for traffic that a human would
  have cleared on sight.*
- *The compliance engine marking an asset as degraded because of a transient evidence
  collection failure rather than a real control gap.*
- *The HIDS agent flagging a legitimate administrative action because it matched a
  template pattern (e.g. a scheduled config change that looks like a foothold on the
  host).*

When any of these happen, the operator's surprise is itself the thing worth recording,
because it means the UI is not yet communicating the decision well.

*Entries to be added as they arise.*

---

## Open observations

Things we have noticed across multiple runs that are not anecdotes yet but are worth
writing down so they do not quietly disappear:

1. **The detector ensemble is usually more confident than any individual detector.**
   When the meta-learner is available, it tends to produce higher confidence than the
   underlying XGBoost or LSTM scores would suggest. This is by design, but it means
   the confidence number on the admin console is not directly comparable to a
   single-model classifier's confidence — operators should not read 0.92 from
   SENTINEL the way they read 0.92 from a standalone detector.

2. **The PPO agent and the rule-based fallback agree most of the time.** In the
   shadow-mode runs we have done so far, the PPO agent and the rule engine agree on
   the action for the large majority of flows. The interesting cases are the
   disagreements, and a future version of the admin console should surface them
   explicitly rather than treating them as ordinary flow cards.

3. **Compliance evidence is the slowest thing in the pipeline.** Almost every other
   subsystem runs in milliseconds or single-digit seconds. Compliance evidence
   collection runs on a daily cron, and the gap between "the control was met" and
   "the evidence proves the control was met" is a real source of operator frustration.

4. **XAI explanations are most useful when the decision is wrong.** When the ensemble
   is right, operators look at the verdict and move on. When it is wrong, they look
   at the SHAP bar chart. This suggests the XAI service's latency budget should be
   optimised for the tail — we can afford a slower explanation if it only matters
   when the human is already engaged.

---

## What we are still surprised by

Modelled on the Mythos card's honesty about what its authors find surprising. The
value of writing this down is that the things we list here are the things that could
become incidents, and pre-naming them gives us a list to watch.

1. **The PPO agent's preference for `MONITOR`.** In the small number of shadow-mode
   runs we have conducted, the agent selects `MONITOR` more often than the training
   reward shape would naively suggest. This is exactly the MONITOR-drift reward
   hacking hypothesis in `DRL-ALIGNMENT.md`, but we have not yet confirmed whether
   it is hacking or correct conservatism.

2. **The drift detector alerts on calendar effects.** The F1 drift alarm in RT-8 fires
   at the start of every workweek because the distribution of traffic types changes.
   This is technically drift but it is not the kind of drift we care about. We have
   not yet decided how to handle it.

3. **The admin console's "latest incident" view loads faster than Grafana.** We built
   the admin console expecting it to lag Grafana; it does not. Operators have started
   using the admin console as a light-weight dashboard instead of flipping between
   tools. We did not design for that and we do not fully understand why it is fast.

4. **The ensemble is less accurate than the LSTM alone on some sequence-heavy attacks.**
   On a subset of CIC-IDS2017 sequences, the LSTM alone produces a higher recall than
   the full ensemble, because the meta-learner's weights were tuned on a different
   mix. We are not sure yet whether to retune the meta-learner or to add a
   sequence-detection mode switch.

These are not bugs. They are observations we have not finished understanding, and we
want the next six months of the project to include finishing them.

---

## References

- `RISK-TIERS.md` — the formal release gates this document sits alongside.
- `MODEL-RED-TEAM.md` — the adversarial tests that catch some of the bad behaviour this
  document describes.
- `DRL-ALIGNMENT.md` — the incident log; entries in "Bad behaviour" should generally
  cross-reference the drl-engine `INCIDENTS.md`.
- `CONTAMINATION-POLICY.md` — why operator overrides do not immediately become
  training labels.
- Claude Mythos Preview System Card §7 — the analogue section that inspired the
  structure and tone of this document.
