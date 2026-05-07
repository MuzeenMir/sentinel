# SENTINEL Contamination Policy

*Status: v0.1 — initial draft, April 10, 2026*
*Owner: ai-engine team*
*Review cadence: per retraining run*

---

## Purpose

This document describes SENTINEL's rules for keeping training and evaluation data
separate, and for ensuring that operator feedback flowing back into the training pipeline
does not silently contaminate the metrics we use to make release decisions.

The document is modelled on the Claude Mythos Preview System Card §6.2 ("Contamination"),
which spends several pages worrying about whether benchmark answers leaked into the
model's training corpus and describes an auditor-based detection scheme. SENTINEL's
situation is different — our "benchmarks" are network flows, not exam questions — but the
underlying concern is identical: **if the thing you evaluate against is not held out from
the thing you train on, your metrics are lying to you.**

---

## Table of Contents

- [What we mean by contamination](#what-we-mean-by-contamination)
- [Rules](#rules)
- [The feedback loop](#the-feedback-loop)
- [Detection methods](#detection-methods)
- [What to do when contamination is found](#what-to-do-when-contamination-is-found)
- [Status](#status)

---

## What we mean by contamination

Three distinct failure modes, in increasing order of subtlety:

1. **Direct overlap.** A flow appears in both the training set and the evaluation set.
   This inflates every metric.
2. **Family overlap.** The training set and the evaluation set share flows from the
   same session, same host pair, or same attack campaign, even if the individual
   packets differ. The model memorises the session-level fingerprint rather than the
   generalisable features.
3. **Feedback contamination.** Operator labels submitted via `/api/v1/feedback` flow
   back into the training set *and* into the evaluation set. The model is implicitly
   trained on the test it is about to be graded on.

All three are realistic for SENTINEL, and the third is the one that a naive retraining
pipeline will introduce by accident.

---

## Rules

### Rule 1 — Deterministic split by session ID

Every raw event in the ingestion pipeline has a `session_id` derived from the 5-tuple
`(src_ip, src_port, dst_ip, dst_port, protocol)` + a time bucket. The session ID is
the unit of the train/eval split.

- Training set: sessions whose `hash(session_id) mod 10 < 8`.
- Validation set: sessions whose `hash(session_id) mod 10 == 8`.
- Held-out evaluation set: sessions whose `hash(session_id) mod 10 == 9`.

The hash is a stable HMAC with a project-wide secret; the secret is rotated only with a
formal release-note entry.

**Why session-level and not flow-level:** a single session can contain dozens of flows
that share strong features (user agent, TCP fingerprint, timing signature). Splitting at
the flow level leaks.

### Rule 2 — Temporal holdout for drift evaluation

In addition to the session-based split, we maintain a rolling **temporal holdout**: the
most recent 7 days of traffic are always excluded from training. This is used to measure
drift — if the model's F1 on the last-7-days traffic falls relative to the older
validation set, that is evidence of distribution shift rather than a training bug.

### Rule 3 — Public-benchmark decontamination

For public datasets (CIC-IDS2017, UNSW-NB15, CTU-13, …), we record the flow hashes of
every sample at ingestion time and grep the training corpus for exact matches. Any
match is removed from the training set, not the evaluation set. This is a small but
meaningful safety margin: we would rather lose a small amount of training data than
corrupt a metric.

### Rule 4 — Adversarial set isolation

The adversarial evaluation set produced by `MODEL-RED-TEAM.md` (RT-1 through RT-4) is
*never* used for training. It is stored under `tests/red_team/eval-sets/` and has a
read-only permission bit enforced by CI.

### Rule 5 — No training on operator overrides from the current release window

An operator who overrides a PPO action in the admin console is labelling that flow.
That label is valuable — but if it flows directly back into the training set and then
the model is retrained and re-evaluated against a set that also contains it, the
evaluation is contaminated.

The rule is: operator labels collected in the current release window are held in a
quarantine buffer (`feedback-quarantine` Kafka topic) and are not promoted to the
training corpus until the release window closes. When the window closes, the quarantine
buffer is split using Rule 1 and merged.

### Rule 6 — Synthetic data isolation

Any synthetic traffic generated for training (e.g. PPO rollouts, GAN-generated
adversarial flows) is tagged at generation time and is excluded from every evaluation
set by default. Synthetic samples can be opted into a specific evaluation set only via
a documented flag in the evaluator config.

---

## The feedback loop

The `/api/v1/feedback` endpoint is SENTINEL's primary retraining signal. The feedback
loop is:

```
operator action
    │
    ▼
feedback-quarantine Kafka topic  ◀── held for current release window
    │
    ▼  (release window closes)
session-split ──► training / validation / held-out sets
    │
    ▼
retraining pipeline
    │
    ▼
candidate model
    │
    ▼
red-team suite + held-out evaluation
    │
    ▼
promotion decision (Tier D-1, Tier DRL-1)
```

Two guardrails on the loop:

1. **No direct promotion.** The retraining pipeline cannot write a model artefact to
   `/models/<detector>/` without first passing the red-team suite and the held-out
   evaluation.
2. **Label quality audit.** A random 1% sample of operator overrides is reviewed by
   the ai-engine team before the sample is promoted from quarantine to training. This
   catches labelling mistakes and malicious labelling before they contaminate the
   training corpus.

---

## Detection methods

Even with the rules above, we assume contamination will still happen and we build
detectors to catch it.

### Detector 1 — Session ID duplicate check

At the start of every retraining run, verify that no `session_id` appears in more than
one of train / validation / held-out. Fail loudly if it does.

### Detector 2 — Memorisation probe

Modelled on the Mythos auditor approach (Mythos §6.2.1): train a light-weight
classifier that takes the detector's raw output on a held-out sample and tries to
predict whether the sample was in the training set. If the classifier's AUC is
meaningfully above 0.5, the detector is memorising and the training corpus is
overlapping the held-out set.

**Status:** **[planned]**.

### Detector 3 — Held-out vs temporal-holdout gap

Compare the detector's F1 on the session-based held-out set against its F1 on the
7-day temporal holdout. A large gap (held-out much higher than temporal) is a
contamination fingerprint — the model is doing better on the session-held-out set
because that set is from the same distribution as training, while the temporal holdout
is from a genuinely newer distribution.

**Status:** **[partial]** — metrics exist per split; the comparison is not yet
computed automatically.

### Detector 4 — Feedback quarantine audit

At release time, verify that no sample in the evaluation set has a `source=feedback`
tag from the current release window. This is a simple filter check that catches the
most common accidental contamination.

**Status:** **[planned]**.

---

## What to do when contamination is found

If any detector fires:

1. **Stop the release.** Contamination invalidates metrics, which means the release gate
   in `RISK-TIERS.md` cannot be trusted.
2. **Identify the scope.** Which detector? Which split? How many samples?
3. **Rebuild the affected split.** Remove the contaminating samples, re-run the session
   hash to rebalance, and re-run the evaluation.
4. **Post-mortem.** Write up the finding as a release-notes entry under "contamination
   events" and file a follow-up issue for the specific rule that failed.
5. **Do not quietly patch and continue.** Contamination is a process failure, not a
   code bug. The goal of writing it up is to catch the next one faster.

---

## Status

| Rule / detector | Status |
|-----------------|--------|
| Rule 1 (session-level split) | **[partial]** — logic exists in `training/split.py`; not yet the single source of truth across all detectors |
| Rule 2 (7-day temporal holdout) | **[planned]** |
| Rule 3 (public-benchmark decontamination) | **[planned]** |
| Rule 4 (adversarial set isolation) | **[planned]** |
| Rule 5 (quarantine feedback) | **[planned]** |
| Rule 6 (synthetic isolation) | **[planned]** |
| Detector 1 (session ID duplicate) | **[planned]** |
| Detector 2 (memorisation probe) | **[planned]** |
| Detector 3 (held-out vs temporal gap) | **[partial]** |
| Detector 4 (feedback quarantine audit) | **[planned]** |

---

## References

- `RISK-TIERS.md` — D-1 tier requires uncontaminated evaluation.
- `MODEL-RED-TEAM.md` — RT-8 (drift) depends on the temporal holdout defined here.
- `ml-models.md` — per-detector training data requirements.
- Mythos System Card §6.2 — "Contamination": the closest frontier-AI analogue to this
  document and the inspiration for the auditor-based detection scheme in Detector 2.
- Mythos System Card §6.2.1 — SWE-bench memorisation filter.
