# SENTINEL External Testing Program

*Status: v0.1 — initial draft, April 10, 2026*
*Owner: project lead*
*Review cadence: quarterly*

---

## Purpose

Internal testing is necessary but not sufficient. The Claude Mythos Preview System Card
devotes an entire section (§1.1.5 and §2.3.7) to describing the external organisations
that stress-tested the model before release: METR on autonomy, Epoch AI on capability
benchmarks, Andon Labs on agentic behaviour, Eleos AI Research and a clinical
psychiatrist on welfare, and at least one government organisation on cyber uplift.
None of those programs produced the same kinds of findings Anthropic's internal team
produced. That is the point: external reviewers see blind spots that an internal team
shares.

SENTINEL is a defensive platform, not a frontier LLM, so its external testing program
looks different — but the discipline transfers directly. This document names the
categories of external reviewer SENTINEL should seek out, what each is supposed to
rule out, how engagements are structured, and what evidence is expected to feed back
into the release process.

A single internal team cannot simultaneously build a platform and credibly assess its
own security posture, adversarial robustness, operator ergonomics, and compliance
readiness. External review is how we close that loop.

---

## Table of Contents

- [Goals](#goals)
- [Reviewer categories](#reviewer-categories)
- [Engagement lifecycle](#engagement-lifecycle)
- [Scope and access control](#scope-and-access-control)
- [Deliverables we expect](#deliverables-we-expect)
- [Feeding findings back into releases](#feeding-findings-back-into-releases)
- [Status](#status)
- [Open questions](#open-questions)
- [References](#references)

---

## Goals

1. **Adversarial robustness.** Confirm that the ensemble and the PPO agent survive
   contact with an attacker who is not on the SENTINEL team.
2. **Operator ergonomics.** Confirm that a SOC analyst who has never seen SENTINEL
   before can run it during a simulated incident without coaching from us.
3. **Compliance defensibility.** Confirm that the SOC 2 evidence collectors and the
   Common Criteria mapping would survive a Type II auditor.
4. **Supply chain assurance.** Confirm that SENTINEL's dependency stack, container
   images, and infrastructure-as-code have no obvious high-severity issues that our
   own `bandit` / `pip-audit` / `trivy` runs missed.
5. **Independent perspective on the docs.** Confirm that this document, `RISK-TIERS.md`,
   `DRL-ALIGNMENT.md`, and `MODEL-RED-TEAM.md` are legible to an outside reader with a
   security background.

Each category of reviewer maps to one or two of these goals.

---

## Reviewer categories

### 1. Independent penetration testers

**Goal:** adversarial robustness; supply chain assurance.

**What we ask them to do:**

- Run a black-box pen test against a SENTINEL deployment, with knowledge of the
  architecture but no credentials beyond those a threat actor would plausibly obtain.
- Run a grey-box test against the admin console and API gateway using a low-privilege
  operator account.
- Run a white-box review of the authentication, authorisation, and session handling in
  `auth-service/`.

**Deliverables expected:** prioritised finding list (severity × exploitability),
reproduction steps, remediation recommendations.

**Cadence:** at least once per major release.

**Status:** **[planned]** — vendor selection not yet done; anticipated in
`compliance-readiness.md`.

### 2. Academic ML-security groups

**Goal:** adversarial robustness of the ML and DRL components, beyond what the
internal red-team suite in `MODEL-RED-TEAM.md` can produce.

**What we ask them to do:**

- Attempt evasion attacks against the detector ensemble using techniques more
  sophisticated than FGSM/HopSkipJump (transferable adversarial examples, black-box
  attacks using only the public API, query-efficient attacks).
- Attempt reward-hacking or adversarial-policy attacks against the PPO agent in the
  simulator.
- Probe the autoencoder's reconstruction loss for blind spots that the internal
  autoencoder-bypass red team (`MODEL-RED-TEAM.md` RT-3) did not catch.

**What we provide:** read access to model artefacts, a sandboxed simulator, a fixed
evaluation set, and a published set of questions we want them to answer.

**Deliverables expected:** a technical report with attack descriptions, success rates,
and suggested mitigations. Where findings are publishable, we support publication with
a reasonable disclosure window.

**Cadence:** per year, or per major architecture change to the ensemble.

**Status:** **[planned]** — no engagement started.

### 3. MSSP / SOC-analyst review

**Goal:** operator ergonomics, especially the admin console, XAI explanations, and
alert lifecycle.

**What we ask them to do:**

- Run through a scripted simulated incident in the admin console. The script includes
  a DDoS, a credential-stuffing attempt, and a lateral-movement HIDS alert.
- Complete without coaching from us, using only the documentation in `docs/`.
- Write up what worked, what didn't, and where they reached for a different tool.

**What we ask them *not* to do:** debug us. The goal is not to find code bugs; it is
to produce a usability report from someone whose instincts were shaped by running
other tools (Elastic Security, Wazuh, Splunk ES, SentinelOne, CrowdStrike Falcon).

**Deliverables expected:** short written report, recording of the session if they
consent, time-to-triage for each of the three scenarios.

**Cadence:** twice per year, or when the admin console sees a major redesign.

**Status:** **[planned]**.

### 4. Compliance auditors

**Goal:** compliance defensibility.

**What we ask them to do:**

- Conduct a dry-run SOC 2 Type II review against `compliance-readiness.md` and the
  evidence collectors.
- Identify controls where the collector output is insufficient (missing, stale,
  unclear provenance, retention shorter than policy).
- Identify controls that are claimed as "automated" in `compliance-readiness.md` but
  where a human still does the work.

**What we provide:** read access to the evidence archive, the compliance engine's gap
analysis output, and the Common Criteria mapping document.

**Deliverables expected:** a list of controls that would pass, fail, or receive a
qualification under a real audit. A recommendation on whether SENTINEL is ready for a
live Type II at the current release.

**Cadence:** at least once per 12 months, as required by `RISK-TIERS.md` C-1.

**Status:** **[planned]** — first scheduled engagement not yet confirmed.

### 5. Documentation review

**Goal:** legibility of the governance documents.

**What we ask them to do:**

- Read `RISK-TIERS.md`, `MODEL-RED-TEAM.md`, `CONTAMINATION-POLICY.md`,
  `DRL-ALIGNMENT.md`, `IMPRESSIONS.md`, and this file.
- Answer, in writing: what does SENTINEL claim about itself? Where is the strongest
  evidence for that claim? Where is the weakest?
- Flag any place where the documents contradict each other, or where a claim is made
  without an evidence path.

**Who does this:** a reviewer with a security engineering background who is not on
the SENTINEL team. Candidates include former frontier-AI safety reviewers, SOC
architects, and open-source security project maintainers.

**Cadence:** once per major release of the governance documents (i.e. when any of
them increments its major version).

**Status:** **[planned]**.

### 6. Host-hardening review (stretch)

**Goal:** adversarial robustness of the hardening-service and HIDS agent.

**What we ask them to do:**

- Review the hardening playbook against CIS Benchmarks and STIG.
- Attempt to bypass the HIDS agent's eBPF-based syscall instrumentation.
- Review the rollback path for hardening actions to confirm that reverting is as
  simple as the documentation claims.

**Cadence:** once, before the first stable release.

**Status:** **[planned]**.

---

## Engagement lifecycle

Every external engagement follows the same six steps:

1. **Scoping document.** We write a one-page brief naming the category, the goals,
   the access the reviewer will need, the data they can see, and the deliverables
   expected. The brief is signed by the project lead and the reviewer's lead.
2. **Access provisioning.** Any model artefact access is granted via a time-boxed
   read-only credential. Any access to production data is conducted on an anonymised
   snapshot. No reviewer ever gets write access to production.
3. **Kick-off.** A 30-minute call walks the reviewer through the architecture and
   answers first-round questions. After the kick-off, we do not actively guide the
   work — the reviewer runs on their own time.
4. **Mid-engagement check-in.** Optional. Used for engagements longer than 4 weeks.
5. **Draft report.** The reviewer submits a draft; we review for factual accuracy
   only, not for framing or severity. Findings we disagree with get a documented
   response rather than a redaction.
6. **Publication decision.** By default the report is internal. Academic findings are
   supported for publication after a coordinated disclosure window. Pen-test reports
   are internal-only.

---

## Scope and access control

The Mythos card's §1.1.5 explicitly says that some external testers had access to
"helpful-only" variants, some did not, and the difference mattered. SENTINEL's analogue
is the separation between:

- **Production-equivalent model artefacts.** Same weights as production, trained on
  the same data.
- **Clean-room artefacts.** Trained on a known-good, anonymised subset. Used when the
  reviewer is an academic group publishing a paper — we do not want to expose the
  production model's weights in a public paper.
- **Simulator-only access.** The reviewer can run the simulator but not touch model
  artefacts directly. Used for MSSP ergonomics reviews.

Every engagement's scoping document names which of these three modes applies, and the
choice is recorded in the status table below.

---

## Deliverables we expect

For each engagement, we commit to producing two artefacts ourselves:

1. **An engagement summary** written into the release notes, naming the reviewer, the
   category, the scope, and a one-paragraph summary of findings.
2. **A follow-up issue list** filed in the issue tracker, one issue per finding at
   severity medium or above. The issue references the reviewer's report and is
   assigned to the owning team.

For each engagement, we commit to *not* producing:

- A rewrite of the report to make it sound better.
- Any pressure on the reviewer to lower a severity rating.
- Any NDAs that prevent the reviewer from discussing the engagement in aggregate
  terms (e.g. "we found X high-severity findings") with other clients, beyond a
  reasonable coordinated-disclosure window.

---

## Feeding findings back into releases

External findings are the highest-priority input into the release process, because
they are the findings our internal team could not produce. The rule is:

- **Severity high or critical** blocks the next release until resolved or explicitly
  accepted with a justification entered into the `RISK-TIERS.md` decision log.
- **Severity medium** must have an owner and a target release by the next
  release-gate sign-off.
- **Severity low or informational** is filed as a tracked issue; no release-level
  consequence.

The same severity ladder applies whether the finding came from a pen tester, an
academic paper, or a documentation reviewer. Findings do not get downgraded because
they are "in the docs" rather than "in the code" — a misleading claim in `RISK-TIERS.md`
is a release-blocker for the same reason a misleading benchmark number would be.

---

## Status

| Engagement | Category | Scope mode | Status |
|------------|----------|-----------|--------|
| Initial pen test | Pen testers | Production-equivalent | **[planned]** — vendor selection |
| First academic ML-security review | Academic | Clean-room artefacts | **[planned]** — outreach not yet started |
| First MSSP ergonomics review | MSSP / SOC | Simulator-only | **[planned]** |
| First SOC 2 Type II dry-run | Compliance | Evidence archive read-only | **[planned]** |
| First governance doc review | Documentation | Docs-only | **[planned]** |
| Host hardening review | Hardening | Production-equivalent | **[planned]** |

---

## Open questions

1. **Disclosure windows.** Academic findings sometimes benefit from fast publication
   (the community learns faster), and sometimes benefit from a longer embargo (the
   defender patches first). What is our default? 90 days is the industry convention
   but may be too long for a defensive tool that is already in production.
2. **Paying for external review.** Some reviewer categories (pen testers, compliance
   auditors) are straightforward vendor relationships. Others (academic groups) may
   want grant funding, data access, or co-authorship. Which of these are we willing
   to offer?
3. **Bug bounty.** A standing bug bounty is a different kind of external testing —
   always-on, lower per-finding depth, higher volume. Should SENTINEL run one from the
   first stable release, or wait until the in-repo red-team suite is fully wired?
4. **Public findings disclosure.** Mythos publishes a high-level summary of external
   findings in the system card itself. Should SENTINEL's equivalent (the
   SENTINEL-System-Card.pdf at the project root) include the same? The argument for
   is transparency; the argument against is that it gives a live attacker a reading
   list.
5. **Conflict of interest.** If the same pen-test firm reviews SENTINEL and is also a
   customer of a competing product, do we declare that in the engagement notes? The
   answer is probably yes, but we have not written it down.

---

## References

- `RISK-TIERS.md` — release gates that external findings feed into.
- `MODEL-RED-TEAM.md` — the internal red-team suite that external reviewers complement.
- `DRL-ALIGNMENT.md` — alignment assessment that external academic review should
  stress-test.
- `CONTAMINATION-POLICY.md` — the contract for model-artefact access.
- `compliance-readiness.md` — the Common Criteria mapping the compliance dry-run
  reviews.
- `IMPRESSIONS.md` — the qualitative document that external MSSP reviewers should be
  invited to contribute to.
- Claude Mythos Preview System Card §1.1.5 — external testing program structure.
- Claude Mythos Preview System Card §2.3.7 — examples of how external findings fed
  back into the release decision.
