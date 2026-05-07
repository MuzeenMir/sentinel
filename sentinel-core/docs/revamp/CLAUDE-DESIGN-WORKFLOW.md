# SENTINEL — Console UX Workflow with Claude Design

| Field          | Value                                             |
|----------------|---------------------------------------------------|
| Document ID    | SENTINEL-DESIGN-001                               |
| Version        | 1.0.0                                             |
| Status         | Draft for review                                  |
| Companion docs | [SRS-002](SRS-002.md), [SDD-002](SDD-002.md), [SDP-002](SDP-002.md) |
| Last Reviewed  | 2026-04-18                                        |

---

## 1. Purpose

This document describes how the team uses **Claude Design**
(`https://claude.ai/design`, launched 2026-04-17) to design and iterate on the
SENTINEL Admin Console across every phase of the v2 revamp. It pairs design
briefs to phase deliverables and defines the brief→Design→implementation
workflow so design artifacts stay aligned with the specs.

Claude Design is in **research preview**. Treat the workflow described here as
load-bearing for the revamp, but expect tooling specifics to evolve. When they
do, update §3 and §6 of this document.

---

## 2. What Claude Design is (in one paragraph)

A chat-driven visual design product for designs, prototypes, slides, and
mockups. Powered by Claude Opus 4.7. You describe the goal; it produces a first
pass; you iterate via inline comments, direct text edits, and adjustment knobs
for spacing, color, and layout. It can read a codebase and design files and
apply that design system to subsequent outputs. Exports to PDF, URL, PPTX, and
Canva. Available to Pro / Max / Team / Enterprise subscribers via the palette
icon in the claude.ai left navigation.

**Important constraints to internalize:**

- It is a **chat product**. It cannot be invoked from the Claude Code CLI, from
  CI, or from automation. A human pastes a brief into the web UI and iterates.
- It produces **visual artifacts**, not React components. Implementation in
  `frontend/admin-console/` remains a coding task.
- It is **not the source of truth** for component-level design tokens — the
  Tailwind config and the design tokens file in `frontend/admin-console/` are.
  Claude Design reads them; it does not own them.

---

## 3. The brief → Design → implementation loop

The workflow is six steps, each owned by a specific role.

```
┌──────────────┐  ┌────────────────┐  ┌──────────────┐  ┌─────────────┐
│ 1. Author    │  │ 2. Iterate in  │  │ 3. Review    │  │ 4. Implement│
│    brief     │─▶│ Claude Design  │─▶│ (design +    │─▶│ in React +  │
│ (written     │  │ (visual)       │  │ security +   │  │ Tailwind    │
│  artifact)   │  │                │  │ product)     │  │             │
└──────────────┘  └────────────────┘  └──────────────┘  └─────────────┘
                                                              │
                          ┌──────────────┐  ┌─────────────┐   │
                          │ 6. Update    │◀─│ 5. Visual   │◀──┘
                          │ design       │  │ regression  │
                          │ artifact in  │  │ check vs.   │
                          │ docs/design/ │  │ approved    │
                          └──────────────┘  └─────────────┘
```

| Step | Who | Output | Time-box |
|---|---|---|---|
| 1. Author brief | Tech Lead or Frontend lead, using §6 templates | Markdown brief in `docs/design/briefs/<phase>-<page>.md` | 1–2 hours per page |
| 2. Iterate in Claude Design | Frontend lead | Mockup; export PDF + PNG; capture share URL | 1–2 hours per page |
| 3. Review | Frontend + Security + Product | Approved revision (or rejected with comments) | Same-day for routine; ≤ 3 days for safety-critical UX |
| 4. Implement | Frontend engineer | React + Tailwind PR | Per estimate |
| 5. Visual regression check | Frontend (Playwright screenshots) | Diff vs. approved mockup; deltas justified or fixed | In CI |
| 6. Update artifact | PR author | Updated PDF/PNG checked into `docs/design/<phase>/` | In the implementation PR |

The loop is intentionally short and human. **No automation between steps.**
Claude Design's output is reviewed by humans, not auto-applied.

---

## 4. Folder layout for design artifacts

Add to the repo per [GIT-RESTRUCTURE](GIT-RESTRUCTURE.md) §4 target layout:

```
docs/
└── design/
    ├── README.md                             # this workflow's tl;dr
    ├── design-system-snapshot.md             # what to feed Claude Design about our system
    ├── briefs/
    │   ├── _template.md                      # the §6.1 brief template
    │   ├── phase1-incidents-list.md
    │   ├── phase1-incident-detail.md
    │   ├── phase1-login-mfa.md
    │   ├── phase1-tenant-switcher.md
    │   ├── phase1-settings-users-scim.md
    │   ├── phase2-sensor-health.md
    │   ├── phase3-incident-ai-narrative.md
    │   ├── phase3-degraded-mode-states.md
    │   ├── phase4-host-posture.md
    │   ├── phase4-edge-llm-toggles.md
    │   ├── phase5-copilot-pane.md
    │   ├── phase5-write-tool-approval.md
    │   ├── phase5-citations-rag-source.md
    │   ├── phase6-robotics-scene-review.md
    │   ├── phase6-compliance-catalog.md
    │   ├── phase6-llm-assisted-mapping.md
    │   └── crosscut-opa-policy-editor.md
    ├── phase1/                               # PDF + PNG exports + share URLs
    ├── phase2/
    ├── ...
    └── system-card-v2/                       # public-facing artifact, Phase 6+
```

Conventions:

- **One brief per page or pane.** Resist composite briefs — they produce mushy
  mockups.
- **Briefs are versioned in git** so design intent is reviewable as code.
- **Mockup exports** committed alongside the brief that produced them, named
  `<brief-stem>-vN-<yyyy-mm-dd>.pdf`. Older versions kept; never overwrite.
- **No source design files in git** beyond exports (Claude Design holds the
  editable artifact at the share URL; recorded in the brief's metadata).
- **Storage budget**: PDFs/PNGs use git-LFS if any single file > 5 MB
  (per GIT-RESTRUCTURE §3.13).

---

## 5. Bootstrapping: feeding the design system to Claude Design

Claude Design can apply a team's design system if it can read the codebase and
design files. SENTINEL has a real React app already; use it.

**One-time setup (first session of Phase 0).**

Create `docs/design/design-system-snapshot.md` containing, in order:

1. **Color tokens** — the palette from `frontend/admin-console/tailwind.config.*`
   exported as a list of CSS variables and human-friendly names
   (`--color-bg-default`, `--color-text-default`, etc.).
2. **Type ramp** — the heading and body sizes / weights / line-heights actually
   used in the SPA, paired with their token names.
3. **Spacing scale** — the Tailwind spacing scale and any custom additions.
4. **Component inventory** — a table of the existing components in
   `frontend/admin-console/src/components/` with one-line descriptions and
   screenshots of representative usage.
5. **Iconography** — the icon library in use (lucide / heroicons / etc.) and
   any custom SVGs.
6. **Voice and tone** — three short examples of how SENTINEL writes button
   labels, error messages, and empty states. (Example: "We didn't find any
   incidents in this window" beats "No data".)
7. **Accessibility baseline** — WCAG 2.2 AA minimum; minimum touch target 44px;
   contrast ratios; keyboard navigation expectations.
8. **Hard rules** — non-negotiables for the product:
   - Every AI-generated content surface carries an "AI-generated" badge linked
     to provenance (SAF-2).
   - Every write-action UI element is a button, not an auto-trigger.
   - Tenant context (current tenant name) is visible in the top nav at all
     times.
   - Destructive actions require explicit confirmation; show what will be
     undone.

When you start a Claude Design session, paste the snapshot first, then the
specific brief. The snapshot becomes the implicit context for everything else.

**Refresh cadence.** Update `design-system-snapshot.md` whenever the SPA's
tokens change. The frontend lead owns the freshness.

---

## 6. Design briefs

### 6.1 Brief template

Save as `docs/design/briefs/_template.md`. Every per-page brief copies this and
fills it in.

```markdown
# Design brief: <page or pane name>

## Metadata
- Phase: <0–6, per SDP-002>
- Owner: <name / GitHub handle>
- Linked SRS requirements: <FR-CON-N, SAF-N, …>
- Linked SDD section: <§N from SDD-002>
- Status: draft | in-design | reviewed | implemented
- Claude Design share URL: <paste after first session>
- Mockup files: <paths under docs/design/<phase>/>

## Purpose
<One sentence: what is the user trying to do on this page?>

## Primary user
<Tenant Admin / Security Analyst / Compliance Officer / Auditor / End User /
AI Reviewer / Policy Author — pick from SRS-002 §2.3>

## User goals
1. <verb-phrased goal>
2. <verb-phrased goal>
3. <verb-phrased goal>

## Key elements (above the fold)
- <element 1 — what, why, what data it shows>
- <element 2 …>

## Information hierarchy
<Ordered list: most-important → least-important. Drives layout decisions.>

## States to design
- Default (typical content)
- Loading
- Empty (zero results, with helpful next-action)
- Error (recoverable + non-recoverable)
- Disabled (e.g., LLM kill-switched, tenant over budget)
- Permission-denied (e.g., read-only role attempting a write)

## Safety affordances
<Concrete UX requirements derived from SRS-002 §5 AI Safety. Examples:
"AI-generated badge on every triage narrative; tooltip explains provenance and
links to raw alerts." "Write-tool buttons styled distinctly from read-tool
buttons; require a click + a confirmation modal that shows the action's
expires_at and revert_token.">

## Accessibility
- WCAG 2.2 AA minimum.
- Keyboard navigation order documented.
- Screen-reader landmarks called out where non-obvious.
- Color is never the sole carrier of state (use icon + text too).

## Responsive
<Default to desktop-first 1280-wide; show 1024 and 1440 in the mockup. Mobile
is non-scope unless this brief explicitly calls it in.>

## Out of scope (for this brief)
<Things adjacent that the reviewer might assume but shouldn't. Prevents brief
sprawl.>

## Open questions
<List anything the implementer needs an answer for before coding starts.>
```

### 6.2 Per-phase brief catalog

Each entry is a **brief title + one-paragraph scope hint**. The team writes the
full brief from the §6.1 template before each Claude Design session.

#### Phase 0 — Stabilize

UX work in Phase 0 is deliberately minimal — no new pages. Two briefs:

- **`phase0-honest-status-indicator.md`.** Replace the misleading "all systems
  green" tile on the current dashboard with a status surface that names which
  v1 services are up, which v2 services are not yet enabled for this tenant,
  and which features are degraded. Maps to SDP-002 Phase 0 "honest README"
  principle, applied to the UI. Single screen.

- **`phase0-readme-and-marketing-pages.md`.** Public-facing scope copy that
  matches reality. Pure typography and layout work; this is also a good first
  Claude Design session because the stakes are low.

#### Phase 1 — Consolidate (heaviest design phase)

The console absorbs auth, api-gateway, alert-service, dashboard-service. Most
of the SPA gets reworked. Briefs:

- **`phase1-login-mfa.md`.** Login screen, OIDC redirect, SAML redirect, TOTP
  challenge, backup-code path. Maps to FR-CON-1.
- **`phase1-tenant-switcher.md`.** Top-nav tenant switcher, current-tenant
  badge, recent tenants. Maps to NFR-SEC-1 (tenant context always visible).
- **`phase1-incidents-list.md`.** New incidents view aligned with the v2
  schema. Filtering by source sensor (Falco/Suricata/Wazuh/OpenSCAP/agent),
  severity, ATT&CK technique. Maps to FR-CON-1.
- **`phase1-incident-detail.md`.** Single-incident page. Raw alerts, ensemble
  scores, SHAP top-10, related events, lifecycle FSM controls. **Does not yet
  show AI narrative** (that lands in Phase 3).
- **`phase1-settings-users-scim.md`.** Users, roles, API keys, SCIM
  provisioning status. Maps to FR-CON-1.
- **`phase1-empty-loading-error-states.md`.** A library brief: define
  consistent empty / loading / error patterns once; reused by every other
  brief.

#### Phase 2 — Sensor swap

- **`phase2-sensor-health.md`.** Per-tenant view of Falco / Suricata / Wazuh /
  OpenSCAP / agent connection health, last-seen, version, lag. Maps to FR-COL-10
  and FR-OBS-3.
- **`phase2-event-explorer.md`.** Per-source raw event browser with CIM
  normalization toggle (raw payload vs. normalized fields). Maps to FR-COL-6.
- **`phase2-attack-technique-overlay.md`.** Component overlay shown wherever
  an event/alert appears: technique ID + name + tactic + a one-line
  description, with a link out to MITRE.

#### Phase 3 — LLM triage

This phase is the inflection point: the AI-generated badge becomes a recurring
component. Briefs:

- **`phase3-incident-ai-narrative.md`.** Incident detail page gains the
  AI-generated narrative card. Provenance link to underlying raw alerts.
  Confidence indicator. ATT&CK technique chips with the technique-overlay from
  Phase 2. Maps to FR-CON-5, SAF-2.
- **`phase3-ai-generated-badge.md`.** Library component brief — the badge
  itself, its tooltip, its hover state, its provenance modal. Reused across
  Phases 3–6.
- **`phase3-degraded-mode-states.md`.** UX for: triage LLM kill-switched,
  tenant over LLM budget, model promotion in canary, gateway 503. Maps to
  FR-LLM-9, OPS-1.
- **`phase3-confidence-gated-review.md`.** UI for analysts to review and
  approve/reject low-confidence triage outputs (SAF-3).
- **`phase3-llm-audit-log-viewer.md`.** Read-only audit log of every LLM call
  per tenant — prompt hash, model version, latency, tool calls, cost. Maps to
  FR-LLM-5, NFR-SEC-7.

#### Phase 4 — Edge LLM

- **`phase4-host-posture.md`.** Per-host page: OpenSCAP findings, Edge LLM
  inline explanations (rendered with the AI-generated badge), remediation
  status FSM. Maps to FR-HRD-2.
- **`phase4-edge-llm-toggles.md`.** Per-profile UI for enabling Edge LLM,
  showing resource ceiling status, last on-device inference latency. Maps to
  FR-AGT-4, FR-AGT-7.
- **`phase4-nl-log-query.md`.** Natural-language log query box on a host
  page; renders the LLM response with provenance citations to the raw log
  lines. Maps to FR-AGT-4.

#### Phase 5 — Analyst Copilot (highest safety-UX stakes)

- **`phase5-copilot-pane.md`.** The chat shell — input, message stream, tool
  result cards, citation cards, history. Maps to FR-CON-3.
- **`phase5-write-tool-approval.md`.** The write-tool affordance: when the
  copilot suggests a write action, render it as a distinctly-styled button
  with a confirmation modal that shows exactly what will change, the
  expires_at, the revert_token, and a one-click revert. Maps to FR-CON-4,
  SAF-1. **This is the most safety-critical UX brief in the whole revamp.**
- **`phase5-citations-rag-source.md`.** Source cards rendered inline with
  copilot answers — incident IDs, alert IDs, ATT&CK technique IDs, with
  click-through to the source.
- **`phase5-tool-call-audit-pane.md`.** Visible audit of every copilot tool
  call (read and write) within the session, plus a link to the persistent
  audit log.
- **`phase5-empty-low-confidence-states.md`.** "Copilot is uncertain" state,
  "Copilot has insufficient context for this question" state, "Tool failed"
  state — patterns reused throughout the chat.

#### Phase 6 — Multimodal robotics + Compliance

- **`phase6-robotics-scene-review.md`.** Image-heavy review UI: camera frame
  with bounding boxes, scene-anomaly verdict (PPE, presence, equipment), Edge
  LLM rationale, accept/reject. Maps to FR-AGT-4, SAF-3.
- **`phase6-compliance-catalog.md`.** Catalog browser per framework (SOC 2 /
  ISO 27001 / NIST CSF / PCI-DSS / GDPR). Per control: status (met / partial
  / gap), linked evidence, last verified. Maps to FR-CMP-1, FR-CMP-3.
- **`phase6-llm-assisted-mapping.md`.** Reviewer UI: Gemma 4 proposes a
  mapping from raw evidence to a control; reviewer accepts or rejects.
  AI-generated badge mandatory; nothing counts as evidence until accepted.
  Maps to FR-CMP-4.
- **`phase6-audit-export-pdf-template.md`.** PDF export template for SOC 2 +
  ISO 27001 evidence. Built in Claude Design directly (PDF export is native).
  Maps to FR-CMP-2.
- **`phase6-system-card-v2.md`.** Public-facing System Card replacing the
  v1 PDF at the repo root. Pitched at security buyers and external auditors.

#### Cross-cutting

- **`crosscut-opa-policy-editor.md`.** Code-editor surface with syntax
  highlighting for Rego, dry-run output panel showing decisions against the
  last 7 days of incidents, two-person promotion flow, version history with
  one-click rollback. Maps to FR-CON-8.
- **`crosscut-notifications.md`.** Per-tenant channel configuration (email /
  Slack / Teams / webhook / PagerDuty) with rate limit indicators. Maps to
  FR-CTR-2.
- **`crosscut-toast-and-banner.md`.** Library brief for transient
  notifications across the SPA. Should land before Phase 1 incidents-list.

---

## 7. Per-phase ritual

For each phase, hold a **design kickoff** at the start of week 1:

1. The Tech Lead lists the briefs needed for this phase (from §6.2).
2. Frontend lead writes the briefs (1–2 hours each, in `docs/design/briefs/`).
3. Frontend lead runs Claude Design sessions, exports PDF/PNG/share URL.
4. **Design review meeting** at the end of week 1: walk every mockup with
   Frontend + Security + Product. Capture decisions in the brief's "Open
   questions" section.
5. Approved mockups land via PR into `docs/design/<phase>/` (PR title:
   `docs(design): phase-<N> mockups for <pages>`).
6. Implementation PRs reference the approved mockups in their PR description
   per the [GIT-RESTRUCTURE](GIT-RESTRUCTURE.md) §9 PR template ("Test
   evidence" section: include screenshot diff vs. mockup).

For Phase 5 (highest safety-UX stakes), add a **safety-design review** as a
separate meeting with Security + AI Reviewer roles. Sign-off on
`phase5-write-tool-approval.md` is required before any code lands.

---

## 8. Visual regression in CI

Once a mockup is approved and implemented, lock it in:

- Playwright takes screenshots of each console page at 1280×800 on every PR.
- Screenshots compared against the approved mockup PNG with a tolerance
  threshold (default 2% pixel diff).
- Diffs above threshold either fix the implementation or update the mockup
  via a follow-up brief revision (with re-review).
- Screenshots stored in `tests/e2e/screenshots/` and gated by the `e2e-smoke`
  workflow (per GIT-RESTRUCTURE §3.11).

This catches drift in two directions: implementation drifting from design,
and design changes that haven't gone through the brief loop.

---

## 9. What Claude Design is NOT used for

Be explicit about boundaries to prevent scope creep:

- **Not for ADRs, specs, runbooks, READMEs.** Markdown stays markdown.
- **Not for architecture / data flow diagrams** that need to live in code
  review (use Mermaid in markdown — diffable, renderable on GitHub, no
  external dependency).
- **Not for component implementation.** React + Tailwind PRs come from
  engineers (or Claude Code), not from Claude Design output.
- **Not as the source of truth for design tokens.** Tokens live in the
  Tailwind config and a tokens file under `frontend/admin-console/`. Claude
  Design *consumes* them; it does not own them.
- **Not for customer dashboards inside the product.** Those are coded React
  components driven by tenant data. Claude Design is for the *layout and
  states* of those dashboards, not for live rendering.

---

## 10. Risk and mitigation

| Risk | Mitigation |
|---|---|
| Research preview deprecates or pivots before v2 GA | Briefs live in git; if Claude Design goes away, the briefs feed any other tool (Figma + AI plugin, plain Figma, Penpot, etc.). The methodology survives the tool. |
| Mockups drift from implementation | Visual regression in CI (§8) |
| Safety-critical UX (write-tool approval, AI badges) softened during iteration | Security sign-off required on Phase 5 briefs; safety affordances are first-class brief sections (§6.1) |
| Design system snapshot stale | Frontend lead refreshes after every tokens change; PR template includes a checkbox for "if you changed tokens, you updated the snapshot" |
| Brief sprawl (15-page brief produces mushy mockup) | Briefs are time-boxed (1–2 hours); composite briefs forbidden; out-of-scope section mandatory |
| Subscription gating (only Pro+ users can run Claude Design) | At least the Frontend lead and Tech Lead must have access; budgeted as a tooling line item |
| Designs don't translate well to mobile / responsive | Brief default is desktop-first; mobile briefs explicit, not implied |

---

## 11. Quick-start checklist (for the first design session)

Phase 0 week 1:

- [ ] `docs/design/` folder created.
- [ ] `_template.md` brief template committed.
- [ ] `design-system-snapshot.md` populated from current
      `frontend/admin-console/`.
- [ ] Frontend lead has Claude Design access verified at
      [claude.ai/design](https://claude.ai/design).
- [ ] First brief written: `phase0-honest-status-indicator.md`.
- [ ] First Claude Design session run; output exported as PDF + PNG;
      share URL captured in the brief metadata.
- [ ] Design review meeting held; outcome captured in the brief.
- [ ] PR opened: `docs(design): phase-0 mockups for honest status indicator`.

If this loop completes cleanly in week 1, the workflow is validated and Phase
1 can proceed at speed.

---

End of CLAUDE-DESIGN-WORKFLOW.
