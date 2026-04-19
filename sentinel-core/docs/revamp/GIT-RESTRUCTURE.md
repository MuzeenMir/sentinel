# SENTINEL — Git Repository Restructure

| Field          | Value                                             |
|----------------|---------------------------------------------------|
| Document ID    | SENTINEL-GIT-001                                  |
| Version        | 1.0.0                                             |
| Status         | Draft for review                                  |
| Last Reviewed  | 2026-04-18                                        |
| Companion      | [SDP-002](SDP-002.md) Phase 0                     |

---

## 1. Purpose

Define how the SENTINEL repository will be structured, branched, gated, and
maintained from Phase 0 of the v2 revamp onward. The goal is a repo that is
**boring**: every change small, traceable, signed, gated, and revertible. The
v1 era of frequent main-breaking commits ends here.

---

## 2. Current state assessment (2026-04-18)

Observations from the live repo before Phase 0:

| Aspect | Current | Gap |
|---|---|---|
| Remote | `https://github.com/MuzeenMir/sentinel` (single `origin`) | OK |
| Default branch | `main` | OK |
| Active branches | `main`, `bugbot-reviews`, `bugbot-reviews-clean`, `feature-sss-vm-lab` | Stale branches accumulating; need cleanup policy |
| Branch protection | None visible (direct pushes possible) | **Critical gap** — must add before Phase 0 work begins |
| Required status checks | `ci.yml` runs but is not a required check | **Critical gap** |
| CODEOWNERS | None | **Gap** — required by Phase 1 multi-owner work |
| Commit signing | Inconsistent | **Gap** — must require signed commits |
| Pre-commit hooks | Local `pre-commit` and `post-merge` exist; not framework-managed | **Gap** — adopt `pre-commit` framework for portability |
| Conventional commits | Mostly followed (`fix(...)`, `ci(...)`) | **Light gap** — formalize and enforce in CI |
| Repo shape | Monorepo: parent `sentinel/` wrapping `sentinel-core/` (the actual product) plus root-level docs | **OK but oddly nested** — see §4 for cleanup |
| Secret scanning | `.gitleaks.toml` present | OK — wire into CI as required |
| LFS | Not in use | **Gap** if model weights or large fixtures land |
| Tags / releases | Not visibly used in this snapshot | **Gap** — needs a release process |
| `CODE-REVIEW-main-2026-04-18.md` at root | One-off review artifact in root | Move to `docs/reviews/` to keep root clean |

---

## 3. Decisions

### 3.1 Repo shape: **monorepo, kept**

SENTINEL stays a single repository. Reasons:

- Cross-service refactors (consolidating 11 services to 4) require atomic
  commits across many directories — a polyrepo would multiply the friction.
- CIM proto schema is shared across collector, analyzer, controller — best
  versioned alongside its consumers.
- Helm chart, OPA bundles, and migrations need to evolve in lockstep with
  service code.
- Team is small; the polyrepo overhead has no offsetting payoff.

### 3.2 Repo layout: **flatten the wrapper**

Current shape: `sentinel/` → `sentinel-core/<everything>` plus a few root-level
files (`CLAUDE.md`, `README.md`, `LICENSE`, `SENTINEL System Card.pdf`).

The wrapping `sentinel/` directory adds no value — every path is one extra
segment for no payoff. Two options; pick one in Phase 0 (track as ADR-011):

- **Option A (preferred): flatten.** Move everything from `sentinel-core/` up
  to repo root. Move root-level wrapper files into `docs/` or `top-level/`.
  Result: `backend/`, `frontend/`, `agent/`, `docs/`, etc. directly at root.
- **Option B: rename.** Keep nesting, rename `sentinel-core/` to `app/` (or
  `src/`) for clarity that it is the product code. Lower-impact but doesn't
  remove the indirection.

Whichever is chosen, the `git mv` happens once in Phase 0, in a dedicated PR,
with CI updated in the same PR.

### 3.3 Branch model: **trunk-based with short-lived branches**

- **`main`** is the trunk. Always green, always shippable.
- **Feature branches** off `main`, named `<type>/<scope>-<short-summary>`
  (e.g., `feat/llm-gateway-skeleton`, `fix/migrations-tenant-seed`). Lifetime:
  ≤ 5 working days. Force-rebase rather than merge when updating from `main`.
- **Release branches** `release/vYYYY.MM` only when a release needs hot-fixes
  past the next tag. Created from a tag, not a branch.
- **No long-lived feature branches.** If a piece of work needs more than 5
  days, ship behind a feature flag (`USE_V2_*`) instead.
- **No `develop` branch.** Trunk is the integration point.

### 3.4 Branch protection on `main` (immediately)

- Require pull request review (≥ 1 approving review by a CODEOWNER).
- Require status checks: `ci/lint`, `ci/typecheck`, `ci/unit`, `ci/integration`,
  `ci/e2e-smoke`, `ci/security` — all must pass before merge.
- Require branches up to date before merge.
- Require conversation resolution before merge.
- Require signed commits.
- Require linear history (no merge commits; squash or rebase only).
- Restrict force pushes to `main` (only via admin override + an audit comment).
- Restrict deletion of `main`.

### 3.5 Branch protection on `release/*`

Same as `main`, plus:
- No new features (only `fix:` and `chore(release):` commits accepted).
- Requires Tech Lead + Security review for any merge.

### 3.6 Commit conventions: **Conventional Commits, enforced**

Format: `<type>(<scope>)!: <summary>`, optional body, optional footer.

Allowed types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `build`,
`ci`, `perf`, `revert`. The `!` after the type/scope marks a breaking change
and triggers a major-version bump where SemVer applies.

Allowed scopes: `collector`, `analyzer`, `controller`, `console`, `agent`,
`llm-gateway`, `opa`, `helm`, `compose`, `ci`, `docs`, `agent-sdk`, `sensors`,
`migrations`, `infra`, plus `revamp` for cross-cutting Phase 0 work.

Enforcement: `commitlint` runs in pre-commit and as a required CI check.
Existing commits like `fix(migrations): seed default tenant with explicit
tenant_id` already match — formalizing prevents drift.

### 3.7 PR conventions

- Title in Conventional-Commits form (becomes the squash commit subject).
- Body uses the [PR template](#9-pr-template).
- Squash-merge only — one commit per PR landed on `main`.
- Linked to an issue (or labeled `chore` if a maintenance PR with no issue).
- ≤ 400 lines of diff except for whitelisted bulk-rename PRs (move/rename only,
  no semantic changes).
- Reviews requested via CODEOWNERS auto-assignment.

### 3.8 Tags and releases

Two tagging schemes:

- **Application releases** (the deployable product): **calendar versioning**
  `vYYYY.MM.MICRO` (e.g., `v2026.04.0`, `v2026.04.1`). One major release per
  month during the revamp; micro for hot-fixes.
- **SDK and agent** (consumed by external code): **semantic versioning**
  `agent-vMAJOR.MINOR.PATCH` and `sdk-vMAJOR.MINOR.PATCH`. Breaking changes
  bump major.

Release notes generated by [release-please](https://github.com/google-github-actions/release-please-action)
from Conventional Commits. PR review for the generated changelog before tag.

Tags are signed (`git tag -s`).

### 3.9 Code review: **CODEOWNERS** required

Implement `.github/CODEOWNERS`:

```
# default: tech lead
*                                       @sentinel/tech-lead

# backend services
/backend/collector/                     @sentinel/backend
/backend/analyzer/                      @sentinel/backend @sentinel/ml
/backend/controller/                    @sentinel/backend @sentinel/security
/backend/console/                       @sentinel/backend @sentinel/frontend
/backend/llm-gateway/                   @sentinel/ai @sentinel/security
/backend/_lib/                          @sentinel/backend @sentinel/tech-lead

# AI / models / safety
/backend/analyzer/triage/               @sentinel/ai
/backend/analyzer/models/               @sentinel/ml
/tests/safety/                          @sentinel/security @sentinel/ai
/docs/models/                           @sentinel/ai
/docs/revamp/                           @sentinel/tech-lead

# OPA policy bundles
/opa-bundles/                           @sentinel/security @sentinel/policy

# Helm + infra
/deploy/helm/                           @sentinel/platform
/infrastructure/                        @sentinel/platform
/.github/workflows/                     @sentinel/platform @sentinel/tech-lead

# Agent
/agent/                                 @sentinel/endpoint @sentinel/security

# Frontend
/frontend/                              @sentinel/frontend

# Docs (revamp set is gated to tech lead; v1 docs are anyone)
/docs/specifications/                   @sentinel/tech-lead
```

Adjust team handles to actual GitHub teams during Phase 0.

### 3.10 Pre-commit hooks (framework)

Adopt the `pre-commit` framework. `.pre-commit-config.yaml` at repo root:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files
        args: ['--maxkb=1024']
      - id: check-merge-conflict
      - id: detect-private-key
      - id: mixed-line-ending
        args: ['--fix=lf']
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.0
    hooks:
      - id: ruff
        args: ['--fix']
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies: ['pydantic>=2.0', 'types-requests']
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
  - repo: https://github.com/koalaman/shellcheck-precommit
    rev: v0.10.0
    hooks:
      - id: shellcheck
  - repo: https://github.com/pre-commit/mirrors-prettier
    rev: v4.0.0-alpha.8
    hooks:
      - id: prettier
        types_or: [javascript, jsx, ts, tsx, json, yaml, markdown]
  - repo: https://github.com/conventional-changelog/commitlint
    rev: v19.3.0
    hooks:
      - id: commitlint
        stages: [commit-msg]
        additional_dependencies: ['@commitlint/config-conventional']
```

Existing local `pre-commit` script (under `.git/hooks/`) is replaced — `pre-commit
install` writes the hook based on the framework config. Users run
`pre-commit install --hook-type commit-msg` once after clone.

### 3.11 GitHub Actions CI gates (required)

Replace the current monolithic `ci.yml` with a small set of focused workflows:

```
.github/workflows/
  lint.yml          # ruff, eslint, shellcheck, prettier --check
  typecheck.yml     # mypy strict, tsc --noEmit
  unit.yml          # pytest unit, vitest
  integration.yml   # pytest with testcontainers
  e2e-smoke.yml     # playwright + docker-compose; < 15 min
  security.yml      # gitleaks, semgrep, trivy, codeql
  build.yml         # docker build for each service, image scan
  sbom.yml          # CycloneDX SBOM per release artifact
  release-please.yml # changelog + tag automation on main
  llm-eval.yml      # nightly hallucination + injection corpus (Phase 3+)
```

Each workflow is its own required check; failure of one does not skip the
others. Branch protection requires all eight (plus `llm-eval` from Phase 3
onward).

### 3.12 `.gitignore` and `.gitattributes` audit

Phase 0 actions:

- Audit `.gitignore` for entries pinning ad-hoc local files (`.sentinel-instance-id`,
  `.sentinel-instance-ip`, `sentinel_env`) — these should not be committed.
  Move them out of tracking and into `.gitignore`.
- `.gitattributes` should set:
  - `* text=auto eol=lf` (cross-platform line ending sanity).
  - `*.gguf binary` and `*.safetensors binary` (model weights).
  - `*.pdf binary diff=pdf`.
  - LFS tracking for any single file > 50 MB (planned: edge model bundles
    distributed via release artifacts, not git).
- The `SENTINEL System Card.pdf` (~117 KB) at root: acceptable in git for now;
  if it grows, move to LFS or a release artifact.

### 3.13 LFS policy

- Use git-LFS for any single file > 5 MB that must live in git.
- Default: model weights (`.gguf`, `.safetensors`, `.pkl` of trained models)
  do **not** live in git at all — they live in a model registry (OCI artifact
  or S3 bucket) and are pulled by Helm or by CI from a SHA-256-pinned manifest
  (`models/manifest.json`).

### 3.14 Secret hygiene

- `.gitleaks.toml` already present — wire it into CI as a required check.
- Phase 0: full-history gitleaks scan
  (`gitleaks detect --source . --log-opts="--all"`); every finding triaged.
- Any leaked secret triggers immediate rotation + a postmortem entry in
  `docs/operations/incidents/`.
- Future: `git secrets --register-aws` patterns plus regex for SENTINEL-specific
  IDs.

### 3.15 Stale branch policy

- Any branch with no commits for 30 days is auto-archived (renamed to
  `archive/<YYYY-MM>/<original-name>`).
- Archived branches deleted after 90 days.
- The current `bugbot-reviews`, `bugbot-reviews-clean`, `feature-sss-vm-lab`
  branches: Phase 0 — review with their owners, merge or archive. None should
  remain by Phase 0 exit.

### 3.16 Default GitHub repository settings

- Squash-merge only; **disable** "merge commit" and "rebase merge" options.
- "Automatically delete head branches" enabled.
- "Always suggest updating pull request branches" enabled.
- Issues + Discussions enabled.
- Wiki disabled (use `docs/`).
- Vulnerability alerts + Dependabot security updates enabled.
- Dependabot configured for `pip`, `npm`, `docker`, `github-actions` ecosystems.

---

## 4. Target directory layout

After the Phase 0 flatten (Option A from §3.2):

```
sentinel/                                # repo root
├── .github/
│   ├── workflows/                       # see §3.11
│   ├── CODEOWNERS
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── ISSUE_TEMPLATE/
│   └── dependabot.yml
├── .pre-commit-config.yaml
├── .commitlintrc.yaml
├── .editorconfig
├── .gitattributes
├── .gitignore
├── .gitleaks.toml
├── README.md                            # honest scope
├── LICENSE
├── CHANGELOG.md                         # generated by release-please
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── SECURITY.md                          # vuln disclosure policy
├── docs/
│   ├── revamp/                          # SRS-002, SDD-002, SDP-002, this file, BACKLOG.md
│   ├── specifications/                  # v1 baseline (kept for history)
│   ├── adr/                             # architecture decision records
│   ├── reviews/                         # code review artifacts (move CODE-REVIEW-* here)
│   ├── operations/runbooks/
│   ├── spikes/
│   ├── models/                          # model cards
│   └── ...
├── proto/
│   └── cim/v2/
├── backend/
│   ├── collector/
│   ├── analyzer/
│   ├── controller/
│   ├── console/
│   ├── llm-gateway/
│   └── _lib/                            # shared internal libs
├── agent/
│   ├── profiles/
│   ├── collectors/
│   ├── inference/
│   └── transport/
├── frontend/
│   └── admin-console/
├── opa-bundles/
├── sensors/
│   └── falco/rules/sentinel/
├── deploy/
│   ├── helm/sentinel/
│   ├── compose/                         # docker-compose for dev parity
│   └── airgap/
├── infrastructure/
│   └── terraform/                       # finally populated in Phase 3+
├── sdk/
├── training/
├── tests/
│   ├── unit/                            # mostly co-located in service dirs
│   ├── integration/
│   ├── e2e/
│   ├── safety/                          # adversarial corpus, isolation tests
│   └── llm/
├── archive/
│   ├── v1-xdp/
│   ├── v1-sensors/
│   └── v1-services/
└── tools/                               # repo scripts (release helpers, dev setup)
```

If Option B (rename, no flatten) is chosen, replace `backend/agent/...` with
`app/backend/...` and so on; the rest stands.

---

## 5. Migration runbook (Phase 0, week 1–2)

This is the actual sequence for the cutover. Treat it as a runbook — every
step is a single PR with the listed verification.

### 5.1 Day 1 — Prep, no destructive ops

1. **PR-A: Branch protection settings.** Apply §3.4 settings via
   `gh api repos/MuzeenMir/sentinel/branches/main/protection` script in
   `tools/branch-protection.sh`. Test with a dummy PR that lacks reviews — must
   be blocked.
2. **PR-B: CODEOWNERS.** Add `.github/CODEOWNERS` per §3.9.
3. **PR-C: Pre-commit framework.** Add `.pre-commit-config.yaml` per §3.10.
   Document `pre-commit install` in CONTRIBUTING.md.
4. **PR-D: Commitlint config.** Add `.commitlintrc.yaml` enforcing the §3.6
   types/scopes.
5. **PR-E: PR template.** §9.

### 5.2 Day 2–5 — CI rebuild

6. **PR-F: Split `ci.yml` into the workflows in §3.11.** Each new workflow
   added one PR at a time, marked required as it lands.
7. **PR-G: gitleaks history scan + remediation.** Run scan, fix any findings,
   document in `docs/reviews/secret-scan-2026-04.md`.
8. **PR-H: Trivy + Semgrep + CodeQL workflows enabled.**
9. **PR-I: SBOM + cosign-signing pipeline.** Even before consolidation begins.

### 5.3 Day 6–10 — Repo flatten (Option A)

This is the big bulk-rename PR; do it last in Phase 0 prep so everything
else is stable.

10. **PR-J: Archive stale branches.** Rename `bugbot-reviews`,
    `bugbot-reviews-clean`, `feature-sss-vm-lab` per §3.15. Communicate with
    branch authors first.
11. **PR-K: Move `CODE-REVIEW-main-2026-04-18.md` and `SENTINEL System Card.pdf`
    into `docs/reviews/` and `docs/`** respectively. Update README links.
12. **PR-L: Bulk flatten.** Single mechanical PR:
    - `git mv sentinel-core/* .`
    - `git mv sentinel-core/.* .` (handle dotfiles individually)
    - Update every workflow path reference.
    - Update every `Dockerfile` `COPY` and `WORKDIR`.
    - Update `docker-compose.yml` build contexts.
    - Update `helm/` paths.
    - Update root `README.md`.
    - PR title: `refactor(repo)!: flatten sentinel-core wrapper directory`
    - **No semantic changes in this PR.** CI must be green before merge.
    - Reviewer checklist explicitly verifies "no diff outside path renames."

13. **PR-M: Honest README.** Per SDP-002 Phase 0; replace marketing copy with
    current shipping scope.

### 5.4 Day 11–14 — Verification

14. Run a full PR cycle on a tiny change (`docs:` typo fix). Confirm all
    required checks block correctly.
15. Run a force-push attempt to `main` (as admin, dry-run). Confirm blocked
    without override.
16. Run `pre-commit run --all-files` locally on a fresh clone. Confirm clean.
17. Verify CODEOWNERS auto-assigns reviewers correctly.

### 5.5 Phase 0 exit gate

Per SDP-002 Phase 0 exit: all CI gates green on `main` for 7 consecutive days,
no in-flight migration, README claims match shipping reality. After that gate,
no Phase 1 PR may merge until this runbook's PR-A through PR-M are landed.

---

## 6. Day-to-day workflow (for every contributor)

Once Phase 0 cutover lands, the loop:

```
# 1. Branch from latest main
git fetch origin
git switch -c feat/llm-gateway-skeleton origin/main

# 2. Work in small commits
# (pre-commit auto-runs; commitlint auto-checks message)

# 3. Push with -u
git push -u origin feat/llm-gateway-skeleton

# 4. Open PR with the template; CI runs
gh pr create --fill

# 5. Address reviews; squash-merge happens via GH UI or:
gh pr merge --squash --delete-branch

# 6. Pull main, branch is gone, repeat
git switch main && git pull --ff-only && git branch -d feat/llm-gateway-skeleton 2>/dev/null
```

Rebase, not merge, when bringing main into a feature branch:

```
git fetch origin
git rebase origin/main
# resolve, then:
git push --force-with-lease
```

Never `--force` (without `-with-lease`) on shared branches.

---

## 7. Hot-fix process

If a Critical bug ships:

1. Branch from the latest tag: `git switch -c fix/<scope>-<short> v2026.04.0`
2. Single small PR; same CI gates required.
3. Tag the fix as `v2026.04.1`; release-please updates CHANGELOG.
4. If `main` has diverged: cherry-pick the fix commit onto `main` in a follow-up
   PR. Never let `main` lack a fix that shipped to production.

---

## 8. Recovery procedures

### 8.1 Bad merge to `main`

- **First choice**: `git revert <commit-sha>` in a new PR. Preserves history.
- **Force push**: only as admin, only after Tech Lead + Security approval, only
  after the bad commit is identified by SHA, and only with a paired audit
  comment in the next standup. Logged in `docs/operations/incidents/`.

### 8.2 Compromised commit author

- Rotate signing keys; revoke the compromised key from GitHub.
- Audit recent commits signed by the key; revert any unauthorized.
- Post-incident review.

### 8.3 Lost branch (e.g., accidental delete)

- `git reflog` first.
- `git fsck --lost-found` second.
- GitHub's branch deletion is recoverable via API for a window — file a support
  request before that window closes.

---

## 9. PR template

`.github/PULL_REQUEST_TEMPLATE.md`:

```markdown
## Summary
<1–3 sentences: what this PR does and why>

## Type
- [ ] feat
- [ ] fix
- [ ] refactor
- [ ] docs
- [ ] test
- [ ] chore / ci / build
- [ ] perf
- [ ] revert

## Linked issue / ADR
<Closes #123 — and/or — Implements ADR-007>

## Phase
<Phase 0 / 1 / 2 / 3 / 4 / 5 / 6 / not-revamp>

## Test evidence
<paste output, screenshots, video — what assures this works>

## Security note
<Anything reviewers should look at: tenant isolation, LLM safety, secrets,
permissions, supply chain. Write "n/a" only if you genuinely have nothing.>

## Rollback plan
<Single sentence: how a reviewer would revert this safely>

## Checklist
- [ ] PR title matches Conventional Commits (`type(scope): summary`)
- [ ] Tests added or updated
- [ ] Docs updated (README, ADR, runbook, model card if applicable)
- [ ] No secrets committed (`pre-commit run gitleaks --all-files` clean)
- [ ] No new dependencies without ADR
- [ ] AI safety: no LLM output drives a write action without human approval
```

---

## 10. Issue templates

`.github/ISSUE_TEMPLATE/`:

- `bug.md` — reproduction, expected, actual, environment, severity.
- `feature.md` — problem, proposed solution, alternatives, success metric.
- `security.md` — references SECURITY.md disclosure path; not for public use.
- `revamp-task.md` — phase, workstream, deliverable, exit criterion link.

---

## 11. SECURITY.md

A repo-root SECURITY.md is required for §3.16 vulnerability alerts. Minimum:

```markdown
# Security policy

## Reporting a vulnerability

Email security@<sentinel-domain> with details. Encrypt with the PGP key at
<URL>. We acknowledge within 2 business days, triage within 5, and aim to
resolve Critical issues within 30 days.

## Supported versions

| Version | Supported |
|---|---|
| v2.x (revamp) | ✓ |
| v1.x | security-only until v2 GA + 90 days |

## Scope

In-scope: this repository's code, OPA bundles, helm chart, container images,
agent.

Out-of-scope: third-party sensors (Falco, Suricata, Wazuh, OpenSCAP) — report
upstream.
```

---

## 12. CODE_OF_CONDUCT.md and CONTRIBUTING.md

Standard short documents. CONTRIBUTING.md must include:

- `pre-commit install` and `pre-commit install --hook-type commit-msg` on
  first clone.
- Signed-commit setup (`git config commit.gpgsign true` plus key on GitHub).
- Conventional Commits format with the §3.6 type/scope list.
- PR-size guideline (≤ 400 lines diff).
- ADR-required scenarios (new dep, new service, new architectural seam).

---

## 13. What is explicitly NOT changing

- **Remote location.** `https://github.com/MuzeenMir/sentinel` stays. No
  re-host required.
- **License.** Whatever is in `LICENSE` stays unless legal initiates a change.
- **Issue tracker.** GitHub Issues. No Jira.
- **CI provider.** GitHub Actions. No third-party CI in the critical path.

---

## 14. Open items (track during Phase 0)

- ADR-011: flatten vs. rename (decide week 1).
- Decide on signed-commits enforcement strictness (require all, or warn-only
  for first 30 days during ramp-up).
- Decide on monthly cadence for stale-branch automation script.
- Decide on Dependabot grouping strategy (per-ecosystem grouped PRs vs. per-
  package).

---

End of GIT-RESTRUCTURE.
