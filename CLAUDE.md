# SENTINEL — Claude Code project context

Use this file for Claude Code sessions in repo. Solo-dev project: open-source DNS shield for Windows. Pre-v0.1; the Rust skeleton, threat-feed updater, tray icon, installer, and block-page are being built.

## What this is

Sentinel runs as a local DNS resolver on `127.0.0.1`, blocks connections to malicious domains using URLhaus + a Tranco-anchored allowlist, and serves a calm, evidence-led block-page when something is caught. Single machine, single binary, no SaaS, no telemetry.

Direction details + visual identity in `DESIGN.md`. Operational backlog in `TODOS.md` (T1 archive → T2 Tranco refresh → T3 DX expansion).

## Repository layout

| Area | Path | Notes |
|------|------|-------|
| Visual identity / design system | `DESIGN.md` | Single source of truth for UI surfaces (block-page, tray, toasts, installer). |
| Operational TODOs | `TODOS.md` | Pre-v0.1 sprint, v0.1 sprint, v0.2 pre-decisions. |
| CI workflows | `.github/workflows/` | `lint` (commitlint), `security` (gitleaks + trivy fs), `release-please`. |
| gstack tooling | `scripts/install-gstack.sh` | Installer for the gstack skill set. Local skill artifacts are gitignored. |
| Archive (v1 Flask/Python) | branch `archive/v1-python` | Frozen at `f15b62d6`. `git checkout archive/v1-python` to mine v1 patterns. |

The Rust crate skeleton (`Cargo.toml`, `src/`, `crates/`) lands in PR-3 of the T1 slice. There is intentionally no source tree on `main` until then.

## v1 history

The v1 Flask/Python codebase under `sentinel-core/` was archived 2026-04-27 (PR #5) and removed from `main` in PR T1-2. The April 2026 audit (`CODE-REVIEW-main-2026-04-18.md`) found v1 was ~60% real, ~40% scaffolding, with chronic CI failures and marketing-grade claims. Rather than fork-lift the v2 revamp, the project pivoted to a narrow, single-machine OSS DNS shield (design doc `~/.gstack/projects/MuzeenMir-sentinel/dscorp-main-design-20260425-191642.md`).

If a session needs v1 patterns (audit-service, llm-gateway design notes, ML pipeline references), check out `archive/v1-python` rather than expecting them in `main`.

## Conventions (non-negotiable)

- **No secrets in source.** Env vars only; `.env.example` placeholders. Never commit keys, passwords, tokens.
- **Safe input handling.** No `eval` / `exec` on untrusted data; parameterized SQL; auth + RBAC on any future API.
- **Errors logged + handled.** No bare `except:` or silent swallow without logging.
- **Dependencies.** Prefer MIT / Apache / BSD; avoid GPL / AGPL unless approved.
- **Tests.** Rust changes ship with `#[cfg(test)]` coverage; integration tests where the surface is observable.
- **Conventional Commits** are required (`commitlint.config.js`). Squash-merge only. Signed commits required on `main`.
- **GitHub Actions hardening.** Never interpolate `${{ github.event.* }}` text fields directly into `run:` scripts; route through `env:` first.

## Git

- **Canonical remote**: `https://github.com/MuzeenMir/sentinel`. Push to `origin` → that repo unless asked otherwise.
- **Branches**: `main` (signed, squash-merge target), `archive/v1-python` (frozen v1 history), feature branches per-PR.
- **Release flow**: release-please action opens release PRs from Conventional Commits on `main`. Workflow-permissions repo setting must allow GH Actions to create PRs (owner action, not code).

## gstack — Browser & QA Skills

**Setup (run once):** `bash scripts/install-gstack.sh`

Use `/browse` skill from gstack for all web browsing. Never use `mcp__claude-in-chrome__*` tools.

Available gstack skills: `/office-hours`, `/plan-ceo-review`, `/plan-eng-review`, `/plan-design-review`, `/design-consultation`, `/design-shotgun`, `/design-html`, `/review`, `/ship`, `/land-and-deploy`, `/canary`, `/benchmark`, `/browse`, `/connect-chrome`, `/qa`, `/qa-only`, `/design-review`, `/setup-browser-cookies`, `/setup-deploy`, `/retro`, `/investigate`, `/document-release`, `/codex`, `/cso`, `/autoplan`, `/plan-devex-review`, `/devex-review`, `/careful`, `/freeze`, `/guard`, `/unfreeze`, `/gstack-upgrade`, `/learn`.

## Optional local overrides

For personal Claude Code notes not shared, use **`CLAUDE.local.md`** in project root + add to `.gitignore` if created.

## Skill routing

When user request matches an available skill, invoke via Skill tool. Skills carry multi-step workflows, checklists, and quality gates — better than ad-hoc answers. False positive cheaper than false negative.

Key routing rules:
- Product ideas, "is this worth building", brainstorming → invoke /office-hours
- Strategy, scope, "think bigger", "what should we build" → invoke /plan-ceo-review
- Architecture, "does this design make sense" → invoke /plan-eng-review
- Design system, brand, "how should this look" → invoke /design-consultation
- Design review of plan → invoke /plan-design-review
- Developer experience of plan → invoke /plan-devex-review
- "Review everything", full review pipeline → invoke /autoplan
- Bugs, errors, "why is this broken", "wtf", "this doesn't work" → invoke /investigate
- Test site, find bugs, "does this work" → invoke /qa (or /qa-only for report only)
- Code review, check diff, "look at my changes" → invoke /review
- Visual polish, design audit, "this looks off" → invoke /design-review
- Developer experience audit, try onboarding → invoke /devex-review
- Ship, deploy, create PR, "send it" → invoke /ship
- Merge + deploy + verify → invoke /land-and-deploy
- Configure deployment → invoke /setup-deploy
- Post-deploy monitoring → invoke /canary
- Update docs after shipping → invoke /document-release
- Weekly retro, "how'd we do" → invoke /retro
- Second opinion, codex review → invoke /codex
- Safety mode, careful mode, lock down → invoke /careful or /guard
- Restrict edits to directory → invoke /freeze or /unfreeze
- Upgrade gstack → invoke /gstack-upgrade
- Save progress, "save my work" → invoke /context-save
- Resume, restore, "where was I" → invoke /context-restore
- Security audit, OWASP, "is this secure" → invoke /cso
- Make PDF, document, publication → invoke /make-pdf
- Launch real browser for QA → invoke /open-gstack-browser
- Import cookies for authenticated testing → invoke /setup-browser-cookies
- Performance regression, page speed, benchmarks → invoke /benchmark
- Review what gstack learned → invoke /learn
- Tune question sensitivity → invoke /plan-tune
- Code quality dashboard → invoke /health
