# Review Plan: SENTINEL `main` — Phase 0 Stabilization & Follow-Ups

## Context

The branch `fix/dragon-scale-stabilize-2026-05-11` (PR #2) plus the preceding hardening commit (`5ee2457`) plus the follow-up release/CI/xdp fixes have all landed on `main` and have been tagged through `v1.0.1`. `CLAUDE.md` claims Phase 0 is largely complete (many ✅ items) and references a baseline plan at `.team/specs/2026-05-12-ultraplan-baseline.md` which does **not** exist in the tree. The actual Phase 0 implementation spec lives at `docs/superpowers/plans/2026-05-07-phase-0-security-stabilization.md`. Before declaring Phase 0 done and applying branch protection (the last open Wave 4 item), Mir wants an independent verification of every claimed fix against the source spec and the original audit, so that any gap — code missing, tests narrower than the spec, CI not actually gating — is caught before Phase 1 starts.

The output is one closure document (`sentinel-core/docs/reviews/phase-0-critical-fixes.md` — which Task 10 of the spec already calls for but was never produced) plus a delta list of remaining work.

## Scope of "all work done till now"

Commits to review (oldest → newest, `git log --oneline` on `main`):

1. `4ac43ef` chore: initial commit (rebrand from sentinel)
2. `947ac90` chore: complete senti→dragon-scale rename in EC2 sync scripts
3. `d21d8af` chore(repo): restore Sentinel branding
4. `593dd25` Add files via upload (System Card PDF)
5. `5ee2457` fix(security): harden auth gateway compose and agent install
6. `2ba7aff` Fix/dragon scale stabilize 2026 05 11 (#2) — Wave 2 + Wave 3 bundle
7. `4143529` fix(ci): add compose-required env vars to e2e and integration CI
8. `88466a6` chore(repo): add missing commitlint scopes
9. `9ac1067` chore(main): release 1.0.0
10. `195c147` fix(xdp-collector): default xdp profile to bridge services (#14)
11. `380063e` fix(deps): repair container startup
12. `219373f` fix(xdp-collector): build xdp flow artifact (#17)
13. `5ac55c6` chore(main): release 1.0.1 (#15)

Authority documents the review checks against:

- `CODE-REVIEW-main-2026-04-18.md` — 7 critical findings + 20 suggestions, the original audit.
- `docs/superpowers/plans/2026-05-07-phase-0-security-stabilization.md` — Tasks 0–10, the implementation spec.
- `CLAUDE.md` "Phase 0 (active)" status block — claimed-done items.

## Shape of the check

```
  spec / audit claim ──► code in repo ──► test asserts it ──► CI runs the test
        │                    │                  │                   │
        └──────────────► one row in findings table with status ◄────┘

  status ∈ { ✅ closed  |  🟡 partial  |  ❌ open / regression }
```

For each row the reviewer fills in: file:line evidence, test name, CI workflow, and a one-line verdict. Anything < ✅ becomes a delta entry.

## Known gaps the reviewer must explicitly confirm

These I already spotted while planning — Kai should re-verify each, not take my word:

| # | Spec item | Where to look | Suspected state |
|---|---|---|---|
| G1 | Task 4 — `_internal_service_headers()` raises on empty `INTERNAL_SERVICE_TOKEN` | `sentinel-core/backend/api-gateway/app.py:175-182` | 🟡 — code only `logger.warning`s; never raises `RuntimeError`. Spec required refusal. |
| G2 | Task 6 — `init.sql` reduced to extensions/functions only; Alembic owns tables | `sentinel-core/init.sql`; `sentinel-core/backend/migrations/versions/` | ❌ — `init.sql` still contains `CREATE TABLE users / token_blacklist / tenants / audit_log / …`; no `20260417_001_consolidate_schema.py` / `_002_sso_scim_mfa.py` / `_003_enable_rls.py` migrations exist. |
| G3 | Task 7 Step 4 — explicit-origin CORS via `_load_cors_origins()` | `sentinel-core/backend/api-gateway/app.py:28` | ❌ — still `CORS(app)` (wildcard). Auth-service does parse `CORS_ORIGINS` but gateway does not. |
| G4 | Task 7 Step 5 — `auth_proxy` forwards `Authorization` header | `sentinel-core/backend/api-gateway/app.py:297-321` | ❌ — `auth_proxy` calls `requests.get/post/put/delete` without forwarding `Authorization`; `/api/v1/auth/profile`, `logout`, `change-password` will 401 through the gateway. |
| G5 | Task 7 Step 6 — strip `token` query param in `_proxy_to` | `sentinel-core/backend/api-gateway/app.py:635-660` | ❌ — `params=request.args` is still passed through. |
| G6 | Task 8 — only `xdp-collector` + `hardening-service` keep `privileged: true` | `sentinel-core/docker-compose.yml:177, 190, 407, 436` | 🟡 — four services still have `privileged: true`; spec wanted `data-collector` and `hids-agent` swapped to `cap_add`. Validator does not enforce. |
| G7 | Task 9 — `python:3.12-slim` pinned by digest on api-gateway + auth-service | `sentinel-core/backend/*/Dockerfile:1` | ❌ — every backend Dockerfile is `FROM python:3.12-slim` unpinned (12 files). |
| G8 | Task 10 — closure artifact | `sentinel-core/docs/reviews/phase-0-critical-fixes.md` | ❌ — file does not exist. |
| G9 | CLAUDE.md references `.team/specs/2026-05-12-ultraplan-baseline.md` | repo tree | ❌ — `.team/` directory does not exist. Either rename pointer in CLAUDE.md to the actual spec at `docs/superpowers/plans/2026-05-07-phase-0-security-stabilization.md`, or commit the missing file. |

## Execution

### Step 1 — collect ground truth

```bash
cd /home/user/repo
git log --oneline --first-parent main | head -20    # commit order in scope
git diff --stat 4ac43ef..HEAD -- sentinel-core/ | tail -5
gh pr list --state merged --base main --limit 20 2>/dev/null || true
```

Record the 13-commit window above in the closure artifact's header.

### Step 2 — verify each of the 7 audit criticals (`CODE-REVIEW-main-2026-04-18.md` Critical Issues 1–7)

For each row, fill:

```
| Audit # | File:line | Test | Verdict |
```

Specific checks:

- **Critical #1 (gateway RBAC).** Grep `@require_role("admin")` in `sentinel-core/backend/api-gateway/app.py` for `update_policy`, `delete_policy`, `acknowledge_alert`, `resolve_alert`, `update_alert`, `admin_get_users`, `admin_update_user`, `tenants_create`, `tenant_update`, `tenant_delete`. Confirm `test_*_viewer_forbidden` exists in `sentinel-core/backend/tests/test_api_gateway.py`. Already verified: lines 384–971 carry the decorators; tests exist.
- **Critical #2 (auth lockout ordering).** Confirm `auth-service/app.py:401-436` checks `status` → `login_attempts_exceeded` → dummy hash branch → `check_password`. Confirm tests `test_locked_account_rejects_correct_password_before_password_check`, `test_suspended_account_rejects_before_password_check`, `test_unknown_user_runs_dummy_password_check` in `test_auth_security.py` (lines 145, 173, 285).
- **Critical #3 (compose unsafe defaults).** Run `python sentinel-core/scripts/validate_compose_security.py`. Expect PASS. Confirm `${VAR:?set VAR}` syntax for the 5 required secrets in `docker-compose.yml:65, 135, 552, …`.
- **Critical #4 (installer signature/checksum).** Confirm `install.sh:33` enforces `https://*`, `install.sh:113` runs `sha256sum -c`, `install.sh:116-122` does optional cosign verify. Confirm `agent/tests/test_install_script.py` asserts these.
- **Critical #5 (`NoNewPrivileges=yes` on systemd unit).** Confirm `install.sh:178` is `NoNewPrivileges=yes`, `:179` has `CapabilityBoundingSet=`, `:180` has `AmbientCapabilities=`. Confirm `agent/tests/test_install_systemd_hardening.py`.
- **Critical #6 (empty `INTERNAL_SERVICE_TOKEN`).** Per **G1** above — code currently warns instead of refusing. Mark 🟡 and open a follow-up.
- **Critical #7 (internal services on `0.0.0.0`).** Validator covers it. Confirm `validate_compose_security.py:188-202` rejects internal `ports:` and `0.0.0.0:` host ports.

### Step 3 — verify each Phase 0 task (spec Tasks 1–10) against repo evidence

Walk Tasks 1 through 10 of `docs/superpowers/plans/2026-05-07-phase-0-security-stabilization.md`. For each task list its files and confirm:

1. File was modified/created at the path the spec called for (rename `dragon-scale-core/` → `sentinel-core/` mentally — the rebrand was reverted).
2. The test the spec dictated exists and asserts the same behavior.
3. The behavior matches: read each `Step` and ensure the actual code matches the snippet, not just shape.

Flag every divergence. Pay particular attention to **G1–G8** above.

### Step 4 — verify Wave 2 / Wave 3 / Wave 4 items claimed in CLAUDE.md

For each ✅ line in the CLAUDE.md "Phase 0 (active)" block:

- **`.gitattributes` LF normalization** → `cat .gitattributes`; grep for `* text=auto eol=lf`.
- **`bind_host()` helper** → `sentinel-core/backend/_lib/net.py` exists and is imported by every Flask `app.py`. `grep -rn "bind_host" sentinel-core/backend/*/app.py`.
- **`validate_compose_security.py` 7-finding assertion** → confirm the 7 invariants the spec specified are all enforced; spec wanted 7 forbidden defaults / 5 required secrets / installer + auth-test cross-checks. The current script does more than 7 — confirm the additional checks are not regressions.
- **`test_install_systemd_hardening.py`** → present.
- **Ruff `check` baseline (F401/F541)** → `ruff check sentinel-core/` from repo root; expect 0 findings for F401/F541. Note baseline scope from `pyproject.toml`.
- **Mypy lenient baseline (auth-service, policy-orchestrator, api-gateway)** → run `mypy` per the workflow; cross-reference against `pyproject.toml` allowlist.
- **Ruff `format` baseline** → `ruff format --check sentinel-core/`.
- **CI required-checks gate** → `.github/branch-protection.json` lists `lint`, `typecheck`, `unit`, `security`, `build`. Cross-reference against actual workflows in `.github/workflows/` (build, e2e-smoke, integration, lint, release-please, sbom, security, typecheck, unit). Note that `e2e-smoke`, `integration`, `sbom`, `release-please` are NOT in `required_status_checks` — confirm that is intentional.
- **Branch protection on `main`** → CLAUDE.md says ❌ Wave 4, still owned by Mir. Confirm: `gh api repos/MuzeenMir/sentinel/branches/main/protection` (skip if no token). This is the last open Wave-4 blocker before exit.

### Step 5 — run the spec's verification gate

From the spec's "Verification Gate Before Declaring Complete":

```bash
cd /home/user/repo/sentinel-core/backend
python -m pytest tests/ --ignore=tests/test_e2e_pipeline.py -v --tb=short
```

```bash
cd /home/user/repo/sentinel-core/frontend/admin-console
npm ci && npm run lint && npm run type-check && npm run test
```

```bash
cd /home/user/repo/sentinel-core
bash ../scripts/fresh_db_check.sh
python scripts/validate_compose_security.py
POSTGRES_PASSWORD=x JWT_SECRET_KEY=y ADMIN_PASSWORD=z GRAFANA_PASSWORD=g \
INTERNAL_SERVICE_TOKEN=t docker compose config >/tmp/sentinel-compose-final.yml
```

If any of these fail or are not runnable in the review environment (no Docker, no node, etc.), record the omission and the reason in the closure artifact rather than silently skipping.

### Step 6 — produce the closure artifact

Create `sentinel-core/docs/reviews/phase-0-critical-fixes.md` (the file Task 10 already specifies). Contents:

```markdown
# Phase 0 Critical Fixes Closure
Date: 2026-05-20
Reviewer: Kai

## Commits in scope
<13-commit list from Step 1>

## Audit Findings (CODE-REVIEW-main-2026-04-18.md)
| # | Finding | Status | File:line | Test | Notes |
|---|---|---|---|---|---|
| 1 | Gateway RBAC | ✅ | api-gateway/app.py:384–971 | test_api_gateway.py::test_*_viewer_forbidden | |
| 2 | Auth lockout ordering | ✅ | auth-service/app.py:401–436 | test_auth_security.py::test_locked_account_rejects_correct_password_before_password_check | |
| 3 | Compose unsafe defaults | ✅ | docker-compose.yml; validate_compose_security.py | test_compose_security.py | |
| 4 | Installer trust | ✅ | agent/install.sh:33,113,116 | test_install_script.py | |
| 5 | systemd NoNewPrivileges | ✅ | agent/install.sh:178–183 | test_install_systemd_hardening.py | |
| 6 | Empty INTERNAL_SERVICE_TOKEN | 🟡 | api-gateway/app.py:175–182 | none | Code warns, does not refuse. Open follow-up. |
| 7 | Internal services on 0.0.0.0 | ✅ | validate_compose_security.py:188–202 | test_compose_security.py | |

## Phase 0 Tasks (2026-05-07 spec)
| Task | Status | Evidence | Notes |
|---|---|---|---|
| 1 Auth ordering | ✅ | ... | |
| 2 Gateway RBAC | ✅ | ... | |
| 3 Compose hardening | ✅ | ... | |
| 4 Internal token strict | 🟡 | G1 | spec wanted RuntimeError + 503 route response |
| 5 Installer + systemd | ✅ | ... | |
| 6 Alembic source of truth | ❌ | G2 | init.sql still creates tables; no 20260417_* migrations |
| 7 CORS/auth-proxy/token | ❌ | G3,G4,G5 | wildcard CORS, auth-proxy drops auth header, no token-strip |
| 8 Privilege tightening | 🟡 | G6 | data-collector + hids-agent still privileged:true |
| 9 Dockerfile pinning | ❌ | G7 | 12 unpinned base images |
| 10 Closure artifact | ✅ (this file) | | |

## CLAUDE.md Wave items
<one row per ✅ / ❌ line, with verification command output>

## Verification Gate Output
<paste of pytest / lint / docker compose config results, or “not runnable: <reason>” lines>

## Delta — work still required for Phase 0 exit
1. Make `_internal_service_headers()` raise; return 503 from `/health` aggregator route.
2. Land migrations `20260417_001_consolidate_schema.py`, `_002_sso_scim_mfa.py`, `_003_enable_rls.py`; reduce `init.sql` to extensions + `update_updated_at_column()`.
3. Replace `CORS(app)` with explicit `_load_cors_origins()`; forward `Authorization` in `auth_proxy`; strip `token` query param in `_proxy_to`.
4. Swap `data-collector` and `hids-agent` from `privileged: true` to `cap_add: [NET_RAW, NET_ADMIN]` / `[BPF, PERFMON, SYS_ADMIN, SYS_RESOURCE]`; extend `validate_compose_security.py` with the `PRIVILEGED_ALLOWED` allowlist.
5. Pin `python:3.12-slim` by digest on at least `auth-service` and `api-gateway` Dockerfiles.
6. Fix `CLAUDE.md` pointer: either move/commit the spec at `.team/specs/2026-05-12-ultraplan-baseline.md` or change the pointer to `docs/superpowers/plans/2026-05-07-phase-0-security-stabilization.md`.
7. Wave 4: apply branch protection on `main` per `.github/branch-protection.json`.

## Sign-off
Phase 0 exit (7 green days on `main`) is **not** met until items 1–7 above are closed.
```

### Step 7 — commit the closure artifact

```bash
git checkout -b chore/phase-0-review-2026-05-20
git add sentinel-core/docs/reviews/phase-0-critical-fixes.md
git commit -m "docs(revamp): phase 0 closure review"
git push -u origin chore/phase-0-review-2026-05-20
```

Do not open a PR until Mir approves the delta list.

## Critical files / paths

Read-only inputs:
- `CODE-REVIEW-main-2026-04-18.md`
- `docs/superpowers/plans/2026-05-07-phase-0-security-stabilization.md`
- `CLAUDE.md`
- `sentinel-core/backend/api-gateway/app.py`
- `sentinel-core/backend/auth-service/app.py`
- `sentinel-core/backend/_lib/net.py`
- `sentinel-core/agent/install.sh`
- `sentinel-core/docker-compose.yml`
- `sentinel-core/init.sql`
- `sentinel-core/scripts/validate_compose_security.py`
- `sentinel-core/backend/tests/test_auth_security.py`
- `sentinel-core/backend/tests/test_api_gateway.py`
- `sentinel-core/backend/tests/test_compose_security.py`
- `sentinel-core/backend/tests/test_bind_host.py`
- `sentinel-core/agent/tests/test_install_script.py`
- `sentinel-core/agent/tests/test_install_systemd_hardening.py`
- `.github/workflows/*.yml`
- `.github/branch-protection.json`
- `.gitattributes`, `pyproject.toml`, `commitlint.config.js`

Write target:
- `sentinel-core/docs/reviews/phase-0-critical-fixes.md` (new)

## Verification (end-to-end)

The review itself is complete when:

1. Every row in the two findings tables of the closure artifact has a status + file:line + test name.
2. Steps 1–5 above were run (or each skip is justified inline).
3. The delta list in the artifact contains exactly the items in **G1–G9** that are still open after re-verification, and no other items.
4. `git diff --stat origin/main..HEAD` shows only one new file: `sentinel-core/docs/reviews/phase-0-critical-fixes.md`.
5. `gh pr create` is **not** run — wait for Mir's review of the delta.