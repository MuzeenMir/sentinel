# Code Audit — Dragon-Scale (Sentinel) `main`

- **Commit audited:** `2447371` (release v1.7.1)
- **Date:** 2026-06-19
- **Scope:** Full backend + CI/CD + docs. Read-only static audit (no runtime verification).
- **Method:** 5 parallel workstreams — docs/architecture, core security, security constraints, code substance & tests, CI/supply-chain. Every Critical/High carries a `file:line` or commit anchor.
- **Baseline:** re-tests the April 2026 `CODE-REVIEW-main-2026-04-18.md` thesis ("~60% real / ~40% scaffolding; marketing-grade claims") against the current tree.

---

## Executive summary

The platform is **materially more real and more secure than its own governance docs admit**, but it ships several **advertised controls that do not actually enforce** and a few **capabilities presented as functional that are inert in the default runtime**. There are **0 Critical** and **~10 High** findings. The dominant risk class has inverted since April: it is no longer overclaiming in shipped code — it is (a) CI gates that exist but aren't *required*, (b) governance docs (`CLAUDE.md`) frozen at v1.1.x while code reached v1.7.1, and (c) enforcement subsystems that silently degrade to no-ops.

**Hypotheses tested and refuted (genuinely solid):**
- **No cross-tenant data exposure.** RLS is enabled on 13 tables and tenant context is bound per-transaction on *every* DB path (SQLAlchemy `after_begin` listener + raw psycopg writers), failing closed to zero rows. `migrations/.../20260417_003_enable_rls.py:96-103`, `_lib/tenancy.py:89-92`.
- **No LLM output reaches enforcement.** Zero LLM imports in `policy-orchestrator`/`firewall-adapters`; copilot is propose→confirm (HMAC, single-use nonce, TTL) → *separate* admin-gated enforce call. `llm-gateway/tools.py:99-101`, `policy-orchestrator/app.py:336-337`.
- **Audit log is append-only at the Postgres role level**, not app code: `REVOKE UPDATE, DELETE, TRUNCATE ON audit_log` from `sentinel_app` (NOBYPASSRLS). `20260417_003_enable_rls.py:120-122`. Merkle verifier recomputes roots, cosign-keyless, fails closed.
- **No SQLi, no committed secrets, B1/B2 controls intact.** All dynamic SQL uses named params; AES-256-GCM secret crypto with fail-fast KEK.
- **70% coverage gate is genuinely enforced and honestly scoped** (no whole-service omits to inflate the number).

**Top risks (all High):**
1. The marquee **`audit-schema-guard` independent-review gate is not a required check** — bypassable (W5-01).
2. **LLM red-team & eval gates are self-validating / stubbed and non-gating** — marketing-grade security claims (W5-02, W5-03).
3. **eBPF/HIDS enforcement silently no-ops in containers** while returning `{"status":"ok"}** (SUB-03).

### Severity counts

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 10 |
| Medium | 16 |
| Low | 6 |
| Pass / refuted | 6 |

---

## Findings (severity-ranked)

| ID | WS | Title | Sev | Evidence |
|----|----|-------|-----|----------|
| CI-01 | CI | `audit-schema-guard` not in required checks → bypassable | High | `.github/branch-protection.json:2-9`; `audit-schema-guard.yml`; `audit_schema_guard.py:33-68` |
| CI-02 | CI | LLM red-team gate not required + self-validating (detectors hand-fit to 23-case corpus) | High | `llm-gateway-redteam.yml`; `evals/redteam/*.jsonl`; `safety.py:24-46` |
| CI-03 | CI | LLM eval "quality gate" runs a deterministic stub, never a model | High | `evals/run.py:32-52,78-81`; `llm-gateway-eval.yml:38-39` |
| CI-04 | CI | gitleaks allowlist blankets all `tests/`/`fixtures/` paths repo-wide | High | `.gitleaks.toml:12-26`; `security.yml:362` |
| SEC-01 | Sec | `docker-compose.prod.yml` adds zero container hardening | High | `docker-compose.prod.yml:1-110` |
| SEC-02 | Sec | Images tag-pinned not digest-pinned (incl. `zookeeper:latest`) | High | `docker-compose.yml:4,97,289,508`; `docker-compose.prod.yml:96` |
| SEC-03 | Sec | `hardening-service` runs `privileged: true` always-on with RW host `/etc` | High | `docker-compose.yml:486,473-474` |
| SUB-01 | Sub | `detection_engine` is real but wired into NO runtime service | High | `detection_engine/registry.py:64`; 0 non-test importers |
| SUB-02 | Sub | `plugins/` subsystem: 362 LOC, zero tests, no runtime consumers | High | `plugins/loader.py`, `plugins/registry.py`; 0 importers |
| SUB-03 | Sub | eBPF/HIDS enforcement silently degrades to no-op in containers, returns `ok` | High | `ebpf-lib/loader.py:71-74,144-149`; `hardening-service/app.py:1121` |
| SEC-04 | Sec | `/api/v1/policies/auto-apply` writes firewall rules without admin RBAC | Medium | `policy-orchestrator/app.py:631-640` |
| SEC-05 | Sec | T-027 claims cover `saml_configs`/`oidc_configs`; those columns are plaintext (tables unused) | Medium | `20260417_002_sso_scim_mfa.py:69,92`; `enterprise_auth.py:225-231` |
| SEC-06 | Sec | SCIM/SSO/update routes trust raw `request.get_json()` (no schema validation) | Medium | `enterprise_auth.py:710-718`; `app.py:782-786` |
| SEC-07 | Sec | Compose security *test* asserts validator logic, not `cap_drop`/`read_only`/pinning posture | Medium | `tests/test_compose_security.py:56-67` |
| CI-05 | CI | Real integration (`integration-compose`) + `e2e-smoke` are not required checks | Medium | `integration.yml:47-144`; `branch-protection.json:8` |
| CI-06 | CI | SBOM/cosign signing runs post-merge only — never gates a PR | Medium | `sbom.yml:55-60,148-168` |
| CI-07 | CI | Backend deps floating (`>=`), no pins/hashes; pip-audit scans loose spec | Medium | `*/requirements.txt` (e.g. `auth-service:2`, `api-gateway:1-14`) |
| CI-08 | CI | `detections-validate` (OPA/Rego) path-filtered, not required | Medium | `detections-validate.yml:4-27` |
| SUB-04 | Sub | Only true e2e test (`test_e2e_pipeline.py`) is CI-excluded | Medium | `unit.yml --ignore`; `test_e2e_pipeline.py:35-41` |
| SUB-05 | Sub | "Integration" pipeline test skips without out-of-band ML dataset | Medium | `test_integration_pipeline.py:25,53` |
| DOC-01 | Doc | CLAUDE.md version pointer stale (v1.1.3) vs actual v1.7.1 | Medium | `CLAUDE.md`; `28778dd` |
| DOC-02 | Doc | CLAUDE.md says llm-gateway = "410 shell"; it's a full propose-only copilot | Medium | `llm-gateway/app.py:5`; #56,#66-#71 |
| DOC-03 | Doc | CLAUDE.md `_lib` lists cim/otel/audit/llm_client; only `net`+`tenancy` exist | Medium | `ls _lib/`; `CLAUDE.md:54` |
| DOC-04 | Doc | CLAUDE.md marks T-031/T-027 pending; both merged | Medium | `944cd31` #46; `2b52275` #51 |
| DOC-05 | Doc | readme.md "Known gaps" understates shipped LLM-triage + SBOM/signing | Medium | `readme.md:228`; #56,#63 |
| ARC-01 | Arc | Architecture not consolidated to 4+1; still 13 discrete services | Medium | `ls backend/`; CLAUDE.md target |
| ARC-02 | Arc | `USE_V2_*` strangler flags mostly vestigial; only 1 is load-bearing | Medium | `policy-orchestrator/app.py:47-48,77` |
| SEC-08 | Sec | No per-event hash chain — intra-day audit tamper window before nightly root | Low (by design) | `audit_logger.py:178-210`; `merkle-root-publish.yml:11-12` |
| SEC-09 | Sec | `_extract_token` accepts JWT via `?token=` query param (log/referer leak) | Low | `auth_middleware.py:70` |
| SEC-10 | Sec | Vault/AWS secret-backend failures silently fall back to env vars | Low | `secrets_manager.py:107-126` |
| SUB-06 | Sub | Committed dead debug logger writes to a hardcoded foreign path | Low | `backend/conftest.py:31` (`/home/mir/...`) |
| DOC-06 | Doc | CLAUDE.md "Flask sunset by Phase 2" lags actual api-gateway FastAPI port | Low | `api-gateway/asgi_app.py:8`; #58,#59 |
| ARC-03 | Arc | Docs imply multi-tenancy unbuilt; RLS isolation actually shipped | Low | `readme.md:228` vs `20260417_003_enable_rls.py` |

---

## Per-workstream detail

### CI/CD & supply-chain (strongest theme)
The `security` aggregator check *is* genuinely wired (Trivy `exit-code 1`, CodeQL, semgrep `--error`, bandit HIGH→exit) and is required — that part is solid. The gap is the **required-check set in `.github/branch-protection.json:2-9`** (`lint,typecheck,unit,security,build,integration-migrations`). Multiple advertised gates run but are *not* required, so a red result does not block merge:
- **CI-01** `audit-schema-guard` — the control ADR-011/CLAUDE.md present as the tamper-evident independent-review gate for audit schemas/RLS/OPA. The script logic is correct (matches protected paths, requires two distinct trailers) but it is advisory only.
- **CI-02** red-team: `safety.py:24-46` `_INJECTION_PATTERNS` contains the exact literal strings used in the 23-line corpus (`evals/redteam/*.jsonl`) → the gate tests that the corpus matches itself; residual is structurally 0. Commit #68 advertises "fails if ANY attack slips through."
- **CI-03** eval: `evals/run.py:_reference_runner` is a deterministic stub that satisfies every published threshold (faithfulness 0.95 etc.) by construction; the live-model eval is nightly/manual and ungated.
- **CI-04** `.gitleaks.toml:12-26` allowlists `.*/tests?/.*` and `.*/fixtures/.*` repo-wide — a real credential committed under any test/fixture path is invisible.
- **CI-05..CI-08** integration-compose, e2e-smoke, SBOM/cosign, detections-validate all run but don't gate; backend deps float.

Root cause is concentrated in one file (`branch-protection.json`) plus the gitleaks allowlist and two stubbed oracles.

### Security posture
B1 (admin-RBAC on mutating routes) and B2 (lockout-before-bcrypt, `auth-service/app.py:461,482,484`) both verified intact. Container hardening is the weak spot (**SEC-01/02/03**): app images set `USER sentinel` at the image layer, but the prod compose overlay adds no `cap_drop`/`no-new-privileges`/`read_only`, images are mutable tags, and `hardening-service` is privileged-by-default with RW `/etc`. **SEC-04**: the DRL feed's `auto-apply` writes firewall rules with only `@require_auth`+`@require_tenant` — not an LLM-constraint breach (DRL is demoted) but it weakens the "write actions require human approval" claim. **SEC-05/06** are bounded (unused tables, behind-auth raw bodies).

### Code substance & tests
Most services are **real** (auth, api-gateway, policy-orchestrator, ai-engine, compliance, llm-gateway, integrations with real Splunk/Elastic/XSOAR/ServiceNow/Jira adapters). Three real-but-inert items (**SUB-01/02/03**) are "marketed as functional but not wired / silently no-op." Coverage gate is enforced and honest (`unit.yml` parses `coverage.xml` line-rate, `sys.exit(1)` if <70; omit set is narrow). e2e/integration tests are real but CI-excluded or skip-gated (**SUB-04/05**).

### Docs & architecture
`CLAUDE.md` is frozen near the Phase-0/1 boundary while code shipped through v1.7.1; all drift *understates* shipped work (no consumer-facing overclaim). Architecture has not yet consolidated 11→4+1 (**ARC-01**, expected mid-Phase-1) and the `USE_V2_*` strangler-routing described in SDD-002 is unimplemented (**ARC-02**).

---

## What's genuinely solid (counterweight)
- End-to-end RLS tenant isolation with fail-closed binding on all DB paths.
- Structural propose→approve→enforce separation for LLM/DRL outputs.
- Role-level audit immutability + recomputing, cosign-gated Merkle verifier.
- Real `security` aggregator gate (Trivy/CodeQL/semgrep/bandit all fail-gating); pip-audit ignores are individually justified with CVE IDs + revisit dates.
- AES-256-GCM secret envelope crypto; JWT verify fails closed on circuit-breaker open.
- Honest, enforced coverage gate; frontend deps fully locked (`package-lock.json`, `npm ci`).
- `drl-engine` correctly de-wired (string label only, no live import).

## Methodology & blind spots
Static read-only audit at `2447371`. **Not verified:** runtime behavior, actual prod branch-protection state on GitHub (audited the committed JSON, which may differ from live settings), whether `AUDIT_DATABASE_URL`/cosign identity secrets are configured in the deploy env (if unset, the Merkle tamper-evidence is dormant — `merkle-root-publish.yml:49-63`), and live-model LLM safety behavior.

---

## Remediation backlog (next steps)

Grouped into waves; each maps to the `.team/tickets/` process. No Criticals → no ship-blockers, but the High wave closes the gap between *advertised* and *enforced* controls.

### Wave A — Highs: make advertised controls actually enforce (do first)
- **A1 (CI-01):** Add `audit-schema-guard` to `branch-protection.json` required checks. *(S)* — single-line config; highest trust-to-effort ratio.
- **A2 (CI-04):** Replace blanket `tests?/`/`fixtures/` gitleaks path allowlists with rule-ID/regex-scoped entries; keep `venv`/`node_modules`. *(S)*
- **A3 (SUB-03):** Surface degraded eBPF/HIDS mode in `/enforce` + health responses (`dry_run:true` / non-200), instead of returning `ok`. *(M)*
- **A4 (SEC-01/02/03):** Harden prod compose — `cap_drop:[ALL]` + `no-new-privileges` + `read_only` on app services; digest-pin all images; least-privilege + profile-gate `hardening-service`, mount `/etc` ro. *(M)*
- **A5 (CI-02/CI-03):** De-stub the LLM gates — expand the red-team corpus with held-out/paraphrased attacks not in `_INJECTION_PATTERNS`; gate eval on a recorded live-model artifact, or relabel the CI step as plumbing-only. Make both required once meaningful. *(M)*
- **A6 (SUB-01/02):** Wire `detection_engine` registry into the ingest path (ai-engine/data-collector) and add `plugins/` tests + a consumer, or explicitly mark both as offline/experimental tooling. *(M)*

### Wave B — Highs/Mediums: CI teeth + doc honesty
- **B1:** Make `integration` (compose), `e2e-smoke`, `sbom` (PR path), and `detections-validate` required checks (CI-05/06/08). *(S)*
- **B2:** Refresh `CLAUDE.md` (version pointer → v1.7.1; T-031/T-027 closed; llm-gateway C1–C7 shipped; `_lib` actual contents; api-gateway already FastAPI) and `readme.md` known-gaps (DOC-01..06). *(S)* — cheap, prevents every future session inheriting stale truth.
- **B3 (SEC-04):** Add admin RBAC (or an explicit documented exception with a human-approval step) to `/api/v1/policies/auto-apply`. *(S)*
- **B4 (CI-07):** Compile a pinned lockfile (`pip-compile`/`uv lock`) with `--require-hashes`; audit the lockfile. *(M)*

### Wave C — Medium hardening
- **C1 (SEC-06):** pydantic/marshmallow schemas for SCIM/SSO/update bodies; allow-list `UserRole` parsing. *(M)*
- **C2 (SEC-05):** When DB-backed SSO config lands, route `sp_private_key`/`client_secret` through `secret_crypto.encrypt()`; until then fix the claim wording. *(S now / M later)*
- **C3 (SEC-07):** Extend `validate_compose_security.py` to assert `cap_drop`/`no-new-privileges`/digest-pinning. *(M)*
- **C4 (SUB-04/05):** Add a scheduled CI job that runs `test_e2e_pipeline.py` against a compose/testcontainers stack; commit/generate a tiny fixture model so integration tests execute. *(M)*
- **C5 (ARC-01/02):** Document consolidation + `USE_V2_*` strangler routing as not-yet-implemented; don't market as achieved. *(S)*

### Wave D — Low / cleanup
- **D1 (SUB-06):** Remove the dead `/home/mir/...` debug logger in `conftest.py:31`. *(S)*
- **D2 (SEC-09):** Drop `?token=` query-param JWT acceptance; header-only. *(S)*
- **D3 (SEC-10):** Log loudly (or fail closed by config) when Vault/AWS secret backends fall back to env. *(S)*
- **D4 (SEC-08):** Optional: intra-day incremental Merkle roots or a real `prev_event_hash` chain if sub-day tamper-evidence is required. *(L)*
- **D5 (ops):** Confirm `AUDIT_DATABASE_URL` + cosign identity secrets are set in prod so the Merkle gate is active, not dormant. *(S)*

### Suggested sequencing
A1 → A2 → B2 (all S, immediate trust + honesty wins) → A3/A4 → A5/A6 → Wave B remainder → C → D.

---

## Remediation closure (2026-06-26)

The remediation backlog above is preserved as the original audit record. This section records
**what actually shipped** against it. As of 2026-06-26 the repository is at **v1.8.0** and the
Wave A–D backlog is materially complete: every finding is either **Closed** in code, resolved
**By-design** (the audit offered an explicit alternative, which was taken), or **Deferred** as a
tracked forward item. Forward work is captured in
[`next-steps-2026-06-26.md`](./next-steps-2026-06-26.md).

| Finding(s) | Wave | Resolution | Status | Closing PR |
|------------|------|-----------|--------|------------|
| CI-01 | A1 | `audit-schema-guard` added to `branch-protection.json` required checks | Closed | #77 |
| CI-04 | A2 | Blanket `tests?/`/`fixtures/` gitleaks allowlists removed; placeholder regexes retained | Closed | #77 |
| SUB-03 | A3 | eBPF/HIDS degraded mode surfaced (`/health` `ebpf_degraded`; `/enforce` `dry_run`; port returns 202 "recorded") instead of faking `ok` | Closed | #77 |
| SEC-01, SEC-02, SEC-03 | A4 | Prod overlay `cap_drop:[ALL]`+`no-new-privileges`+`read_only`; all images digest-pinned; `hardening-service` least-priv + ro `/etc` | Closed | #77 |
| CI-02 | A5 | Red-team detector de-stubbed (intent-shaped regexes + held-out paraphrase corpus `injection_heldout.jsonl`) | Closed (code) | #77 |
| CI-03 | A5 | Eval relabeled plumbing-only in workflow + `evals/run.py` docstrings; stub no longer presented as a quality gate | By-design | #77 |
| SUB-01, SUB-02 | A6 | `detection_engine` + `plugins` marked EXPERIMENTAL/OFFLINE in module docstrings; `tests/test_plugins.py` added | By-design (alt taken) | #77 |
| CI-05, CI-06, CI-08 | B1 | `integration-compose`, `e2e-smoke-api`, `e2e-smoke-ui`, `sbom`, `detections-validate` made required | Closed | #82 |
| DOC-01..06, ARC-02, ARC-03 | B2/C5 | `CLAUDE.md` + `readme.md` synced to shipped reality | Closed | #78 |
| SEC-04 | B3 | Admin RBAC added to `/api/v1/policies/auto-apply` | Closed | #79 |
| CI-07 | B4 | Hashed lockfiles + `--require-hashes` installs; `lockfile-verify` required | Closed | #88, #89 |
| SEC-06 | C1 | SCIM/SSO/update bodies validated; allow-list `UserRole` parsing | Closed | #86 |
| SEC-05 | C2 | Encryption-at-rest claim wording corrected (columns stay plaintext until DB-backed SSO lands) | By-design (now) / Deferred (encryption) | #87 |
| SEC-07 | C3 | `validate_compose_security.py` asserts `cap_drop`/`no-new-privileges`/digest-pinning | Closed | #83 |
| SUB-04, SUB-05 | C4 | Scheduled CI runs `test_e2e_pipeline.py`; integration test gets a committed fixture model | Closed | #91 |
| ARC-01 | C5 | 11→4+1 consolidation documented as not-yet-built (not marketed as done) | By-design | #78 |
| SUB-06 | D1 | Dead `/home/mir/...` conftest logger removed | Closed | #84 |
| SEC-09 | D2 | `?token=` query-param JWT acceptance dropped (header-only) | Closed | #84 |
| SEC-10 | D3 | Vault/AWS secret-backend fallback now loud / fail-closed by config | Closed | #84 |
| SEC-08 | D4 | Per-event audit hash chain added (code sound; **review-trail** noted below) | Closed | #90 |
| ops (Merkle dormancy) | D5 | CI fails loudly when audit-ledger anchor is dormant + activation runbook | Closed | #93 |

### Deliberately left open (tracked, not oversights)

- **A5.3 — red-team gate not a *required* check.** The detector is now meaningful (held-out corpus),
  but `llm-gateway-redteam.yml` is **path-filtered** to `sentinel-core/backend/llm-gateway/**`. A
  required path-filtered check would leave every non-LLM PR stuck on "Expected — waiting for status"
  (the failure mode `audit-schema-guard` avoids by running on all PRs and exiting 0 when no guarded
  path changes). Making it required requires restructuring the trigger first — tracked in the
  next-steps roadmap. The **eval** gate (CI-03) is intentionally plumbing-only per its own header and
  should stay non-required.
- **A6.3 — `detection_engine`/`plugins` not wired to runtime.** The audit allowed "wire it **OR**
  mark both offline/experimental"; the experimental-marker path was taken. Wiring is a forward item.
- **SEC-05 encryption.** `saml_configs`/`oidc_configs` columns remain plaintext because the tables
  are unused; routing `sp_private_key`/`client_secret` through `secret_crypto.encrypt()` lands when
  DB-backed SSO config actually ships.

### Process note — D4 (SEC-08) review-trail

The D4 *code* is sound (independently re-reviewed — see
[`D4-marcus-retro-review-2026-06-26.md`](./D4-marcus-retro-review-2026-06-26.md)), but #90 was
**admin-merged past a red `audit-schema-guard`** with no `Audit-Reviewed-by`/`Audit-Approved-by`
trailers. The retro review is recorded honestly as **same-model** (Claude reviewing Claude-authored
code): PASS on the merits, independence not satisfied. The cross-model-independence premise itself is
no longer available (Codex/"Kai" retired) and was formally downgraded in
[ADR-022](../adr/ADR-022-review-gate-cross-model-independence.md). So D4's *code* is Closed; its
audit-*trail* is documented rather than retroactively greened — #90 stands as merged-via-admin-override.
