# SENTINEL — Claude Code project context

Use this file for Claude Code sessions in this repository. Primary application code lives under **`sentinel-core/`** (not the repo root alone — flatten to root is a Phase 0 task, see below).

## SENTINEL v2 Revamp — Active Phases

**Reference:** `sentinel-core/docs/revamp/` (README, SRS-002, SDD-002, SDP-002, GIT-RESTRUCTURE, CLAUDE-DESIGN-WORKFLOW). Driver: `CODE-REVIEW-main-2026-04-18.md` audit — v1 is ~60% real, ~40% scaffolding; chronic CI failures, schema drift, marketing-grade claims.

**Architecture target:** 11 services → 4 + LLM Gateway
- `console` ← api-gateway + auth-service + dashboard
- `controller` ← alert-service + policy-orchestrator (read) + audit
- `analyzer` ← ai-engine + xai-service + Bytewax stream
- `collector` ← data-collector + agent-grpc + sensor skeletons (Falco/Suricata/Wazuh/OpenSCAP)
- `llm-gateway` ← new (Gemma 4, TurboQuant); Phase 1 = shell returning 410

**Phase 0 (4 wks, active):** stabilize — 8 split CI workflows, idempotent migrations, honest README, secrets sweep, SBOM+cosign, OTel pilot, git flatten `sentinel-core/`→root, CODEOWNERS, commitlint, trunk-based. Exit: 7 consecutive green days on `main`.

**Phase 1 (8 wks, blocked on Phase 0):** consolidate behind `USE_V2_*` JWT flags — shared `backend/_lib/` (cim, tenancy, otel, audit, llm_client), Helm scaffold, PG16 + pgvector + RLS, Kafka 3 per-tenant topics, Redis 7, Tempo. Exit: `sentinel-internal` canary runs 14 days on v2 with zero P0/P1 regressions.

**Hard constraints:**
- No LLM output reaches enforcement adapters — write actions require human approval.
- Audit log is append-only at the Postgres role level (not app code).
- DRL demoted to research; no Kubernetes role permissions.
- Python 3.12+ backend, FastAPI (Flask sunset by Phase 2); TypeScript 5.x strict, React 18.
- Conventional Commits mandatory; squash-merge only; signed commits on `main`.
- Two-person rule for OPA bundles, model promotions, Helm prod values, RLS policies, audit schemas.

**Do not (Phase 0/1):** decommission v1 services, remove compliance-engine, touch drl-engine beyond archival, or land real LLM inference (that's Phase 2+).

## What this is

SENTINEL is a server/endpoint security platform: telemetry collection, AI-assisted detection, policy orchestration, and compliance reporting. **Current shipping scope (v1):** Flask microservices, React admin console, Kafka/Flink stream processing, ML-based anomaly detection, DRL policy prototype (demoted), Terraform AWS deployment. Marketing-grade claims ("enterprise-grade", production-ready compliance) are **not** accurate for v1 — they describe the v2 target.

## Repository layout

| Area | Path | Notes |
|------|------|--------|
| Backend (Flask microservices) | `sentinel-core/backend/<service>/` | Each service: `app.py`, `requirements.txt`, often Dockerfile |
| Admin UI | `sentinel-core/frontend/admin-console/` | React 18, TypeScript, Vite |
| Stream processing | `sentinel-core/stream-processing/flink-jobs/` | Apache Flink (Python), Kafka-oriented jobs |
| Training | `sentinel-core/training/` | ML / DRL training scripts |
| Infrastructure | `sentinel-core/infrastructure/terraform/` | AWS Terraform |
| Cursor / Bugbot | `.cursor/` | Rules, skills, BUGBOT—parallel to this file for Cursor |

## Architecture (data flow)

- Client traffic → **API Gateway** (auth, rate limits, routing) → domain services.
- Collectors and pipelines → **Kafka** → Flink → features; **AI engine** integrates via HTTP and/or Kafka consumption.
- **DRL engine** → policy decisions → **Policy orchestrator** → firewall adapters.
- **Compliance engine** and **XAI** support compliance reporting and explainability.

## Conventions (non-negotiable)

- **No secrets in source**: environment variables and `.env.example` placeholders only; never commit keys, passwords, or tokens.
- **Safe handling of input**: no `eval` / `exec` on untrusted data; parameterized SQL; auth and RBAC on APIs.
- **Errors**: log and handle failures; avoid bare `except:` or silent swallowing without logging.
- **Dependencies**: Prefer MIT/Apache/BSD; avoid GPL/AGPL unless explicitly approved.
- **Tests**: Backend and stream-processing changes should include or update tests where applicable.

## Documentation

- Specification index: `sentinel-core/docs/SPECIFICATIONS.md`
- Full specifications may live in `sentinel-core/docs/specifications/` (often gitignored; distributed separately).
- Quick refs: `sentinel-core/docs/security.md`, `sentinel-core/docs/api-reference.md`, `sentinel-core/docs/ml-models.md`
- Human overview: `sentinel-core/readme.md`
- Cursor-oriented agent summary: `AGENTS.md` (root)

## Common commands

Most day-to-day work assumes `cd sentinel-core` unless noted.

**Stack (Docker)**

```bash
cd sentinel-core
cp .env.example .env   # then edit
docker compose up -d
```

Typical URLs after compose (see `readme.md` for current ports): admin console ~`http://localhost:3000`, API gateway ~`http://localhost:8080`, docs ~`http://localhost:8080/docs`.

**Frontend (`sentinel-core/frontend/admin-console/`)**

```bash
npm install
npm run dev          # Vite dev server
npm run build
npm run test         # Vitest
npm run lint
npm run type-check
```

**Python backend**

- Per-service virtualenv and `pip install -r requirements.txt` under `sentinel-core/backend/<service>/`.
- Run patterns vary by service; check each service’s `readme` or `Dockerfile` for the intended entrypoint.

## Git

- **Canonical remote**: `https://github.com/MuzeenMir/sentinel` — use `origin` → that repo for normal pushes unless the user says otherwise.

## Optional local overrides

For personal Claude Code notes that should not be shared, use **`CLAUDE.local.md`** in the project root and add it to `.gitignore` if you create it.
