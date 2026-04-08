# SENTINEL — Claude Code project context

Use this file for Claude Code sessions in this repository. Primary application code lives under **`sentinel-core/`** (not the repo root alone).

## What this is

SENTINEL is an enterprise-grade, AI-powered security platform: real-time threat detection, automated response, DRL-driven policy, compliance, and hardening. The product goal is to move a server from a default install toward a hardened, monitored posture—security-first, least privilege, auditable behavior.

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
