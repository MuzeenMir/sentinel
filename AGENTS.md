# SENTINEL — Agent context

Use this file for AI agents (Cursor, Bugbot, etc.) working in this repo.

## What this project is

SENTINEL is an enterprise-grade, AI-powered security platform for real-time threat detection, automated response, and compliance management. It aims to take a server from default installation to a hardened, monitored state.

## Repo layout

- **sentinel-core/** — Main application.
  - **backend/** — Python/Flask microservices (api-gateway, auth-service, ai-engine, drl-engine, policy-orchestrator, etc.).
  - **frontend/admin-console/** — React 18 + TypeScript + Vite dashboard.
  - **stream-processing/flink-jobs/** — Apache Flink Python jobs.
  - **training/** — ML/DRL training scripts.
  - **infrastructure/terraform/** — AWS Terraform.
- **.cursor/** — Cursor and Bugbot config: rules, skills, BUGBOT.md.

## Conventions

- **Security first**: No secrets in code; no eval/exec on untrusted input; parameterized SQL; auth and RBAC on APIs.
- **Docs**: Specification documents index in `sentinel-core/docs/SPECIFICATIONS.md`; specifications in `sentinel-core/docs/specifications/` (gitignored, distributed out-of-band). Quick refs: `sentinel-core/docs/security.md`, `sentinel-core/docs/api-reference.md`, `sentinel-core/docs/ml-models.md`.
- **Tests**: Backend and stream changes should include or update tests.
- **Dependencies**: Per-service `requirements.txt` for Python; `package.json` in frontend. Prefer MIT/Apache/BSD; avoid GPL/AGPL unless approved.

## Git — canonical remote

- **Primary (default) remote**: [https://github.com/MuzeenMir/sentinel](https://github.com/MuzeenMir/sentinel) — treat this as the main, original repository.
- **Pushes**: Use `origin` → `MuzeenMir/sentinel` for normal work (`git push origin <branch>`). Do not push to another remote or fork unless the user explicitly asks.

## Bugbot and Cursor

- Bugbot PR rules: `.cursor/BUGBOT.md`.
- Cursor rules: `.cursor/rules/*.mdc`.
- Project skills: `.cursor/skills/` (e.g. sentinel-security-review, sentinel-architecture).
