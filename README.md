# DRAGON_SCALE

Server and endpoint security platform: telemetry collection, AI-assisted detection, policy orchestration, and compliance reporting. Deployed via Docker Compose (dev) or Terraform/AWS (infra scaffolded, not production-validated).

> **Status:** active development. This repository is mid-revamp (v1 → v2). Claims below describe what currently ships. Target architecture and timeline live in `dragon-scale-core/docs/revamp/`. An April 2026 audit (`CODE-REVIEW-main-2026-04-18.md`) drives the v2 plan.

## What ships today (v1)

- **Backend microservices** (Flask, Python): auth, API gateway, alert, AI engine, XAI, data collector, policy orchestrator, compliance engine, DRL engine (demoted to research), hardening service.
- **Admin console** (React 18 + TypeScript + Vite): dashboard, policy and alert views.
- **Stream processing**: Apache Flink jobs over Kafka.
- **ML detection**: XGBoost, LSTM, Isolation Forest, Autoencoder ensemble. Accuracy numbers are research-grade, not production benchmarks.
- **Explainability**: SHAP integration via XAI service.
- **Compliance engine**: framework scaffolding for GDPR / HIPAA / NIST CSF / PCI-DSS. Control mapping is partial; no external certification.
- **Infrastructure**: Terraform modules for AWS (VPC, RDS, ElastiCache, MSK). Not deployed or validated end-to-end in production.

## What does not yet ship (deferred to v2)

- Real multi-tenant isolation with Postgres RLS.
- LLM-assisted triage (llm-gateway is a Phase 1 shell returning `HTTP 410`).
- Consolidated services (11 → 4 + llm-gateway is a v2 goal).
- SSO / SCIM, billing, SOC2 certification.
- Helm charts and Kubernetes production deploy.
- SBOM + cosign signed releases (Phase 0 in progress).
- Signed, append-only audit at the Postgres role level.

## Quick start (dev)

```bash
cd dragon-scale-core
cp .env.example .env           # edit before starting
docker compose up -d
```

Typical URLs (dev compose):

- Admin console: http://localhost:3000
- API gateway: http://localhost:8080
- API docs: http://localhost:8080/docs

Initial admin credentials are set via `ADMIN_USERNAME` / `ADMIN_PASSWORD` / `ADMIN_EMAIL` in `.env`.

## Repository layout

```
dragon-scale-core/
├── backend/                    # Flask microservices
├── frontend/admin-console/     # React + Vite admin UI
├── stream-processing/          # Flink jobs
├── training/                   # ML / DRL training scripts
├── infrastructure/terraform/   # AWS Terraform (scaffolded)
├── docs/                       # Quick refs + specifications index
│   └── revamp/                 # v2 design docs (SRS/SDD/SDP, GIT-RESTRUCTURE, ADRs)
├── tests/                      # Integration + e2e
└── docker-compose.yml
```

A git-flatten of `dragon-scale-core/` → repo root is scheduled in Phase 0 of the revamp. After that lands, these paths move up one level.

## Documentation

- **Specification index**: `dragon-scale-core/docs/SPECIFICATIONS.md`
- **Quick refs**: `dragon-scale-core/docs/security.md`, `dragon-scale-core/docs/api-reference.md`, `dragon-scale-core/docs/ml-models.md`
- **Overview**: `dragon-scale-core/readme.md`
- **v2 revamp**: `dragon-scale-core/docs/revamp/README.md` and siblings
- **ADRs**: `dragon-scale-core/docs/adr/`
- **Backlog**: `dragon-scale-core/docs/revamp/BACKLOG.md`

## Contributing

- Conventional Commits required (`commitlint.config.js`). Scopes include `collector | analyzer | controller | console | agent | llm-gateway | revamp | opa | helm | ci | docs | migrations | deps`.
- Pre-commit hooks via `.pre-commit-config.yaml`. Install with `pre-commit install`.
- `CODEOWNERS` gates review. Squash-merge only; signed commits required on `main`.

## License

MIT — see `LICENSE`.
