---
name: sentinel-architecture
description: Quick reference for SENTINEL architecture, service layout, and data flow. Use when navigating the codebase, adding features, or explaining how components connect.
---

# SENTINEL architecture reference

## Layout

| Area | Path | Purpose |
|------|------|---------|
| Backend services | `sentinel-core/backend/<service>/` | Flask apps; each has `app.py`, `requirements.txt`, Dockerfile |
| Frontend | `sentinel-core/frontend/admin-console/` | React + TS + Vite SPA |
| Stream processing | `sentinel-core/stream-processing/flink-jobs/` | Flink Python jobs, Kafka consumers |
| Training | `sentinel-core/training/` | ML/DRL training scripts |
| Infra | `sentinel-core/infrastructure/terraform/` | AWS Terraform |

## Flow

- Traffic → **API Gateway** (auth, rate limit) → backend services.
- Collectors (data-collector, xdp-collector, hids-agent) → **Kafka** → Flink → features; AI engine can run via HTTP or consume from Kafka.
- **DRL engine** → policy decisions → **Policy Orchestrator** → firewall adapters.
- **Compliance engine** and **XAI service** support compliance and explainability.

## Docs

- Specification index: `sentinel-core/docs/SPECIFICATIONS.md`
- Specifications (gitignored): `sentinel-core/docs/specifications/` (SRS, SDD, SAD, STP, SDP, Deployment/Ops, Security Architecture, API Spec)
- Security quick ref: `sentinel-core/docs/security.md`
- API quick ref: `sentinel-core/docs/api-reference.md`
- ML models: `sentinel-core/docs/ml-models.md`
