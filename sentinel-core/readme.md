# SENTINEL — Core

Security platform for server/endpoint telemetry, AI-assisted detection, policy orchestration, and compliance reporting.

> **Status:** active v1 → v2 revamp. This README describes the currently shipping v1 implementation. Target v2 architecture is in `docs/revamp/`.

## Shipping today (v1)

- **Ensemble ML detection**: XGBoost + LSTM + Isolation Forest + Autoencoder. Accuracy figures from research; not production-benchmarked.
- **DRL policy research prototype**: PPO agent. Demoted — no production write path, no Kubernetes role permissions.
- **Real-time collection**: packet analysis with XDP/eBPF support (linux kernel only; build toolchain is fragile).
- **Explainability**: SHAP explanations via `xai-service`.
- **Compliance scaffolding**: framework stubs for GDPR / HIPAA / NIST CSF / PCI-DSS. Partial control mapping; no external certification.
- **Admin console**: React 18 + TypeScript + Vite.

## Architecture (current)

```
┌──────────────────────────────────────────────────────────────────┐
│                        Admin Console (React)                      │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────┐
│                         API Gateway                               │
│                 (Authentication, Rate Limiting, Routing)          │
└─────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────────┘
      │      │      │      │      │      │      │      │
   ┌──▼──┐ ┌─▼─┐ ┌──▼──┐ ┌─▼─┐ ┌──▼──┐ ┌─▼─┐ ┌──▼──┐ ┌─▼─┐
   │Auth │ │AI │ │Alert│ │DRL│ │Policy│ │XAI│ │Comp.│ │Data│
   │Svc  │ │Eng│ │Svc  │ │Eng│ │Orch. │ │Svc│ │Eng. │ │Coll│
   └──┬──┘ └─┬─┘ └──┬──┘ └─┬─┘ └──┬──┘ └─┬─┘ └──┬──┘ └─┬─┘
      │      │      │      │      │      │      │      │
┌─────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴─────────┐
│                     Message Queue (Kafka)                       │
└─────────────────────────────────────────────────────────────────┘
                                 │
           ┌─────────────────────┼─────────────────────┐
           │                     │                     │
      ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
      │PostgreSQL│          │  Redis  │          │ Models  │
      │   (DB)   │          │ (Cache) │          │(Storage)│
      └──────────┘          └─────────┘          └─────────┘
```

**v2 target:** 11 services collapse to 4 (`console`, `controller`, `analyzer`, `collector`) plus `llm-gateway`. See `docs/revamp/SDD-002.md`.

## Quick start

### Prerequisites

- Docker & Docker Compose v2+
- Node.js 18+ (frontend dev)
- Python 3.10+ (backend dev; Phase 2 moves to 3.12+)

### Dev setup

```bash
cp .env.example .env   # edit before start
docker compose up -d
```

Access:
- Admin console: http://localhost:3000
- API gateway: http://localhost:8080
- API docs: http://localhost:8080/docs

Initial admin credentials are set via `.env` (`ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`).

## Project structure

```
sentinel-core/
├── backend/
│   ├── ai-engine/          # ML detection
│   ├── alert-service/
│   ├── api-gateway/
│   ├── auth-service/
│   ├── compliance-engine/  # framework scaffolding
│   ├── data-collector/
│   ├── drl-engine/         # research prototype (demoted)
│   ├── policy-orchestrator/
│   ├── xai-service/        # SHAP
│   └── xdp-collector/      # eBPF/XDP
├── frontend/admin-console/
├── infrastructure/terraform/
├── stream-processing/flink-jobs/
├── docs/
│   ├── revamp/             # v2 SRS/SDD/SDP + GIT-RESTRUCTURE
│   └── adr/                # architecture decisions
├── docker-compose.yml
└── init.sql
```

Full spec index: [`docs/SPECIFICATIONS.md`](docs/SPECIFICATIONS.md). Quick refs: [`docs/security.md`](docs/security.md), [`docs/api-reference.md`](docs/api-reference.md), [`docs/ml-models.md`](docs/ml-models.md).

## API (v1, subject to change in v2)

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/login` | Login |
| POST | `/api/v1/auth/logout` | Logout |
| POST | `/api/v1/auth/refresh` | Refresh token |
| GET | `/api/v1/auth/profile` | Current user |

### Threats
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/threats` | List |
| GET | `/api/v1/threats/:id` | Detail |
| PUT | `/api/v1/threats/:id/status` | Update status |

### Policies
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/policies` | List |
| POST | `/api/v1/policies` | Create |
| PUT | `/api/v1/policies/:id` | Update |
| DELETE | `/api/v1/policies/:id` | Delete |

### Alerts
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/alerts` | List |
| POST | `/api/v1/alerts` | Create |
| POST | `/api/v1/alerts/:id/acknowledge` | Ack |
| POST | `/api/v1/alerts/:id/resolve` | Resolve |

v2 contracts pin these specs under `tests/contract/` (Phase 1).

## Configuration

See `.env.example`. Key variables:

| Variable | Description | Required |
|---|---|---|
| `JWT_SECRET_KEY` | JWT signing key | Yes |
| `POSTGRES_PASSWORD` | DB password | Yes |
| `ADMIN_USERNAME` | Initial admin | Yes |
| `ADMIN_PASSWORD` | Initial admin password | Yes |
| `ADMIN_EMAIL` | Initial admin email | Yes |

### Production deployment

Infrastructure is **scaffolded, not production-validated**. Before running in prod:

1. Generate strong passwords for every service.
2. Terminate TLS at an external load balancer.
3. Configure DB and Redis backups.
4. Wire real secrets management (AWS Secrets Manager or Vault).
5. Observability: OTel pilot lives in `api-gateway` (Phase 0); broad rollout is Phase 1.

## Development

### Backend services

```bash
cd backend/auth-service
python -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### Frontend

```bash
cd frontend/admin-console
npm install
npm run dev
```

### Tests

```bash
# Backend
cd backend/auth-service && pytest

# Frontend
cd frontend/admin-console && npm run test
```

## Infrastructure

Terraform modules target AWS (VPC, RDS Postgres Multi-AZ, ElastiCache Redis, MSK Kafka, ECS/EKS). Applying these to a new account has not been validated end-to-end.

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

## Security

- Sensitive data encrypted in transit and at rest where the backing store supports it.
- JWT with short TTL and refresh.
- Rate limiting at the API gateway.
- RBAC enforced at the auth service.
- Audit logging via `backend/audit_logger.py` (v2 moves this into a Postgres-role-enforced append-only table).

**Known gaps** (driving v2): no production-grade multi-tenancy, LLM-assisted triage not shipped, SOC2 not certified, SBOM + image signing not in CI.

## License

MIT — see [`../LICENSE`](../LICENSE).
