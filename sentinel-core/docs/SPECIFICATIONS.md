# SENTINEL Specification Documents

This project maintains a suite of professional software specification documents that define how SENTINEL is designed, built, tested, deployed, and maintained. These documents are the authoritative reference for all development activities.

## Document Location

Specification documents are stored in `docs/specifications/` and are **gitignored** (sensitive internal documentation, distributed out-of-band). If you do not have them locally, request them from the project lead or obtain them from the team's document management system.

## Document Index

| Document | ID | Description |
|----------|----|-------------|
| **SRS.md** | SENTINEL-SRS-001 | Software Requirement Specification. Defines all functional and non-functional requirements (IEEE 830). |
| **SDD.md** | SENTINEL-SDD-001 | Software Design Document. Describes internal design of every component, data design, interfaces, and patterns (IEEE 1016). |
| **SAD.md** | SENTINEL-SAD-001 | Software Architecture Document. Architectural views (building block, runtime, deployment), ADRs, quality attributes (Arc42). |
| **STP.md** | SENTINEL-STP-001 | Software Test Plan. Test strategy, levels, environments, entry/exit criteria, acceptance criteria. |
| **SDP.md** | SENTINEL-SDP-001 | Software Development Plan. Methodology, workflow, CI/CD, roadmap, maintenance plan, extension guide. |
| **DEPLOYMENT_AND_OPERATIONS.md** | SENTINEL-DOG-001 | Deployment and Operations Guide. All deployment models, configuration, monitoring, DR, scaling, troubleshooting. |
| **SECURITY_ARCHITECTURE.md** | SENTINEL-SECARCH-001 | Security Architecture Document. Threat model, auth architecture, encryption, compliance mapping, incident response. |
| **API_SPECIFICATION.md** | SENTINEL-API-001 | API Specification. Complete endpoint catalog, event schemas, SSE streams, webhook payloads, SDK guidelines. |

## In-Repo Quick References

The following documents remain tracked in git for quick developer reference:

| Document | Purpose |
|----------|---------|
| [security.md](security.md) | Security patterns, controls, and practices |
| [api-reference.md](api-reference.md) | Complete API endpoint reference for all services |
| [ml-models.md](ml-models.md) | ML/DRL model architecture, training, and deployment |
| [operations.md](operations.md) | Deployment, configuration, monitoring, and troubleshooting |
| [compliance-readiness.md](compliance-readiness.md) | SOC 2, ISO 27001, audit scope, and pen-test guidelines |
| [../sdk/README.md](../sdk/README.md) | Python SDK quick start and custom detector development |
| [../training/README.md](../training/README.md) | Training pipeline setup and datasets |
| [../readme.md](../readme.md) | Project overview and quick start |

## Document Lifecycle

These specifications are living documents. They should be updated when:
- New features are added or requirements change (update SRS, SDD, SAD).
- Test strategy evolves (update STP).
- Development process changes (update SDP).
- Deployment procedures change (update DOG).
- Security controls are added or modified (update SECARCH).
- API endpoints are added or modified (update API_SPECIFICATION).
