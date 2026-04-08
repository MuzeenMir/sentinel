# SENTINEL Security Platform

An enterprise-grade, AI-powered security platform for real-time threat detection, automated response, and compliance management.

## Features

- **AI-Powered Threat Detection**: Ensemble ML models (XGBoost, LSTM, Isolation Forest, Autoencoder) for comprehensive threat analysis
- **Deep Reinforcement Learning**: Automated firewall policy optimization using PPO agents
- **Real-Time Monitoring**: High-speed packet analysis with XDP/eBPF support
- **Explainable AI**: SHAP-based explanations for all detections
- **Compliance Engine**: Built-in frameworks for GDPR, HIPAA, NIST CSF, PCI-DSS
- **Modern Dashboard**: React-based admin console with real-time updates

## Architecture

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

## Quick Start

### Prerequisites

- Docker & Docker Compose v2+
- Node.js 18+ (for local frontend development)
- Python 3.10+ (for local backend development)

### Development Setup

1. **Clone and configure:**
```bash
cd sentinel-core
cp .env.example .env
# Edit .env with your configuration
```

2. **Start all services:**
```bash
docker compose up -d
```

3. **Access the platform:**
- Admin Console: http://localhost:3000
- API Gateway: http://localhost:8080
- API Documentation: http://localhost:8080/docs

### Default Credentials

Set in your `.env` file:
- Username: `ADMIN_USERNAME`
- Password: `ADMIN_PASSWORD`

## Project Structure

```
sentinel-core/
├── backend/
│   ├── ai-engine/          # ML threat detection service
│   ├── alert-service/      # Alert management & notifications
│   ├── api-gateway/        # Central API gateway
│   ├── auth-service/       # Authentication & authorization
│   ├── compliance-engine/  # Compliance frameworks
│   ├── data-collector/     # Network data ingestion
│   ├── drl-engine/         # Deep RL policy optimization
│   ├── policy-orchestrator/# Firewall policy management
│   ├── xai-service/        # Explainable AI service
│   └── xdp-collector/      # High-speed XDP collection
├── frontend/
│   └── admin-console/      # React admin dashboard
├── infrastructure/
│   └── terraform/          # AWS infrastructure as code
├── stream-processing/
│   └── flink-jobs/         # Apache Flink stream processing
├── docs/                   # Documentation and specifications index
├── docker-compose.yml      # Container orchestration
└── init.sql                # Database schema
```

For the complete specification document suite, see [docs/SPECIFICATIONS.md](docs/SPECIFICATIONS.md). Quick references: [docs/security.md](docs/security.md), [docs/api-reference.md](docs/api-reference.md), [docs/ml-models.md](docs/ml-models.md).

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | User login |
| POST | `/api/v1/auth/logout` | User logout |
| POST | `/api/v1/auth/refresh` | Refresh token |
| GET | `/api/v1/auth/profile` | Get current user |

### Threats
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/threats` | List threats |
| GET | `/api/v1/threats/:id` | Get threat details |
| PUT | `/api/v1/threats/:id/status` | Update threat status |

### Policies
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/policies` | List firewall policies |
| POST | `/api/v1/policies` | Create policy |
| PUT | `/api/v1/policies/:id` | Update policy |
| DELETE | `/api/v1/policies/:id` | Delete policy |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/alerts` | List alerts |
| POST | `/api/v1/alerts` | Create alert |
| POST | `/api/v1/alerts/:id/acknowledge` | Acknowledge alert |
| POST | `/api/v1/alerts/:id/resolve` | Resolve alert |

## Configuration

### Environment Variables

See `.env.example` for all available configuration options. Key variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `JWT_SECRET_KEY` | Secret key for JWT tokens | Yes |
| `POSTGRES_PASSWORD` | Database password | Yes |
| `ADMIN_USERNAME` | Initial admin username | Yes |
| `ADMIN_PASSWORD` | Initial admin password | Yes |
| `ADMIN_EMAIL` | Initial admin email | Yes |

### Production Deployment

For production deployments:

1. **Use secure passwords**: Generate strong passwords for all services
2. **Enable TLS**: Configure SSL certificates for all external endpoints
3. **Set up backups**: Configure database and Redis backups
4. **Monitor services**: Set up CloudWatch/Prometheus monitoring
5. **Use secrets management**: Integrate with AWS Secrets Manager or HashiCorp Vault

## Development

### Backend Services

Each backend service is a Python Flask application:

```bash
cd backend/auth-service
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
python app.py
```

### Frontend Development

```bash
cd frontend/admin-console
npm install
npm run dev
```

### Running Tests

```bash
# Backend tests
cd backend/auth-service
pytest

# Frontend tests
cd frontend/admin-console
npm run test
```

## Infrastructure

### AWS Deployment

Deploy to AWS using Terraform:

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your configuration

terraform init
terraform plan
terraform apply
```

### Required AWS Resources

- VPC with public/private subnets
- RDS PostgreSQL (Multi-AZ for production)
- ElastiCache Redis
- MSK Kafka cluster
- ECS/EKS for container orchestration
- Application Load Balancer
- SageMaker endpoints (optional, for ML inference)

## Security Considerations

- All sensitive data is encrypted at rest and in transit
- JWT tokens with short expiration and refresh mechanism
- Rate limiting on all API endpoints
- Role-based access control (RBAC)
- Audit logging for all actions
- Password strength requirements enforced

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

For enterprise support and custom deployments, contact: support@sentinel.io
