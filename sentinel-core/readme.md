# SENTINEL - AI-Powered Intrusion Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![React 18](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev)

## Overview

SENTINEL is an enterprise-grade AI-powered Intrusion Detection System (IDS) with Deep Reinforcement Learning (DRL) based firewall policy generation. The platform provides:

- **Real-time Threat Detection** using ensemble ML models (XGBoost, LSTM, Isolation Forest)
- **Autonomous Policy Generation** via PPO-based Deep Reinforcement Learning
- **Multi-Vendor Firewall Integration** (iptables, AWS Security Groups, Palo Alto)
- **Explainable AI** with SHAP-based decision explanations
- **Compliance Management** for GDPR, HIPAA, PCI-DSS, NIST CSF

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      SENTINEL Platform                          │
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Data      │───▶│   AI        │───▶│    DRL      │         │
│  │  Collector  │    │  Engine     │    │   Engine    │         │
│  └─────────────┘    └─────────────┘    └──────┬──────┘         │
│         │                                      │                 │
│         ▼                                      ▼                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Kafka     │    │    XAI      │    │   Policy    │         │
│  │   (MSK)     │    │  Service    │    │Orchestrator │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Compliance  │    │   Alert     │    │    Auth     │         │
│  │   Engine    │    │  Service    │    │  Service    │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+
- Node.js 18+

### Local Development

```bash
# Clone the repository
git clone https://github.com/MuzeenMir/sentinel.git
cd sentinel/sentinel-core

# Copy environment file and set your values (JWT_SECRET_KEY, ADMIN_*, etc.)
cp sentinelenv.example sentinelenv
# Edit `sentinelenv` with JWT_SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_EMAIL

# Start all services
docker compose --env-file sentinelenv up -d

# Start frontend (development)
cd frontend/admin-console
npm install
npm run dev
```

Access the admin console at `http://localhost:3000`

### Production Deployment (AWS)

```bash
cd infrastructure/terraform
terraform init
terraform apply
```

See [Deployment Guide](docs/deployment-guide.md) for detailed instructions.

## Services

| Service | Port | Description |
|---------|------|-------------|
| API Gateway | 8080 | Main API entry point |
| Auth Service | 5001 | Authentication & authorization |
| Alert Service | 5002 | Notification management |
| AI Engine | 5003 | ML-based threat detection |
| Policy Orchestrator | 5004 | Firewall rule management |
| DRL Engine | 5005 | Reinforcement learning decisions |
| XAI Service | 5006 | Explainability & audit trails |
| Compliance Engine | 5007 | Regulatory compliance |
| Data Collector | 5008 | Network traffic ingestion |
| Admin Console | 3000 | Web UI (development) |

## Detection Capabilities

### Supervised Detection (Known Threats)
- Malware communication
- DoS/DDoS attacks
- Brute force attacks
- Port scanning
- SQL injection
- XSS attacks
- Data exfiltration

### Unsupervised Detection (Zero-Day)
- Anomalous traffic patterns
- Behavioral deviations
- Protocol anomalies

## DRL Policy Actions

| Action | Description |
|--------|-------------|
| ALLOW | Permit traffic |
| DENY | Block traffic |
| RATE_LIMIT | Throttle connection rate |
| QUARANTINE | Isolate host |
| MONITOR | Enhanced logging |

## Configuration

Key environment variables:

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/db

# Redis
REDIS_URL=redis://localhost:6379

# Kafka
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# AI Engine
CONFIDENCE_THRESHOLD=0.85
BATCH_SIZE=32

# DRL
DRL_LEARNING_RATE=0.0003
DRL_DISCOUNT_FACTOR=0.99
```

## Documentation

- [Architecture](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Deployment Guide](docs/deployment-guide.md)
- [ML Models](docs/ml-models.md)
- [Security](docs/security.md)

## API Example

```bash
# Authenticate
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Run detection
curl -X POST http://localhost:8080/api/v1/detect \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "traffic_data": {
      "source_ip": "192.168.1.100",
      "dest_ip": "10.0.0.1",
      "dest_port": 22,
      "protocol": "TCP"
    }
  }'
```

## Technology Stack

- **Backend**: Python, Flask, Gunicorn
- **Frontend**: React 18, TypeScript, Tailwind CSS
- **ML/DL**: PyTorch, XGBoost, scikit-learn
- **RL**: Stable-Baselines3, Gymnasium
- **Streaming**: Apache Kafka (MSK), Apache Flink
- **Database**: PostgreSQL, Redis
- **Infrastructure**: Terraform, Docker, AWS ECS
- **Monitoring**: CloudWatch, Prometheus (optional)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.sentinel.example.com
- Issues: https://github.com/MuzeenMir/sentinel/issues
- Security: security@sentinel.example.com
