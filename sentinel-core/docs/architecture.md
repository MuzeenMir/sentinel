# SENTINEL Architecture Documentation

## System Overview

SENTINEL is an enterprise-grade AI-powered Intrusion Detection System (IDS) with Deep Reinforcement Learning (DRL) based firewall policy generation. The platform provides autonomous threat detection, intelligent policy decisions, and comprehensive compliance management.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SENTINEL Platform                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Data Ingestion Layer                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │   │
│  │  │   PCAP       │  │  NetFlow     │  │   sFlow      │           │   │
│  │  │  Capture     │  │  v5/v9       │  │   Parser     │           │   │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │   │
│  │         │                 │                 │                    │   │
│  │         └─────────────────┼─────────────────┘                    │   │
│  │                           ▼                                      │   │
│  │              ┌────────────────────────┐                          │   │
│  │              │   CIM Normalizer       │                          │   │
│  │              └───────────┬────────────┘                          │   │
│  └──────────────────────────┼───────────────────────────────────────┘   │
│                             ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Apache Kafka (MSK)                            │   │
│  │        ┌─────────────────────────────────────────┐              │   │
│  │        │  normalized_traffic │ alerts │ features │              │   │
│  │        └─────────────────────────────────────────┘              │   │
│  └──────────────────────────┬───────────────────────────────────────┘   │
│                             ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                Stream Processing (Apache Flink)                  │   │
│  │  ┌────────────────────────────────────────────────────────┐     │   │
│  │  │  Feature Extraction │ Windowing │ Anomaly Detection    │     │   │
│  │  └────────────────────────────────────────────────────────┘     │   │
│  └──────────────────────────┬───────────────────────────────────────┘   │
│                             ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    AI Detection Engine                           │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │   │
│  │  │   XGBoost    │  │    LSTM      │  │  Isolation   │           │   │
│  │  │  Classifier  │  │  Sequence    │  │   Forest     │           │   │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │   │
│  │         │                 │                 │                    │   │
│  │         └─────────────────┼─────────────────┘                    │   │
│  │                           ▼                                      │   │
│  │              ┌────────────────────────┐                          │   │
│  │              │   Ensemble Classifier  │                          │   │
│  │              └───────────┬────────────┘                          │   │
│  └──────────────────────────┼───────────────────────────────────────┘   │
│                             ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    DRL Policy Engine                             │   │
│  │  ┌────────────────────────────────────────────────────────┐     │   │
│  │  │  State Builder │ PPO Agent │ Reward Function            │     │   │
│  │  └────────────────────────────────────────────────────────┘     │   │
│  │                           │                                      │   │
│  │                           ▼                                      │   │
│  │              ┌────────────────────────┐                          │   │
│  │              │   Action Decision      │                          │   │
│  │              │  ALLOW│DENY│RATE_LIMIT │                          │   │
│  │              └───────────┬────────────┘                          │   │
│  └──────────────────────────┼───────────────────────────────────────┘   │
│                             ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  Policy Orchestrator                             │   │
│  │  ┌────────────────────────────────────────────────────────┐     │   │
│  │  │  Rule Generator │ Validator │ Conflict Detection       │     │   │
│  │  └────────────────────────────────────────────────────────┘     │   │
│  │                           │                                      │   │
│  │         ┌─────────────────┼─────────────────┐                   │   │
│  │         ▼                 ▼                 ▼                   │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │   │
│  │  │  iptables    │  │ AWS Security │  │  Palo Alto   │           │   │
│  │  │  Vendor      │  │   Groups     │  │   (Future)   │           │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  Supporting Services                             │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │   │
│  │  │    XAI     │ │ Compliance │ │   Alert    │ │    Auth    │   │   │
│  │  │  Service   │ │  Engine    │ │  Service   │ │  Service   │   │   │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Data Storage                                  │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │   │
│  │  │ PostgreSQL │ │   Redis    │ │ TimescaleDB│ │     S3     │   │   │
│  │  │  (RDS)     │ │(ElastiCache│ │ (Optional) │ │  (Models)  │   │   │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Data Ingestion Layer
- **Data Collector Service**: Captures network traffic via raw sockets, NetFlow v5/v9, and sFlow
- **CIM Normalizer**: Converts heterogeneous data to Common Information Model format
- **Kafka Integration**: Reliable message queuing for event streaming

### 2. Stream Processing
- **Apache Flink Jobs**: Real-time feature extraction with tumbling, sliding, and session windows
- **Statistical Features**: Packet size distribution, inter-arrival times, byte rates
- **Behavioral Features**: Entropy calculations, connection patterns, protocol analysis

### 3. AI Detection Engine
- **XGBoost Detector**: Gradient boosting for known threat classification
- **LSTM Sequence Detector**: Deep learning for temporal attack patterns
- **Isolation Forest**: Unsupervised anomaly detection
- **Autoencoder**: Reconstruction-based anomaly detection
- **Ensemble Classifier**: Weighted combination of all models

### 4. DRL Policy Engine
- **PPO Agent**: Proximal Policy Optimization for policy decisions
- **State Builder**: Constructs state vectors from threat context
- **Action Space**: ALLOW, DENY, RATE_LIMIT, QUARANTINE, MONITOR
- **Reward Function**: Multi-objective optimization for security vs availability

### 5. Policy Orchestrator
- **Rule Generator**: Converts policy decisions to firewall rules
- **Policy Validator**: Ensures rule correctness and security
- **Vendor Adapters**: iptables, AWS Security Groups, extensible for others

### 6. Supporting Services
- **XAI Service**: SHAP-based explanations and audit trails
- **Compliance Engine**: GDPR, HIPAA, PCI-DSS, NIST CSF assessments
- **Alert Service**: Notification and escalation management
- **Auth Service**: JWT authentication and RBAC

## Data Flow

1. Network traffic is captured by Data Collector
2. Traffic is normalized to CIM format and published to Kafka
3. Flink processes streams to extract features
4. AI Engine analyzes features for threat detection
5. DRL Engine decides on policy action based on threat assessment
6. Policy Orchestrator translates decisions to firewall rules
7. Rules are applied to target firewalls
8. XAI provides explanations for all decisions
9. Compliance Engine maps actions to regulatory controls

## Technology Stack

| Component | Technology |
|-----------|------------|
| Backend Services | Python 3.10, Flask |
| Message Queue | Apache Kafka (AWS MSK) |
| Stream Processing | Apache Flink |
| ML/DL | PyTorch, XGBoost, scikit-learn |
| RL Framework | Stable-Baselines3, Gymnasium |
| Database | PostgreSQL (RDS), Redis (ElastiCache) |
| Object Storage | AWS S3 |
| ML Training | AWS SageMaker |
| Container Orchestration | AWS ECS Fargate |
| Infrastructure | Terraform |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |

## Security Architecture

- **Authentication**: JWT tokens with configurable expiration
- **Authorization**: Role-based access control (Admin, Analyst, Viewer)
- **Encryption**: TLS for all service communication, KMS for data at rest
- **Network Isolation**: VPC with public/private subnets
- **Audit Logging**: Comprehensive decision audit trails
