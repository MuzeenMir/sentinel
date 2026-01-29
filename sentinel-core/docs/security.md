# SENTINEL Security Documentation

## Security Architecture Overview

SENTINEL implements a defense-in-depth security model following Zero Trust principles.

## Authentication & Authorization

### JWT Authentication

- **Token Type**: JWT with RS256 signing
- **Token Lifetime**: 1 hour (configurable)
- **Refresh Token**: 7 days
- **Token Storage**: Client-side only (no server-side session)

### Role-Based Access Control (RBAC)

| Role | Permissions |
|------|-------------|
| Admin | Full system access, user management, policy creation |
| Analyst | View threats, create policies, view reports |
| Operator | Monitor dashboards, acknowledge alerts |
| Viewer | Read-only access to dashboards |

### API Key Authentication

For service-to-service communication:
- HMAC-SHA256 signed requests
- Key rotation every 90 days
- Scoped permissions per service

## Encryption

### In Transit

- TLS 1.3 for all external communications
- mTLS for inter-service communication
- Certificate pinning for critical services

### At Rest

- AES-256-GCM for database encryption (RDS)
- AWS KMS for key management
- S3 server-side encryption for model storage

### Secrets Management

- AWS Secrets Manager for credentials
- Environment variables for non-sensitive config
- HashiCorp Vault integration (optional)

## Network Security

### VPC Architecture

```
Internet
    │
    ▼
┌───────────────────────────────────────────┐
│              Public Subnets               │
│  ┌─────────────┐    ┌─────────────┐      │
│  │     ALB     │    │   NAT GW    │      │
│  └──────┬──────┘    └──────┬──────┘      │
└─────────┼──────────────────┼─────────────┘
          │                  │
          ▼                  │
┌─────────────────────────────────────────────┐
│              Private Subnets                │
│  ┌─────────────┐  ┌─────────────┐          │
│  │ ECS Fargate │  │ ECS Fargate │          │
│  │  Services   │  │  Services   │          │
│  └──────┬──────┘  └──────┬──────┘          │
│         │                │                  │
            if self._connected:
│  └──────────────────────────────┘          │
└─────────────────────────────────────────────┘
```

### Security Groups

| Service | Inbound | Outbound |
|---------|---------|----------|
| ALB | 443 (HTTPS) from 0.0.0.0/0 | All to ECS |
| ECS Tasks | From ALB only | VPC CIDR |
| RDS | 5432 from ECS | None |
| Redis | 6379 from ECS | None |
| MSK | 9094 from VPC | VPC CIDR |

### WAF Rules

- OWASP Core Rule Set
- IP rate limiting (1000 req/min)
- Geographic restrictions (configurable)
- SQL injection prevention
- XSS prevention

## AI/ML Security

### Model Security

- **Model Signing**: All models cryptographically signed
- **Version Control**: Git-based versioning for model artifacts
- **Access Control**: IAM roles for model access

### Adversarial Robustness

- Input validation and sanitization
- Anomaly detection on input features
- Model monitoring for drift detection
- Adversarial training included in model updates

### Data Security

- **Training Data**: Encrypted at rest, anonymized
- **Inference Data**: No persistence, memory-only processing
- **Feature Extraction**: Local processing, no external calls

## Compliance Security Controls

### GDPR

- Data minimization in feature extraction
- Right to erasure support
- Data processing audit trails
- Privacy by design architecture

### HIPAA

- PHI never logged or stored
- Audit controls for all access
- Encryption in transit and at rest
- Business Associate Agreement support

### PCI-DSS

- Cardholder data never enters system
- Network segmentation
- Regular vulnerability scans
- Access logging and monitoring

### SOC2

- Access control policies
- Change management procedures
- Incident response plan
- Regular security assessments

## Audit & Logging

### Log Categories

| Category | Retention | Encryption |
|----------|-----------|------------|
| Access Logs | 90 days | Yes |
| Detection Logs | 1 year | Yes |
| Policy Changes | 7 years | Yes |
| System Logs | 30 days | No |

### Audit Trail Contents

```json
{
  "event_id": "audit_abc123",
  "timestamp": "2024-01-24T10:30:00Z",
  "event_type": "policy_created",
  "user_id": "user_xyz",
  "user_role": "analyst",
  "resource": "policy/P001",
  "action": "create",
  "result": "success",
  "source_ip": "10.0.0.100",
  "user_agent": "SENTINEL-Admin/1.0",
  "details": {...}
}
```

## Incident Response

### Security Incident Classification

| Severity | Response Time | Escalation |
|----------|---------------|------------|
| P1 Critical | 15 minutes | Security Team + Management |
| P2 High | 1 hour | Security Team |
| P3 Medium | 4 hours | On-call Engineer |
| P4 Low | 24 hours | Standard Queue |

### Response Procedures

1. **Detection**: Automated alerts or manual report
2. **Containment**: Isolate affected systems
3. **Investigation**: Forensic analysis
4. **Remediation**: Fix root cause
5. **Recovery**: Restore normal operations
6. **Post-Incident**: Review and improve

## Vulnerability Management

### Scanning Schedule

- **Container Images**: Every build
- **Dependencies**: Daily
- **Infrastructure**: Weekly
- **Penetration Testing**: Quarterly

### Patch Management

- Critical vulnerabilities: 24 hours
- High vulnerabilities: 7 days
- Medium vulnerabilities: 30 days
- Low vulnerabilities: 90 days

## Security Contacts

For security concerns:
- Email: security@sentinel.example.com
- Bug Bounty: https://sentinel.example.com/security/bounty
