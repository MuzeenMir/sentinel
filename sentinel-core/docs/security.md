# SENTINEL Security Architecture

This document describes the security patterns, controls, and practices embedded throughout the SENTINEL platform.

---

## Table of Contents

- [Authentication](#authentication)
- [Authorization](#authorization)
- [Input Validation](#input-validation)
- [Rate Limiting](#rate-limiting)
- [Secrets Management](#secrets-management)
- [Transport Security](#transport-security)
- [Network Policies](#network-policies)
- [Audit Logging](#audit-logging)
- [Encryption](#encryption)
- [Token Management](#token-management)
- [Vulnerability Management](#vulnerability-management)
- [Incident Response Integration](#incident-response-integration)
- [eBPF Runtime Enforcement](#ebpf-runtime-enforcement)
- [Supply Chain Security](#supply-chain-security)

---

## Authentication

### JWT Token Flow

SENTINEL uses JSON Web Tokens (JWTs) for stateless authentication across all services.

**Token lifecycle:**

1. Client authenticates via `POST /api/v1/auth/login` with username and password.
2. Auth service verifies credentials against bcrypt-hashed passwords in PostgreSQL.
3. On success, the service issues an **access token** (default 24h) and a **refresh token** (default 30d).
4. Clients include the access token in the `Authorization: Bearer <token>` header on subsequent requests.
5. The API Gateway validates each request by calling the auth service's `/api/v1/auth/verify` endpoint.
6. Expired access tokens are renewed via `POST /api/v1/auth/refresh` using the refresh token.
7. On logout, the token's JTI is added to a blacklist (Redis for fast lookup, PostgreSQL for persistence).

**Token configuration (environment variables):**

| Variable                    | Default | Description             |
|-----------------------------|---------|-------------------------|
| `JWT_SECRET_KEY`            | --      | Required. HMAC signing key (min 64 chars recommended). |
| `JWT_ACCESS_EXPIRES_HOURS`  | 24      | Access token TTL        |
| `JWT_REFRESH_EXPIRES_DAYS`  | 30      | Refresh token TTL       |

### Password Policy

- Minimum 8 characters.
- At least one uppercase letter, one lowercase letter, one digit, and one special character.
- Passwords are hashed with bcrypt (auto-salted).
- Plaintext passwords are never stored or logged.

### Account Lockout

- 5 consecutive failed login attempts lock the account for 15 minutes.
- Failed attempts are tracked per user and per IP address in Redis.
- Lockout counters reset on successful login.

### Multi-Factor Authentication

Enterprise MFA is available via the `enterprise_auth` module:

- TOTP (Time-based One-Time Password) for all users.
- FIDO2/WebAuthn for hardware security keys.
- OIDC and SAML integration for federated identity.
- SCIM provisioning for directory sync.

---

## Authorization

### Role-Based Access Control

SENTINEL implements RBAC with five predefined roles:

| Role                | Permissions                                                    |
|---------------------|----------------------------------------------------------------|
| `admin`             | Full system access. User management. Configuration changes. Model retraining. Hardening. |
| `security_analyst`  | View and acknowledge alerts. View threats. View policies. Run compliance assessments. |
| `operator`          | Acknowledge and resolve alerts. Run scans. View enforcement status. |
| `auditor`           | Read-only access to alerts, threats, compliance reports, and audit trails. |
| `viewer`            | Read-only access to dashboards and statistics.                  |

### Enforcement Points

- **Auth service:** The `require_role` decorator checks the JWT identity's role against the required role.
- **API Gateway:** The `require_auth` decorator verifies tokens before proxying. The `require_role` decorator adds role checks on write operations.
- **Downstream services:** Each service independently verifies auth via the shared `auth_middleware` module.

### Principle of Least Privilege

- Write operations (create, update, delete) require elevated roles (`admin` or `operator`).
- Destructive operations (hardening remediation, model retraining, eBPF mode changes) require `admin`.
- Read-only endpoints are accessible to all authenticated users.

---

## Input Validation

### Request Validation

- All API endpoints validate `Content-Type: application/json`.
- Required fields are checked explicitly; missing fields return `400` with a descriptive error.
- Username format: alphanumeric and underscores, 3-50 characters (`^[a-zA-Z0-9_]{3,50}$`).
- Email format: validated against RFC-compliant regex.
- Policy creation requires `name`, `action`, `source`, `destination`.
- Batch endpoints enforce maximum batch sizes (e.g., AI Engine defaults to 1000).

### SQL Injection Prevention

- All database access uses SQLAlchemy ORM with parameterized queries.
- No raw SQL concatenation exists in the codebase.
- The auth service uses `filter_by` and `filter` exclusively.

### Path Traversal Prevention

- The hardening service resolves all file paths through `_host_path()`, which constrains operations to the `HOST_ROOT` mount point.
- No user-supplied strings are used to construct file paths without sanitization.

---

## Rate Limiting

### Gateway-Level

- Default: 200 requests per hour per IP (Flask-Limiter with Redis backend).
- Rate-limit test endpoint: 5 requests per minute.
- Response header `429 Too Many Requests` with `Retry-After`.

### Auth-Service-Level

- Registration: 10 requests per hour per IP.
- Login: 5 requests per minute per IP.
- Additional Redis-backed IP rate limiting: 5 login attempts per 5-minute window.

### Implementation

Rate limiting uses Redis as a shared backend, ensuring consistent enforcement across multiple API Gateway instances. Limits are configurable via Flask-Limiter's `default_limits` and per-route `@limiter.limit()` decorators.

---

## Secrets Management

### Environment Variables

All secrets are configured via environment variables. The `.env.example` file documents required variables without exposing real values.

| Secret                   | Description                                    |
|--------------------------|------------------------------------------------|
| `JWT_SECRET_KEY`         | JWT signing key (required, no default)         |
| `POSTGRES_PASSWORD`      | Database password                              |
| `ADMIN_PASSWORD`         | Initial admin account password                 |
| `SMTP_PASSWORD`          | Email notification credentials                 |
| `GRAFANA_PASSWORD`       | Grafana admin password                         |
| `INTERNAL_SERVICE_TOKEN` | Service-to-service authentication token        |
| `SLACK_WEBHOOK_URL`      | Slack notification endpoint                    |

### Runtime Enforcement

- `JWT_SECRET_KEY` and `DATABASE_URL` are required at startup; the auth service raises `RuntimeError` if they are missing.
- No secrets appear in source code, Docker images, or log output.
- The `.env` file is gitignored; only `.env.example` with placeholder values is committed.

### Production Recommendations

- Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets with encryption at rest).
- Rotate `JWT_SECRET_KEY` periodically; coordinate with token blacklist to invalidate old tokens.
- Use separate credentials per environment (dev, staging, production).

---

## Transport Security

### mTLS Between Services

In production deployments, all inter-service communication should use mutual TLS:

- Each service presents a client certificate signed by the SENTINEL internal CA.
- The API Gateway terminates external TLS and re-encrypts traffic to backend services.
- Kubernetes deployments can leverage a service mesh (Istio, Linkerd) for automatic mTLS.

### External TLS

- The admin console Nginx reverse proxy should be configured with TLS 1.2+ and strong cipher suites.
- HSTS headers should be set with a minimum `max-age` of one year.
- Certificate management via Let's Encrypt or organizational PKI.

### Configuration

```
# Recommended TLS settings for Nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

## Network Policies

### Docker Compose

- All services communicate over the `sentinel-network` bridge network.
- Only the API Gateway (8080), admin console (3000), and monitoring endpoints (Grafana 3001, Prometheus 9090) are exposed to the host.
- Backend services (auth, alert, AI engine, etc.) are only reachable within the Docker network.

### Kubernetes

- Default deny-all `NetworkPolicy` on the SENTINEL namespace.
- Explicit allow rules for service-to-service communication.
- API Gateway is the only ingress point for external traffic.
- eBPF-powered services (HIDS, hardening, XDP) require host network or privileged mode.

### Service Isolation

- The XDP collector uses host networking for raw NIC access but is isolated to read-only operations.
- HIDS and hardening services mount host filesystems with the minimum required access level (`ro` where possible, `rw` only for remediation paths).

---

## Audit Logging

### What is Logged

- All authentication events: login success, login failure, logout, token refresh, password change.
- All API requests: method, path, status code, response time, user identity.
- Alert lifecycle events: creation, acknowledgment, resolution.
- Policy changes: creation, update, deletion.
- Configuration changes: who changed what, old value, new value.
- AI/DRL decisions: detection results, policy decisions, confidence scores.
- Hardening actions: scans, remediations, rollbacks.
- eBPF events: process executions, file access, network connections, privilege escalations.

### Log Format

Structured JSON logging via the shared `observability` module:

```json
{
  "timestamp": "2026-04-02T12:00:00Z",
  "service": "api-gateway",
  "level": "INFO",
  "method": "POST",
  "path": "/api/v1/auth/login",
  "status": 200,
  "duration_ms": 45,
  "user": "admin",
  "ip": "10.0.0.5"
}
```

### Log Pipeline

- Application logs are written to stdout for container orchestrators.
- Elasticsearch (port 9200) indexes logs for search and analysis.
- Kibana (port 5601) provides log visualization and alerting.
- Prometheus (port 9090) scrapes application metrics endpoints.
- Grafana (port 3001) renders dashboards and alert rules.

### Retention

- Alert data: 30 days in Redis.
- Detection records: 7 days in Redis.
- DRL decisions: 7 days in Redis.
- Elasticsearch: configurable, recommended 90 days minimum.
- Prometheus: 30 days (`--storage.tsdb.retention.time=30d`).

---

## Encryption

### At Rest

- PostgreSQL: enable `pgcrypto` extension for column-level encryption of sensitive fields.
- Redis: enable persistence encryption with `appendonly yes` and filesystem-level encryption.
- Elasticsearch: enable encryption at rest via the security plugin or filesystem encryption.
- AI model artefacts: stored in Docker volumes; encrypt the volume backend in production.
- Backup files: the hardening service stores backups at `BACKUP_DIR`; encrypt with filesystem-level encryption.

### In Transit

- All external traffic must use TLS 1.2+.
- Inter-service traffic should use mTLS in production.
- Kafka: configure `SASL_SSL` security protocol for production message bus.
- Redis: enable TLS with `redis://` replaced by `rediss://` and appropriate certificates.

### Password Hashing

- bcrypt with automatic salt generation (cost factor 12 by default).
- Password hashes are stored as UTF-8 strings in PostgreSQL.
- No reversible encryption is used for passwords.

---

## Token Management

### Blacklist

- On logout, the token's JTI (JWT ID) is added to both Redis (fast lookup, 24h TTL) and PostgreSQL (`TokenBlacklist` table).
- The `token_in_blocklist_loader` callback checks Redis first, then falls back to the database.
- Expired tokens are naturally rejected by the JWT library before the blacklist is consulted.

### Token Rotation

- Access tokens have a short TTL (default 24h) to limit exposure window.
- Refresh tokens have a longer TTL (default 30d) and should be stored securely by clients.
- Token refresh issues a new access token without requiring re-authentication.

---

## Vulnerability Management

### Dependency Scanning

- Pin all Python dependencies in per-service `requirements.txt` files.
- Run `pip-audit` or `safety check` in CI to detect known vulnerabilities.
- Frontend dependencies are managed via `package-lock.json` with `npm audit`.

### Container Security

- Use minimal base images (Alpine, distroless) where possible.
- Run containers as non-root users (except eBPF services that require privileged access).
- Scan images with Trivy, Grype, or Snyk before deployment.

### Application Security

- No `eval()` or `exec()` on untrusted input.
- No shell command injection vectors (subprocess calls use lists, not shell=True).
- CORS is configured per service with explicit allowed origins.
- Flask debug mode is disabled in production (`FLASK_DEBUG` defaults to `false`).

---

## Incident Response Integration

### Alert Notifications

- Email: SMTP notifications for `high` and `critical` severity alerts.
- Slack: Webhook notifications for `critical` alerts.
- Custom webhooks: configurable per-alert notification endpoints.
- All notifications are sent asynchronously via a thread pool to avoid blocking the alert pipeline.

### SSE Real-Time Streams

- `/api/v1/stream/threats` and `/api/v1/stream/alerts` provide real-time event feeds.
- Backed by Redis pub/sub for horizontal scalability.
- 15-second heartbeat to keep connections alive through proxies.

### Kafka Event Bus

- All security events (detections, alerts, hardening scans, HIDS events) are published to Kafka topics.
- Downstream Flink jobs process events in real-time for anomaly detection and DRL state updates.
- Kafka provides durable, replayable event storage for forensic analysis.

### Compliance Reporting

- The XAI service generates compliance-ready explanation reports linking detections to policy decisions.
- The compliance engine maps policies to framework controls (NIST, GDPR, HIPAA, PCI-DSS, SOC 2).
- All AI decisions include provenance metadata (models used, confidence scores, explanation method).

---

## eBPF Runtime Enforcement

### Hardening Service

- Loads LSM (Linux Security Module) eBPF programs for runtime policy enforcement.
- Supports `audit` mode (log violations) and `enforce` mode (block violations).
- Port-binding policies restrict which processes can bind to specific ports.

### HIDS Agent

- Attaches to kernel tracepoints and kprobes for real-time host monitoring.
- Monitored events: process execution (`sched_process_exec`), file access (`sys_enter_openat`), network connections (`tcp_v4_connect`), privilege escalation (`sys_enter_setuid`), kernel module loading.
- Events are filtered through a baseline rule engine to reduce noise from known-good activity.

### Requirements

- Linux kernel 5.8+ with BTF (BPF Type Format) support.
- `CAP_BPF` + `CAP_PERFMON` capabilities or privileged container mode.
- Compiled eBPF objects in `ebpf-lib/compiled/`.

---

## Supply Chain Security

### Code Integrity

- All commits should be signed (GPG or SSH key).
- Branch protection rules enforce code review before merge to main.
- CI pipeline runs linting, type checking, and security scanning on every PR.

### Dependency Provenance

- Python packages are installed from PyPI with pinned versions.
- Frontend packages are installed from npm with lockfile integrity checks.
- Prefer MIT/Apache/BSD-licensed dependencies; GPL/AGPL requires approval.

### Build Reproducibility

- Dockerfiles use explicit base image tags (not `latest`).
- Multi-stage builds minimize attack surface in production images.
- Build arguments do not contain secrets.
