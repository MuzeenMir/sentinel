# SENTINEL Operations Manual

Deployment, configuration, monitoring, and troubleshooting guide for SENTINEL platform operators.

---

## Table of Contents

- [Deployment](#deployment)
  - [Docker Compose](#docker-compose)
  - [Kubernetes](#kubernetes)
  - [AWS Reference Architecture](#aws-reference-architecture)
- [Configuration Reference](#configuration-reference)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Backup and Restore](#backup-and-restore)
- [Scaling Guidelines](#scaling-guidelines)
- [Health Check Endpoints](#health-check-endpoints)
- [Log Analysis](#log-analysis)
- [Troubleshooting](#troubleshooting)

---

## Deployment

### Prerequisites

- Docker 24+ and Docker Compose v2.
- Linux host with kernel 5.8+ (required for eBPF features).
- Minimum 8 GB RAM, 4 CPU cores for a single-node deployment.
- Production: 16+ GB RAM, 8+ CPU cores, SSD storage.

### Docker Compose

**Quick start:**

```bash
cd sentinel-core

# Copy and configure environment
cp .env.example .env
# Edit .env with production values:
#   JWT_SECRET_KEY, POSTGRES_PASSWORD, ADMIN_PASSWORD, GRAFANA_PASSWORD, INTERNAL_SERVICE_TOKEN

# Start all services
docker compose up -d

# Verify health
curl http://localhost:8080/health
curl http://localhost:5000/health
```

**Service ports:**

| Service               | Port  | Description                       |
|-----------------------|-------|-----------------------------------|
| API Gateway           | 8080  | Main entry point for all API calls|
| Auth Service          | 5000  | Authentication and user management|
| Data Collector        | 5001  | Network traffic ingestion         |
| Alert Service         | 5002  | Alert lifecycle management        |
| AI Engine             | 5003  | ML threat detection               |
| Policy Orchestrator   | 5004  | Firewall policy management        |
| DRL Engine            | 5005  | Autonomous policy decisions       |
| XAI Service           | 5006  | Explainability and audit trails   |
| Compliance Engine     | 5007  | Compliance assessment             |
| HIDS Agent            | 5010  | Host intrusion detection          |
| Hardening Service     | 5011  | OS hardening and CIS benchmarks   |
| XDP Collector         | 5012  | High-speed packet processing      |
| Admin Console         | 3000  | Web dashboard                     |
| Prometheus            | 9090  | Metrics collection                |
| Grafana               | 3001  | Metrics dashboards                |
| Elasticsearch         | 9200  | Log indexing                      |
| Kibana                | 5601  | Log visualization                 |
| Kafka                 | 9092  | Message bus                       |
| PostgreSQL            | 5433  | Relational database               |
| Redis                 | 6379  | Cache and session store           |

**Startup order:**

Docker Compose manages dependencies, but the expected order is:

1. PostgreSQL, Redis, Zookeeper.
2. Kafka (waits for Zookeeper).
3. Auth Service (waits for PostgreSQL + Redis).
4. All other backend services (wait for Auth Service).
5. API Gateway (waits for all backend services).
6. Admin Console (waits for API Gateway).
7. Flink jobs (wait for Kafka).
8. Prometheus, Grafana, Elasticsearch, Kibana.

**Stopping:**

```bash
docker compose down           # Stop and remove containers
docker compose down -v        # Also remove volumes (destroys data)
```

### Kubernetes

A Kubernetes deployment uses Helm charts or raw manifests. Key considerations:

**Namespace:**

```bash
kubectl create namespace sentinel
```

**Secrets:**

```bash
kubectl create secret generic sentinel-secrets \
  --namespace sentinel \
  --from-literal=jwt-secret-key='<64-char-random-string>' \
  --from-literal=postgres-password='<password>' \
  --from-literal=admin-password='<password>' \
  --from-literal=internal-service-token='<token>'
```

**StatefulSets** for: PostgreSQL, Redis, Elasticsearch, Kafka/Zookeeper.

**Deployments** for: all SENTINEL services (auth, ai-engine, drl-engine, etc.).

**DaemonSets** for: HIDS Agent, Hardening Service (one per node).

**Privileged pods:** HIDS Agent, Hardening Service, and XDP Collector require privileged security contexts or specific capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`).

**Network policies:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: sentinel
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

Add explicit allow rules for each service-to-service communication path.

**Ingress:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sentinel-ingress
  namespace: sentinel
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts: [sentinel.example.com]
      secretName: sentinel-tls
  rules:
    - host: sentinel.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api-gateway
                port:
                  number: 8080
          - path: /
            pathType: Prefix
            backend:
              service:
                name: admin-console
                port:
                  number: 8080
```

### AWS Reference Architecture

**VPC layout:**

- Public subnet: ALB (Application Load Balancer) for TLS termination.
- Private subnet A: EKS worker nodes for SENTINEL services.
- Private subnet B: RDS (PostgreSQL), ElastiCache (Redis), MSK (Kafka).
- Isolated subnet: AI model training (GPU instances, spot-capable).

**Managed services:**

| Component     | AWS Service         | Configuration                        |
|---------------|---------------------|--------------------------------------|
| Database      | RDS PostgreSQL 13   | Multi-AZ, encrypted, r6g.large      |
| Cache         | ElastiCache Redis 7 | Cluster mode, 2 replicas            |
| Message bus   | MSK (Kafka 3.x)     | 3 brokers, m5.large                 |
| Search        | OpenSearch           | 2 data nodes, gp3 storage           |
| Compute       | EKS 1.29+           | Managed node groups, m6i.2xlarge    |
| Storage       | EFS                  | Model artefacts shared volume       |
| Secrets       | Secrets Manager      | Automatic rotation for DB passwords |
| DNS           | Route 53             | Alias to ALB                        |

**Spot instances for training:**

The training pipeline in `sentinel-core/training/spot_handler.py` supports AWS Spot interruption handling for cost-effective model training.

---

## Configuration Reference

All configuration is via environment variables. The `.env.example` file documents all available settings.

### Required Variables

| Variable           | Description                                        |
|--------------------|----------------------------------------------------|
| `JWT_SECRET_KEY`   | JWT signing key. Minimum 64 random characters.     |
| `DATABASE_URL`     | PostgreSQL connection string.                      |
| `ADMIN_USERNAME`   | Initial admin username.                            |
| `ADMIN_PASSWORD`   | Initial admin password (must meet password policy).|
| `ADMIN_EMAIL`      | Initial admin email.                               |

### Database

| Variable              | Default                | Description                     |
|-----------------------|------------------------|---------------------------------|
| `POSTGRES_DB`         | `sentinel_db`          | Database name                   |
| `POSTGRES_USER`       | `sentinel`             | Database user                   |
| `POSTGRES_PASSWORD`   | --                     | Database password (required)    |
| `DB_POOL_SIZE`        | `10`                   | SQLAlchemy connection pool size |

### Redis

| Variable                 | Default                  | Description                  |
|--------------------------|--------------------------|------------------------------|
| `REDIS_URL`              | `redis://localhost:6379` | Redis connection URL         |
| `REDIS_MAX_CONNECTIONS`  | `20`                     | Connection pool max size     |

### JWT and Authentication

| Variable                     | Default | Description                       |
|------------------------------|---------|-----------------------------------|
| `JWT_SECRET_KEY`             | --      | Required. HMAC signing key.       |
| `JWT_ACCESS_EXPIRES_HOURS`   | `24`    | Access token TTL in hours.        |
| `JWT_REFRESH_EXPIRES_DAYS`   | `30`    | Refresh token TTL in days.        |

### AI Engine

| Variable                | Default                   | Description                       |
|-------------------------|---------------------------|-----------------------------------|
| `MODEL_PATH`            | `/models`                 | Base directory for model artefacts|
| `CONFIDENCE_THRESHOLD`  | `0.85`                    | Ensemble detection threshold      |
| `BATCH_SIZE`            | `1000`                    | Maximum batch detection size      |

### Notifications

| Variable              | Default            | Description                          |
|-----------------------|--------------------|--------------------------------------|
| `SMTP_HOST`           | `localhost`        | SMTP server hostname                 |
| `SMTP_PORT`           | `587`              | SMTP server port                     |
| `SMTP_USER`           | --                 | SMTP username                        |
| `SMTP_PASSWORD`       | --                 | SMTP password                        |
| `NOTIFICATION_EMAIL`  | `admin@example.com`| Destination for alert emails         |
| `SLACK_WEBHOOK_URL`   | --                 | Slack incoming webhook URL           |

### Services

| Variable                     | Default                           | Description                     |
|------------------------------|-----------------------------------|---------------------------------|
| `AUTH_SERVICE_URL`           | `http://auth-service:5000`        | Auth service internal URL       |
| `DATA_COLLECTOR_URL`         | `http://data-collector:5001`      | Data collector internal URL     |
| `ALERT_SERVICE_URL`          | `http://alert-service:5002`       | Alert service internal URL      |
| `AI_ENGINE_URL`              | `http://ai-engine:5003`           | AI engine internal URL          |
| `POLICY_SERVICE_URL`         | `http://policy-orchestrator:5004` | Policy service internal URL     |
| `DRL_ENGINE_URL`             | `http://drl-engine:5005`          | DRL engine internal URL         |
| `XAI_SERVICE_URL`            | `http://xai-service:5006`         | XAI service internal URL        |
| `COMPLIANCE_ENGINE_URL`      | `http://compliance-engine:5007`   | Compliance engine internal URL  |
| `KAFKA_BOOTSTRAP_SERVERS`    | `kafka:9092`                      | Kafka broker addresses          |
| `INTERNAL_SERVICE_TOKEN`     | --                                | Service-to-service auth token   |

### HIDS and Hardening

| Variable              | Default              | Description                              |
|-----------------------|----------------------|------------------------------------------|
| `HOST_ROOT`           | `/host`              | Host filesystem mount point              |
| `FIM_PATHS`           | (see defaults)       | Comma-separated FIM target paths         |
| `FIM_CHECK_INTERVAL`  | `60`                 | FIM check interval in seconds            |
| `BACKUP_DIR`          | `/var/lib/sentinel/backups` | Hardening backup directory        |

---

## Monitoring and Alerting

### Prometheus

Prometheus scrapes metrics from all SENTINEL services at `/metrics` endpoints (provided by the shared `metrics` module).

**Key metrics:**

| Metric                          | Type      | Description                                |
|---------------------------------|-----------|--------------------------------------------|
| `sentinel_threats_detected`     | Counter   | Threats detected by severity               |
| `sentinel_alerts_created`       | Counter   | Alerts created by severity                 |
| `sentinel_drl_decisions`        | Counter   | DRL decisions by action type               |
| `sentinel_detection_latency`    | Histogram | AI detection latency                       |
| `sentinel_hardening_posture`    | Gauge     | Current hardening posture score (0-100)    |
| `sentinel_ebpf_events`         | Counter   | eBPF events by type                        |
| `sentinel_fim_alerts`           | Counter   | File integrity monitoring alerts           |
| `http_request_duration_seconds` | Histogram | HTTP request duration per service          |

**Prometheus configuration** is at `observability/prometheus/prometheus.yml`.

### Grafana

Access Grafana at `http://<host>:3001` (default credentials: `admin` / value of `GRAFANA_PASSWORD`).

Pre-provisioned dashboards are located in `observability/grafana/dashboards/`:

- **SENTINEL Overview:** System-wide health, request rates, error rates.
- **Threat Detection:** AI detection metrics, model performance, false positive rates.
- **Alert Management:** Alert volumes, severity distribution, resolution times.
- **DRL Performance:** Policy decision rates, action distribution, reward trends.
- **Infrastructure:** CPU, memory, disk, network for all containers.

### Recommended Alerting Rules

| Alert                            | Condition                              | Severity |
|----------------------------------|----------------------------------------|----------|
| High error rate                  | Error rate > 5% for 5 min             | Critical |
| Detection latency spike          | p95 > 500ms for 5 min                 | High     |
| Service down                     | Health check fails for 2 min          | Critical |
| Hardening posture drop           | Posture score < 70%                   | High     |
| FIM alert                        | Any file integrity change detected    | Critical |
| Privilege escalation             | Priv escalation event detected        | Critical |
| High false positive rate         | FP rate > 10% over 1 hour            | Medium   |
| Kafka consumer lag               | Lag > 10000 messages for 10 min       | High     |

---

## Backup and Restore

### PostgreSQL

**Automated backup (cron):**

```bash
# Daily backup at 02:00
0 2 * * * docker exec sentinel-postgres pg_dump -U sentinel sentinel_db | gzip > /backups/sentinel_$(date +\%Y\%m\%d).sql.gz
```

**Restore:**

```bash
gunzip < /backups/sentinel_20260401.sql.gz | docker exec -i sentinel-postgres psql -U sentinel sentinel_db
```

### Redis

Redis is configured with `appendonly yes` for durability. The AOF file is stored in the `redis_data` volume.

**Manual snapshot:**

```bash
docker exec sentinel-redis redis-cli BGSAVE
```

### AI Model Artefacts

Model files are stored in the `ai_models` Docker volume. Back up the volume:

```bash
docker run --rm -v sentinel-core_ai_models:/data -v /backups:/backup alpine tar czf /backup/models_$(date +%Y%m%d).tar.gz /data
```

### Hardening Backups

The hardening service automatically backs up files before remediation to `BACKUP_DIR` (`/var/lib/sentinel/backups`). Files are named `<sanitized_path>.<timestamp>.bak`.

### Elasticsearch

Use snapshot and restore:

```bash
# Register repository
curl -X PUT "localhost:9200/_snapshot/backup" -H 'Content-Type: application/json' -d '{"type": "fs", "settings": {"location": "/backups/es"}}'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/backup/snap_$(date +%Y%m%d)"
```

---

## Scaling Guidelines

### Horizontal Scaling

| Service              | Scaling Strategy              | Notes                                      |
|----------------------|-------------------------------|--------------------------------------------|
| API Gateway          | Multiple replicas behind LB   | Stateless; Redis for shared state          |
| Auth Service         | Multiple replicas             | Stateless; shared PostgreSQL + Redis       |
| Alert Service        | Multiple replicas             | Stateless; shared Redis                    |
| AI Engine            | Scale by CPU/GPU              | CPU-bound inference; GPU for training      |
| DRL Engine           | 1-2 replicas                  | Single model instance; scale reads only    |
| Compliance Engine    | Multiple replicas             | Stateless                                  |
| XAI Service          | Multiple replicas             | Stateless                                  |
| Policy Orchestrator  | Multiple replicas             | Stateless; shared Redis                    |
| HIDS Agent           | DaemonSet (one per node)      | Tied to host kernel                        |
| Hardening Service    | DaemonSet (one per node)      | Tied to host filesystem                    |

### Vertical Scaling

| Service     | Resource          | Recommendation                            |
|-------------|-------------------|-------------------------------------------|
| AI Engine   | Memory            | 4 GB minimum; 8 GB for large models       |
| AI Engine   | CPU/GPU           | GPU recommended for training              |
| PostgreSQL  | Memory            | 25% of dataset size for shared_buffers    |
| Redis       | Memory            | Monitor with `INFO memory`                |
| Kafka       | Disk              | SSD, 3x daily ingestion volume            |
| Elasticsearch | Memory + Disk   | 50% RAM for JVM heap; SSD storage        |

### Kafka Partitioning

- `sentinel-network-events`: 12 partitions (scale with data collector instances).
- `sentinel-host-events`: 6 partitions (scale with HIDS agent count).
- `extracted_features`: 6 partitions.
- `sentinel-hardening-events`: 3 partitions.

---

## Health Check Endpoints

Every service exposes a `GET /health` endpoint that returns `200` when healthy.

| Service              | URL                          | Response Fields                              |
|----------------------|------------------------------|----------------------------------------------|
| API Gateway          | `:8080/health`               | `status`, `timestamp`, `request_stats`       |
| Auth Service         | `:5000/health`               | `status`, `timestamp`                        |
| AI Engine            | `:5003/health`               | `status`, `models`, `ensemble_ready`         |
| DRL Engine           | `:5005/health`               | `status`, `agent_ready`, `model_version`     |
| Alert Service        | `:5002/health`               | `status`, `timestamp`                        |
| Policy Orchestrator  | `:5004/health`               | `status`, `timestamp`                        |
| Compliance Engine    | `:5007/health`               | `status`, `frameworks`                       |
| XAI Service          | `:5006/health`               | `status`, `components`                       |
| HIDS Agent           | `:5010/health`               | `status`, `ebpf_programs_loaded`, `fim_paths_monitored` |
| Hardening Service    | `:5011/health`               | `status`, `posture_score`, `ebpf_enforcing`  |

**Docker Compose health check example:**

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 60s
```

---

## Log Analysis

### Log Locations

In containerized deployments, all services write structured logs to stdout. Container runtime captures these for aggregation.

### Structured Log Fields

Every log line includes:

- `timestamp` -- ISO 8601 format.
- `service` -- originating service name.
- `level` -- `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.
- `message` -- human-readable description.

HTTP request logs additionally include:

- `method`, `path`, `status`, `duration_ms`, `ip`.

### Useful Queries (Kibana/Elasticsearch)

**Failed login attempts:**

```
service: "auth-service" AND message: "Invalid credentials"
```

**High-latency requests:**

```
duration_ms: >500 AND status: 200
```

**Alert creation events:**

```
service: "alert-service" AND message: "Created alert*"
```

**FIM alerts:**

```
service: "hids-agent" AND message: "FIM ALERT*"
```

**Hardening remediation events:**

```
service: "hardening-service" AND message: "Remediation*"
```

---

## Troubleshooting

### Service Will Not Start

**Symptom:** Container exits immediately or restart loops.

**Checks:**

1. `docker compose logs <service-name>` -- look for startup errors.
2. Verify required environment variables are set (`JWT_SECRET_KEY`, `DATABASE_URL`).
3. Check dependency health: `docker compose ps` to confirm PostgreSQL and Redis are running.
4. Auth service: ensure PostgreSQL is reachable and `init.sql` ran successfully.

### Authentication Failures

**Symptom:** All API calls return `401` or `503`.

**Checks:**

1. Confirm the auth service is healthy: `curl http://localhost:5000/health`.
2. Verify `JWT_SECRET_KEY` matches between auth service and other services.
3. Check for account lockout: 5 failed attempts trigger a 15-minute lock.
4. Token may be blacklisted; try re-authenticating.

### AI Engine Returns Low Confidence

**Symptom:** All detections show confidence near 0.5 or use default model.

**Checks:**

1. Check model status: `GET /api/v1/models/status`.
2. If models show `1.0.0-default`, they have not been trained on real data.
3. Verify the `/models` volume is mounted and contains trained artefacts.
4. Check AI Engine logs for model loading errors.

### Kafka Consumer Lag

**Symptom:** Flink jobs or data collector falling behind.

**Checks:**

1. `docker exec sentinel-kafka kafka-consumer-groups --bootstrap-server localhost:9092 --describe --all-groups`.
2. Increase Flink parallelism via `FLINK_PARALLELISM` environment variable.
3. Add Kafka partitions to the lagging topic.
4. Check for slow downstream services (AI engine inference bottleneck).

### HIDS/Hardening eBPF Failures

**Symptom:** "No eBPF programs loaded" or "FIM-only mode".

**Checks:**

1. Verify kernel version >= 5.8 with BTF: `ls /sys/kernel/btf/vmlinux`.
2. Ensure the container runs in privileged mode or has `CAP_BPF` + `CAP_PERFMON`.
3. Compile eBPF objects: `make` in `ebpf-lib/`.
4. Check for BTF availability: `bpftool btf dump file /sys/kernel/btf/vmlinux | head`.

### High Memory Usage

**Symptom:** OOM kills or degraded performance.

**Checks:**

1. AI Engine: default memory limit is 4 GB in docker-compose.yml. Increase if loading multiple large models.
2. Redis: run `docker exec sentinel-redis redis-cli INFO memory` to check usage.
3. Elasticsearch: check JVM heap with `curl localhost:9200/_nodes/stats/jvm`.
4. Review Grafana infrastructure dashboard for per-container memory trends.

### Database Connection Errors

**Symptom:** Auth service or other PostgreSQL-dependent services fail.

**Checks:**

1. Confirm PostgreSQL is healthy: `docker exec sentinel-postgres pg_isready -U sentinel`.
2. Check connection pool exhaustion: `DB_POOL_SIZE` may need to be increased.
3. Verify `DATABASE_URL` format: `postgresql://user:pass@host:port/dbname`.
4. Check for long-running queries: `SELECT * FROM pg_stat_activity WHERE state = 'active';`.
