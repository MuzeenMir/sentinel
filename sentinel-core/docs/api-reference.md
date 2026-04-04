# SENTINEL API Reference

All endpoints are exposed through the **API Gateway** at port `8080`. Downstream services are not intended for direct external access.

Base URL: `http://<host>:8080`

Authentication is required on all endpoints except `/health`. Include a JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Responses use `application/json` unless otherwise noted.

---

## Table of Contents

- [Authentication](#authentication)
- [Threats](#threats)
- [Alerts](#alerts)
- [Policies](#policies)
- [Compliance Engine](#compliance-engine)
- [AI Engine](#ai-engine)
- [DRL Engine](#drl-engine)
- [XAI Service](#xai-service)
- [Hardening Service](#hardening-service)
- [HIDS Agent](#hids-agent)
- [System](#system)
- [SSE Streaming](#sse-streaming)
- [Error Codes](#error-codes)

---

## Authentication

Backed by the Auth Service (port 5000). The gateway proxies all `/api/v1/auth/*` paths.

### POST /api/v1/auth/register

Create a new user account.

**Rate limit:** 10 per hour.

**Request body:**

```json
{
  "username": "analyst1",
  "email": "analyst1@example.com",
  "password": "Str0ng!Pass#2026",
  "role": "security_analyst"
}
```

**Roles:** `admin`, `security_analyst`, `auditor`, `operator`, `viewer`

**Response (201):**

```json
{
  "message": "User registered successfully",
  "user": {
    "id": 2,
    "username": "analyst1",
    "email": "analyst1@example.com",
    "role": "security_analyst",
    "status": "active",
    "tenant_id": null,
    "created_at": "2026-04-02T12:00:00",
    "last_login": null
  }
}
```

**Errors:** `400` missing/invalid fields, `409` duplicate username or email.

**Password requirements:** minimum 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character.

---

### POST /api/v1/auth/login

Authenticate and obtain JWT tokens.

**Rate limit:** 5 per minute. Additional IP-based limiting: 5 attempts per 5 minutes.

**Request body:**

```json
{
  "username": "admin",
  "password": "Str0ng!Pass#2026"
}
```

**Response (200):**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "user": { "id": 1, "username": "admin", "role": "admin", "status": "active", "..." : "..." },
  "token_type": "Bearer",
  "expires_in": 86400
}
```

**Errors:** `401` invalid credentials, `403` account locked/inactive, `429` rate limit exceeded.

Account locks after 5 consecutive failures for 15 minutes.

---

### POST /api/v1/auth/refresh

Refresh an expired access token. Requires the refresh token in the `Authorization` header.

**Response (200):**

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

---

### POST /api/v1/auth/verify

Verify the current access token and return user info.

**Auth:** Bearer token.

**Response (200):**

```json
{
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "status": "active",
    "..."  : "..."
  }
}
```

---

### POST /api/v1/auth/logout

Blacklist the current access token.

**Auth:** Bearer token.

**Response (200):**

```json
{ "message": "Successfully logged out" }
```

---

### GET /api/v1/auth/profile

Get the current user's profile.

**Auth:** Bearer token.

**Response (200):**

```json
{
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "status": "active",
    "tenant_id": null,
    "created_at": "2026-04-01T00:00:00",
    "last_login": "2026-04-02T12:00:00"
  }
}
```

---

### PUT /api/v1/auth/change-password

Change the current user's password.

**Auth:** Bearer token.

**Request body:**

```json
{
  "current_password": "OldP@ssw0rd!",
  "new_password": "NewStr0ng!Pass#2026"
}
```

**Response (200):**

```json
{ "message": "Password updated successfully" }
```

---

### GET /api/v1/auth/users

List users (admin only).

**Auth:** Bearer token, role `admin`.

**Query parameters:**

| Parameter  | Type | Default | Description       |
|------------|------|---------|-------------------|
| `page`     | int  | 1       | Page number       |
| `per_page` | int  | 10      | Results per page  |
| `role`     | str  | --      | Filter by role    |

**Response (200):**

```json
{
  "users": [ { "id": 1, "username": "admin", "..." : "..." } ],
  "total": 15,
  "pages": 2,
  "current_page": 1
}
```

---

### PUT /api/v1/auth/users/{user_id}

Update a user's role or status (admin only).

**Auth:** Bearer token, role `admin`.

**Request body:**

```json
{
  "role": "operator",
  "status": "active"
}
```

---

## Threats

### GET /api/v1/threats

List detected threats.

**Auth:** Bearer token.

**Query parameters:** Proxied to data-collector; supports `limit`, `offset`.

**Response (200):**

```json
{
  "threats": [ { "id": 1, "type": "brute_force", "source_ip": "10.0.1.5", "..." : "..." } ],
  "total": 42
}
```

---

### GET /api/v1/threats/{threat_id}

Get details for a specific threat.

**Auth:** Bearer token.

---

### POST /api/v1/threats

Create a manual threat entry.

**Auth:** Bearer token, role `admin`.

---

## Alerts

### GET /api/v1/alerts

List alerts with optional filters.

**Auth:** Bearer token.

**Query parameters:**

| Parameter  | Type | Default | Description                            |
|------------|------|---------|----------------------------------------|
| `severity` | str  | --      | `low`, `medium`, `high`, `critical`    |
| `status`   | str  | --      | `new`, `acknowledged`, `resolved`, `ignored` |
| `limit`    | int  | 100     | Max results                            |
| `offset`   | int  | 0       | Pagination offset                      |

**Response (200):**

```json
{
  "alerts": [
    {
      "id": "alert_1712000000_1234",
      "type": "brute_force",
      "severity": "high",
      "status": "new",
      "timestamp": "2026-04-02T12:00:00",
      "description": "Repeated failed SSH logins from 10.0.1.5",
      "details": {},
      "source": "ai_engine",
      "assigned_to": null,
      "correlation_id": null,
      "tags": []
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

---

### GET /api/v1/alerts/{alert_id}

Get a single alert by ID.

**Auth:** Bearer token.

---

### POST /api/v1/alerts

Create a new alert.

**Auth:** Bearer token, role `admin`.

**Request body:**

```json
{
  "type": "network_anomaly",
  "severity": "high",
  "description": "Unusual outbound traffic to C2 server",
  "source": "manual",
  "details": { "dest_ip": "198.51.100.1", "bytes": 1048576 },
  "tags": ["c2", "exfiltration"]
}
```

**Response (201):**

```json
{
  "message": "Alert created successfully",
  "alert_id": "alert_1712000000_5678"
}
```

---

### PUT /api/v1/alerts/{alert_id}

Update alert status.

**Auth:** Bearer token.

**Request body:**

```json
{
  "status": "acknowledged",
  "assigned_to": "analyst1"
}
```

---

### POST /api/v1/alerts/{alert_id}/acknowledge

Acknowledge an alert.

**Auth:** Bearer token, role `admin`, `operator`, or `security_analyst`.

---

### POST /api/v1/alerts/{alert_id}/resolve

Resolve an alert.

**Auth:** Bearer token, role `admin`, `operator`, or `security_analyst`.

---

### GET /api/v1/alerts/statistics

Get alert statistics grouped by severity and status.

**Auth:** Bearer token.

**Response (200):**

```json
{
  "total_alerts": 150,
  "by_severity": { "low": 40, "medium": 60, "high": 35, "critical": 15 },
  "by_status": { "new": 50, "acknowledged": 70, "resolved": 25, "ignored": 5 },
  "timestamp": "2026-04-02T12:00:00"
}
```

---

### GET /api/v1/alerts/types

Get available alert types, severities, and statuses.

**Auth:** Bearer token.

---

## Policies

Proxied to the Policy Orchestrator (port 5004).

### GET /api/v1/policies

List all firewall policies.

**Auth:** Bearer token.

---

### GET /api/v1/policies/{policy_id}

Get a single policy.

**Auth:** Bearer token.

---

### POST /api/v1/policies

Create a new policy.

**Auth:** Bearer token, role `admin`.

**Required fields:** `name`, `action`, `source`, `destination`.

**Request body:**

```json
{
  "name": "block-ssh-brute-force",
  "action": "DENY",
  "source": "10.0.1.0/24",
  "destination": "10.0.0.0/8",
  "protocol": "TCP",
  "port": 22,
  "priority": 100,
  "vendor": "nftables"
}
```

---

### PUT /api/v1/policies/{policy_id}

Update an existing policy.

**Auth:** Bearer token.

---

### DELETE /api/v1/policies/{policy_id}

Delete a policy.

**Auth:** Bearer token.

---

## Compliance Engine

Proxied to the Compliance Engine (port 5007). Supports GDPR, HIPAA, PCI-DSS, NIST CSF, and SOC 2.

### GET /api/v1/frameworks

List available compliance frameworks.

**Auth:** Bearer token.

**Response (200):**

```json
{
  "frameworks": [
    { "id": "NIST", "name": "NIST Cybersecurity Framework", "description": "...", "control_count": 23 },
    { "id": "GDPR", "name": "General Data Protection Regulation", "description": "...", "control_count": 18 },
    { "id": "SOC2", "name": "SOC 2 Trust Services Criteria", "description": "...", "control_count": 20 }
  ]
}
```

---

### GET /api/v1/frameworks/{framework_id}

Get framework details and controls.

**Auth:** Bearer token.

---

### POST /api/v1/assess

Run a compliance assessment.

**Auth:** Bearer token.

**Request body:**

```json
{
  "framework": "NIST",
  "policies": [ { "id": "pol-1", "action": "DENY", "source": "0.0.0.0/0" } ],
  "configurations": { "encryption_at_rest": true, "mfa_enabled": true }
}
```

**Response (200):**

```json
{
  "framework": "NIST",
  "assessment_id": "assess_20260402120000",
  "overall_score": 82.5,
  "status": "compliant",
  "control_assessments": { "..." : "..." },
  "gaps": [ "..." ],
  "recommendations": [ "..." ]
}
```

---

### POST /api/v1/gap-analysis

Perform gap analysis between current state and target framework.

**Auth:** Bearer token.

---

### POST /api/v1/reports

Generate a compliance report.

**Auth:** Bearer token.

**Request body:**

```json
{
  "framework": "SOC2",
  "type": "summary",
  "date_range": { "start": "2026-01-01", "end": "2026-04-01" }
}
```

---

### GET /api/v1/reports/history

Get historical compliance reports.

**Auth:** Bearer token.

**Query parameters:** `framework`, `limit`.

---

### POST /api/v1/map-policy

Map a policy to compliance controls across one or more frameworks.

**Auth:** Bearer token.

---

## AI Engine

Proxied to the AI Engine (port 5003). Provides ML-powered threat detection.

### POST /api/v1/detect

Perform threat detection on a single traffic sample.

**Auth:** Bearer token.

**Request body:**

```json
{
  "traffic_data": {
    "src_ip": "10.0.1.100",
    "dst_ip": "10.0.0.1",
    "dst_port": 22,
    "protocol": "TCP",
    "bytes_sent": 4096,
    "bytes_recv": 512,
    "duration_ms": 1500,
    "packets": 45
  },
  "context": { "time_of_day": "02:30", "geo": "US" }
}
```

**Response (200):**

```json
{
  "detection_id": "det_20260402120001",
  "is_threat": true,
  "confidence": 0.93,
  "severity": "high",
  "threat_type": "brute_force",
  "model_verdicts": {
    "xgboost": { "is_threat": true, "confidence": 0.95 },
    "lstm": { "is_threat": true, "confidence": 0.91 },
    "isolation_forest": { "is_threat": true, "confidence": 0.88 },
    "autoencoder": { "is_threat": false, "confidence": 0.62 }
  }
}
```

---

### POST /api/v1/detect/batch

Batch threat detection. Maximum batch size configured via `BATCH_SIZE` (default 1000).

**Auth:** Bearer token.

**Request body:**

```json
{
  "traffic_batch": [
    { "src_ip": "10.0.1.100", "dst_port": 22, "..." : "..." },
    { "src_ip": "10.0.1.101", "dst_port": 80, "..." : "..." }
  ]
}
```

**Response (200):**

```json
{
  "results": [ { "detection_id": "...", "is_threat": true, "..." : "..." } ],
  "total": 2,
  "threats_detected": 1
}
```

---

## DRL Engine

Proxied to the DRL Engine (port 5005). Provides autonomous policy decisions.

### POST /api/v1/decide

Get a policy decision for a detected threat.

**Auth:** Bearer token.

**Request body:**

```json
{
  "detection_id": "det_12345",
  "threat_score": 0.95,
  "threat_type": "brute_force",
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.1",
  "dest_port": 22,
  "protocol": "TCP",
  "asset_criticality": 4
}
```

**Response (200):**

```json
{
  "decision_id": "drl_20260402120000_e12345",
  "action": "DENY",
  "action_code": 1,
  "confidence": 0.92,
  "parameters": {
    "target": { "source_ip": "192.168.1.100", "dest_port": 22, "protocol": "TCP" }
  },
  "state_features": { "threat_score": 0.95, "asset_criticality": 4, "threat_type": "brute_force" },
  "timestamp": "2026-04-02T12:00:00"
}
```

---

### POST /api/v1/decide/batch

Batch policy decisions.

**Auth:** Bearer token.

---

### GET /api/v1/action-space

Get available DRL actions and descriptions.

**Auth:** Bearer token.

---

### GET /api/v1/state-space

Get state space dimensions and feature descriptions.

**Auth:** Bearer token.

---

## XAI Service

Proxied to the XAI Service (port 5006). Provides explainability for AI and DRL decisions.

### POST /api/v1/explain/detection

Explain a threat detection decision.

**Auth:** Bearer token.

**Request body:**

```json
{
  "detection_id": "det_12345",
  "features": { "bytes_sent": 5000, "packets": 200 },
  "prediction": { "confidence": 0.92, "is_threat": true },
  "model_verdicts": {
    "xgboost": { "is_threat": true, "confidence": 0.94 },
    "lstm": { "is_threat": true, "confidence": 0.88 }
  }
}
```

**Response (200):**

```json
{
  "detection_id": "det_12345",
  "summary": "High-confidence threat detected based on anomalous traffic volume and timing.",
  "detailed_explanation": "...",
  "feature_contributions": [ { "feature": "bytes_sent", "importance": 0.35, "direction": "positive" } ],
  "top_factors": [ "..." ],
  "model_contributions": [ { "model": "xgboost", "verdict": "threat", "confidence": 0.94, "weight": 0.35 } ],
  "provenance": { "models_used": ["xgboost", "lstm"], "explanation_method": "SHAP + NLG" }
}
```

---

### POST /api/v1/explain/policy

Explain a DRL policy decision.

**Auth:** Bearer token.

---

### GET /api/v1/audit-trail

Get the decision audit trail.

**Auth:** Bearer token.

**Query parameters:** `type` (`detection` or `policy`), `id`, `limit`.

---

### POST /api/v1/report/compliance

Generate a compliance-ready explanation report for given detection and decision IDs.

**Auth:** Bearer token.

---

### GET /api/v1/xai/statistics

Get XAI service statistics.

**Auth:** Bearer token.

---

## Hardening Service

Direct access on port 5011. All paths are relative to the hardening service root (not proxied through the gateway by default).

### GET /health

Health check with posture score and eBPF enforcement status.

### GET /posture

**Auth:** Bearer token.

Current hardening posture statistics: checks run, passed, failed, posture score, remediations applied, eBPF policies active.

### GET /checks

**Auth:** Bearer token.

List all available CIS benchmark check IDs.

### GET /checks/{check_id}

**Auth:** Bearer token.

Run a single CIS benchmark check and return the result.

### POST /scan

**Auth:** Bearer token, role `admin`, `operator`, or `security_analyst`.

Run a full CIS benchmark scan. Returns all check results with posture score.

### POST /harden

**Auth:** Bearer token, role `admin`.

Apply auto-remediation. Optionally pass `check_ids` array to remediate specific checks; otherwise remediates all failed auto-remediable checks.

**Request body (optional):**

```json
{
  "check_ids": ["ssh_root_login", "sysctl_ip_forward"]
}
```

### POST /rollback

**Auth:** Bearer token, role `admin`.

List available backup files for manual rollback.

### GET /enforce

**Auth:** Bearer token, role `admin` or `operator`.

Get eBPF enforcement mode and active policies.

### POST /enforce/mode

**Auth:** Bearer token, role `admin`.

Set eBPF enforcement mode (`enforce` or `audit`).

### POST /enforce/port

**Auth:** Bearer token, role `admin`.

Add a port-binding enforcement policy.

---

## HIDS Agent

Direct access on port 5010. Provides host-level intrusion detection.

### GET /health

Health check with eBPF program status and FIM path count.

### GET /status

**Auth:** Bearer token.

Detailed status: event counts by type, eBPF programs loaded, FIM paths monitored.

### GET /events

**Auth:** Bearer token.

**Query parameters:** `limit` (default 50), `type` (filter by event type).

Recent kernel events: process executions, file access, network connections, privilege escalations, module loads.

### GET /baselines

**Auth:** Bearer token.

Current FIM file hash baselines and allowed execution paths.

### POST /baselines/rebuild

**Auth:** Bearer token, role `admin` or `operator`.

Rebuild FIM baselines from current file state.

### POST /baselines/execs

**Auth:** Bearer token, role `admin`.

Add or remove paths from the process execution allowlist.

### GET /fim/alerts

**Auth:** Bearer token.

Get file integrity monitoring alerts (modified or deleted files).

---

## System

### GET /health

API Gateway health check (unauthenticated).

**Response (200):**

```json
{
  "status": "healthy",
  "timestamp": 1712000000.0,
  "request_stats": {}
}
```

---

### GET /api/v1/stats

### GET /api/v1/statistics

Aggregated real-time statistics from all downstream services.

**Auth:** Bearer token.

**Response (200):**

```json
{
  "requests": {},
  "threats_detected": 42,
  "alerts_total": 150,
  "alerts_by_severity": { "low": 40, "medium": 60, "high": 35, "critical": 15 },
  "policies_total": 25,
  "system_health": "healthy",
  "timestamp": 1712000000.0
}
```

---

### GET /api/v1/config

Get system configuration (admin only).

**Auth:** Bearer token, role `admin`.

---

### PUT /api/v1/config

Update system configuration (admin only).

**Auth:** Bearer token, role `admin`.

**Required sections:** `ai_engine`, `firewall`, `monitoring`.

---

## SSE Streaming

Server-Sent Events endpoints for real-time dashboard updates. Connect with `EventSource` or any SSE client.

### GET /api/v1/stream/threats

**Auth:** Bearer token (via header or `?token=` query parameter).

Streams real-time threat detection events from the Redis pub/sub channel. Heartbeat every 15 seconds.

### GET /api/v1/stream/alerts

**Auth:** Bearer token (via header or `?token=` query parameter).

Streams real-time alert events. Heartbeat every 15 seconds.

**Event format:**

```
data: {"type": "new_alert", "alert": {...}, "timestamp": 1712000000.0}
```

---

## Error Codes

| Code | Meaning                                      |
|------|----------------------------------------------|
| 400  | Bad request -- missing or invalid parameters |
| 401  | Unauthorized -- missing or invalid token     |
| 403  | Forbidden -- insufficient role permissions   |
| 404  | Not found -- resource or endpoint missing    |
| 409  | Conflict -- duplicate resource               |
| 429  | Too many requests -- rate limit exceeded     |
| 500  | Internal server error                        |
| 503  | Service unavailable -- downstream service unreachable |

All error responses follow a consistent format:

```json
{
  "error": "Short error description",
  "message": "Human-readable detail (optional)"
}
```
