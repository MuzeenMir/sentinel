# SENTINEL API Reference

Base URL: `https://api.sentinel.example.com` (production) or `http://localhost:8080` (development)

## Authentication

All API endpoints require a valid JWT token in the Authorization header:

```
Authorization: Bearer <token>
```

### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

## Threat Detection API

### Get All Threats

```http
GET /api/v1/threats?limit=50&offset=0&severity=high
```

Response:
```json
{
  "threats": [
    {
      "id": "det_abc123",
      "type": "brute_force",
      "severity": "high",
      "source_ip": "192.168.1.100",
      "dest_ip": "10.0.0.1",
      "confidence": 0.95,
      "timestamp": "2024-01-24T10:30:00Z",
      "status": "blocked"
    }
  ],
  "total": 1247
}
```

### Get Threat Details

```http
GET /api/v1/threats/{threat_id}
```

### Run Detection

```http
POST /api/v1/detect
Content-Type: application/json

{
  "traffic_data": {
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "dest_port": 22,
    "protocol": "TCP",
    "bytes": 1500,
    "packets": 10
  },
  "context": {
    "asset_criticality": 4
  }
}
```

Response:
```json
{
  "detection_id": "det_xyz789",
  "is_threat": true,
  "confidence": 0.92,
  "threat_type": "brute_force",
  "model_verdicts": {
    "xgboost": {"is_threat": true, "confidence": 0.94},
    "lstm": {"is_threat": true, "confidence": 0.88},
    "isolation_forest": {"is_threat": true, "confidence": 0.91}
  }
}
```

---

## Policy API

### Get All Policies

```http
GET /api/v1/policies
```

### Create Policy

```http
POST /api/v1/policies
Content-Type: application/json

{
  "name": "Block SSH Brute Force",
  "description": "Block repeated SSH login attempts",
  "action": "DENY",
  "source": {
    "ip": "192.168.1.100",
    "cidr": "/32"
  },
  "destination": {
    "port": 22
  },
  "protocol": "TCP",
  "priority": 100,
  "duration": 3600,
  "vendors": ["iptables", "aws_security_group"]
}
```

### Apply DRL Decision

```http
POST /api/v1/policies/apply
Content-Type: application/json

{
  "decision_id": "drl_abc123",
  "action": "DENY",
  "target": {
    "source_ip": "192.168.1.100",
    "dest_port": 22,
    "protocol": "TCP"
  },
  "duration": 3600,
  "confidence": 0.95,
  "threat_type": "brute_force",
  "vendors": ["iptables"]
}
```

### Rollback Policy

```http
POST /api/v1/policies/{policy_id}/rollback
```

---

## DRL Engine API

### Get Policy Decision

```http
POST /api/v1/decide
Content-Type: application/json

{
  "detection_id": "det_abc123",
  "threat_score": 0.95,
  "threat_type": "brute_force",
  "source_ip": "192.168.1.100",
  "dest_port": 22,
  "asset_criticality": 4
}
```

Response:
```json
{
  "decision_id": "drl_xyz789",
  "action": "DENY",
  "confidence": 0.92,
  "parameters": {
    "target": {
      "source_ip": "192.168.1.100",
      "dest_port": 22,
      "protocol": "TCP"
    },
    "duration": 3600
  }
}
```

### Submit Feedback

```http
POST /api/v1/feedback
Content-Type: application/json

{
  "decision_id": "drl_xyz789",
  "outcome": "success",
  "blocked_threat": true,
  "false_positive": false,
  "latency_impact": 0.02
}
```

---

## XAI (Explainability) API

### Explain Detection

```http
POST /api/v1/explain/detection
Content-Type: application/json

{
  "detection_id": "det_abc123",
  "features": {...},
  "prediction": {...},
  "model_verdicts": {...}
}
```

Response:
```json
{
  "detection_id": "det_abc123",
  "summary": "High-confidence threat detected due to elevated threat score and repeated connection attempts",
  "feature_contributions": [
    {"feature": "syn_ratio", "shap_value": 0.32, "direction": "increases_threat"},
    {"feature": "connection_frequency", "shap_value": 0.28, "direction": "increases_threat"}
  ],
  "top_factors": ["High SYN packet ratio", "Abnormal connection frequency"]
}
```

### Get Audit Trail

```http
GET /api/v1/audit-trail?type=detection&id=det_abc123
```

---

## Compliance API

### Get Frameworks

```http
GET /api/v1/frameworks
```

### Run Assessment

```http
POST /api/v1/assess
Content-Type: application/json

{
  "framework": "NIST",
  "policies": [...],
  "configurations": {...}
}
```

Response:
```json
{
  "framework": "NIST",
  "overall_score": 94,
  "status": "compliant",
  "control_assessments": [
    {"control_id": "PR.AC", "status": "compliant", "score": 100},
    {"control_id": "DE.CM", "status": "partial", "score": 75}
  ],
  "gaps": [...],
  "recommendations": [...]
}
```

### Generate Report

```http
POST /api/v1/reports
Content-Type: application/json

{
  "framework": "GDPR",
  "type": "detailed",
  "date_range": {
    "start": "2024-01-01",
    "end": "2024-01-24"
  }
}
```

---

## Traffic Statistics API

### Get Traffic Stats

```http
GET /api/v1/traffic
```

### Get Dashboard Statistics

```http
GET /api/v1/statistics
```

Response:
```json
{
  "total_threats": 1247,
  "blocked_threats": 1189,
  "active_policies": 42,
  "compliance_score": 94,
  "traffic_summary": {
    "inbound_bytes": 1500000000,
    "outbound_bytes": 800000000,
    "total_packets": 2500000
  }
}
```

---

## Error Responses

All endpoints return standard error responses:

```json
{
  "error": "Error message",
  "details": "Additional details if available",
  "code": "ERROR_CODE"
}
```

Common HTTP Status Codes:
- `400` Bad Request
- `401` Unauthorized
- `403` Forbidden
- `404` Not Found
- `409` Conflict
- `500` Internal Server Error

---

## Rate Limiting

- Default: 100 requests per minute per user
- Detection endpoints: 1000 requests per minute
- Batch endpoints: 10 requests per minute

Headers returned:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1706097600
```
