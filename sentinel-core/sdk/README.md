# SENTINEL Python SDK

Client library for interacting with the SENTINEL Security Platform API.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Threat Detection](#threat-detection)
- [Alert Management](#alert-management)
- [Policy Management](#policy-management)
- [Compliance Assessment](#compliance-assessment)
- [DRL Policy Decisions](#drl-policy-decisions)
- [Explainability](#explainability)
- [Streaming Events](#streaming-events)
- [Custom Detector Development](#custom-detector-development)
- [Error Handling](#error-handling)
- [Configuration](#configuration)

---

## Installation

```bash
pip install sentinel-sdk
```

Or install from source:

```bash
cd sentinel-core/sdk
pip install -e .
```

**Dependencies:** `requests>=2.31`, `sseclient-py>=1.7`.

---

## Quick Start

```python
from sentinel_sdk import SentinelClient

client = SentinelClient(
    base_url="https://sentinel.example.com",
    username="analyst1",
    password="Str0ng!Pass#2026",
)

# Detect a threat
result = client.detect({
    "src_ip": "10.0.1.100",
    "dst_ip": "10.0.0.1",
    "dst_port": 22,
    "protocol": "TCP",
    "bytes_sent": 4096,
    "packets": 45,
})

if result["is_threat"]:
    print(f"Threat detected: {result['threat_type']} "
          f"(confidence: {result['confidence']:.2f})")

    # Get an explanation
    explanation = client.explain_detection(result["detection_id"])
    print(explanation["summary"])

    # Request an autonomous policy decision
    decision = client.decide(
        detection_id=result["detection_id"],
        threat_score=result["confidence"],
        threat_type=result["threat_type"],
        source_ip="10.0.1.100",
        dest_ip="10.0.0.1",
        dest_port=22,
    )
    print(f"Action: {decision['action']} (confidence: {decision['confidence']:.2f})")
```

---

## Authentication

The SDK handles JWT token lifecycle automatically. Tokens are refreshed transparently before expiration.

```python
from sentinel_sdk import SentinelClient

# Username/password authentication
client = SentinelClient(
    base_url="https://sentinel.example.com",
    username="admin",
    password="Str0ng!Pass#2026",
)

# Token-based authentication (e.g., for service accounts)
client = SentinelClient(
    base_url="https://sentinel.example.com",
    token="<pre-obtained-jwt>",
)

# Check current user
profile = client.get_profile()
print(profile["username"], profile["role"])

# Explicitly refresh the token
client.refresh_token()

# Logout (blacklists the token)
client.logout()
```

---

## Threat Detection

### Single Detection

```python
result = client.detect({
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "dst_port": 443,
    "protocol": "TCP",
    "bytes_sent": 102400,
    "bytes_recv": 2048,
    "duration_ms": 5000,
    "packets": 150,
})

print(result["is_threat"])        # True/False
print(result["confidence"])       # 0.0 - 1.0
print(result["threat_type"])      # e.g., "brute_force"
print(result["model_verdicts"])   # Per-model results
```

### Batch Detection

```python
samples = [
    {"src_ip": "10.0.1.1", "dst_port": 22, "protocol": "TCP", "bytes_sent": 512},
    {"src_ip": "10.0.1.2", "dst_port": 80, "protocol": "TCP", "bytes_sent": 1024},
    {"src_ip": "10.0.1.3", "dst_port": 443, "protocol": "TCP", "bytes_sent": 2048},
]

results = client.detect_batch(samples)
for r in results["results"]:
    if r["is_threat"]:
        print(f"Threat: {r['threat_type']} from detection {r['detection_id']}")

print(f"Total threats: {results['threats_detected']}/{results['total']}")
```

---

## Alert Management

```python
# List alerts with filters
alerts = client.list_alerts(severity="critical", status="new", limit=10)
for alert in alerts["alerts"]:
    print(f"[{alert['severity']}] {alert['type']}: {alert['description']}")

# Get a specific alert
alert = client.get_alert("alert_1712000000_1234")

# Create an alert
alert_id = client.create_alert(
    alert_type="network_anomaly",
    severity="high",
    description="Unusual outbound traffic to known C2 server",
    details={"dest_ip": "198.51.100.1", "bytes": 1048576},
    tags=["c2", "exfiltration"],
)

# Acknowledge an alert
client.acknowledge_alert(alert_id)

# Resolve an alert
client.resolve_alert(alert_id)

# Get alert statistics
stats = client.alert_statistics()
print(f"Total: {stats['total_alerts']}, Critical: {stats['by_severity']['critical']}")
```

---

## Policy Management

```python
# List policies
policies = client.list_policies()

# Create a policy
policy = client.create_policy(
    name="block-ssh-brute-force",
    action="DENY",
    source="10.0.1.0/24",
    destination="10.0.0.0/8",
    protocol="TCP",
    port=22,
)

# Update a policy
client.update_policy(policy["id"], action="RATE_LIMIT")

# Delete a policy
client.delete_policy(policy["id"])
```

---

## Compliance Assessment

```python
# List available frameworks
frameworks = client.list_frameworks()
for fw in frameworks["frameworks"]:
    print(f"{fw['id']}: {fw['name']} ({fw['control_count']} controls)")

# Run a compliance assessment
assessment = client.assess_compliance(
    framework="NIST",
    policies=policies["policies"],
    configurations={"encryption_at_rest": True, "mfa_enabled": True},
)
print(f"Score: {assessment['overall_score']}% - {assessment['status']}")

# Gap analysis
gaps = client.gap_analysis(framework="SOC2", current_controls={})
for gap in gaps["gaps"]:
    print(f"Gap: {gap['control']} - {gap['description']}")

# Generate compliance report
report = client.generate_compliance_report(
    framework="PCI-DSS",
    report_type="detailed",
    date_range={"start": "2026-01-01", "end": "2026-04-01"},
)
```

---

## DRL Policy Decisions

```python
# Get an autonomous policy decision
decision = client.decide(
    detection_id="det_12345",
    threat_score=0.95,
    threat_type="brute_force",
    source_ip="192.168.1.100",
    dest_ip="10.0.0.1",
    dest_port=22,
    protocol="TCP",
    asset_criticality=4,
)

print(f"Action: {decision['action']}")
print(f"Confidence: {decision['confidence']:.2f}")

# Submit feedback on the decision
client.submit_drl_feedback(
    decision_id=decision["decision_id"],
    outcome="success",
    blocked_threat=True,
    false_positive=False,
)

# View action space
actions = client.get_action_space()
for action in actions["actions"]:
    print(f"{action['code']}: {action['name']} - {action['description']}")
```

---

## Explainability

```python
# Explain a detection
explanation = client.explain_detection(
    detection_id="det_12345",
    features={"bytes_sent": 5000, "packets": 200},
    prediction={"confidence": 0.92, "is_threat": True},
    model_verdicts={
        "xgboost": {"is_threat": True, "confidence": 0.94},
        "lstm": {"is_threat": True, "confidence": 0.88},
    },
)

print(explanation["summary"])
for factor in explanation["top_factors"]:
    print(f"  {factor['feature']}: {factor['importance']:.3f}")

# Explain a policy decision
policy_explanation = client.explain_policy(
    decision_id="drl_12345",
    action="DENY",
    state_features={"threat_score": 0.95, "asset_criticality": 4},
    confidence=0.92,
)

# Get audit trail
trail = client.get_audit_trail(entity_type="detection", limit=50)
```

---

## Streaming Events

Subscribe to real-time threat and alert events via Server-Sent Events:

```python
# Stream threats
for event in client.stream_threats():
    print(f"Threat event: {event}")

# Stream alerts
for event in client.stream_alerts():
    if event.get("type") == "new_alert":
        alert = event["alert"]
        print(f"New alert: [{alert['severity']}] {alert['description']}")
```

---

## Custom Detector Development

Build custom detectors that integrate with the SENTINEL ensemble.

### Detector Interface

All custom detectors must implement the `BaseDetector` interface:

```python
import numpy as np
from sentinel_sdk.detectors import BaseDetector


class MyCustomDetector(BaseDetector):
    """Custom detector for domain-specific threats."""

    def __init__(self, model_path=None):
        super().__init__(model_path)
        self._model = None

    def load_model(self):
        # Load your model from self.model_path
        self._is_ready = True
        return True

    def save_model(self, path=None):
        # Save model artefacts
        return True

    def predict(self, features: np.ndarray) -> dict:
        # Run inference
        return {
            "detector": "my_custom_detector",
            "is_threat": False,
            "confidence": 0.0,
            "threat_type": "benign",
        }

    def predict_batch(self, features: np.ndarray) -> list:
        return [self.predict(features[i]) for i in range(len(features))]

    def train(self, X: np.ndarray, y: np.ndarray = None) -> dict:
        # Train your model
        return {"accuracy": 0.95}
```

### Registering a Custom Detector

```python
from sentinel_sdk.ensemble import EnsembleManager

manager = EnsembleManager(base_url="https://sentinel.example.com", token="<jwt>")

# Register the detector
manager.register_detector(
    name="my_custom_detector",
    detector_class=MyCustomDetector,
    weight=0.15,
    model_path="/models/custom",
)

# The ensemble now includes your detector in its voting
```

### Feature Extractor Plugin

```python
from sentinel_sdk.features import BaseFeatureExtractor


class DomainSpecificFeatures(BaseFeatureExtractor):
    """Extract features specific to your network environment."""

    def extract(self, raw_data: dict) -> dict:
        return {
            "custom_metric_1": self._compute_metric(raw_data),
            "custom_metric_2": self._compute_other(raw_data),
        }
```

---

## Error Handling

The SDK raises typed exceptions:

```python
from sentinel_sdk.exceptions import (
    SentinelAuthError,
    SentinelAPIError,
    SentinelRateLimitError,
    SentinelConnectionError,
)

try:
    result = client.detect(traffic_data)
except SentinelAuthError:
    # Token expired or invalid -- re-authenticate
    client.authenticate()
    result = client.detect(traffic_data)
except SentinelRateLimitError as e:
    # Back off and retry
    time.sleep(e.retry_after)
    result = client.detect(traffic_data)
except SentinelAPIError as e:
    # Server-side error
    print(f"API error {e.status_code}: {e.message}")
except SentinelConnectionError:
    # Network connectivity issue
    print("Cannot reach SENTINEL API")
```

---

## Configuration

### Environment Variables

The SDK respects these environment variables as defaults:

| Variable               | Description                              |
|------------------------|------------------------------------------|
| `SENTINEL_BASE_URL`   | API base URL                             |
| `SENTINEL_USERNAME`   | Authentication username                  |
| `SENTINEL_PASSWORD`   | Authentication password                  |
| `SENTINEL_TOKEN`      | Pre-obtained JWT token                   |
| `SENTINEL_TIMEOUT`    | Request timeout in seconds (default 30)  |
| `SENTINEL_VERIFY_SSL` | SSL verification (`true`/`false`)        |

### Client Options

```python
client = SentinelClient(
    base_url="https://sentinel.example.com",
    username="admin",
    password="Str0ng!Pass#2026",
    timeout=30,
    verify_ssl=True,
    max_retries=3,
    retry_backoff=1.0,
)
```
