# SENTINEL ML Model Documentation

## Overview

SENTINEL employs a multi-model ensemble approach for threat detection, combining supervised learning for known threats with unsupervised methods for zero-day detection.

## Detection Models

### 1. XGBoost Classifier

**Purpose**: Classification of known threat types

**Features**:
- 50+ network traffic features
- Multi-class classification (13 threat categories)
- High throughput inference (~10k samples/sec)

**Threat Categories**:
- Benign
- Malware
- DoS/DDoS Attack
- Brute Force
- Port Scan
- SQL Injection
- XSS
- Data Exfiltration
- Lateral Movement
- C2 Communication
- Ransomware

**Training Data**:
- CIC-IDS2017 dataset
- UNSW-NB15 dataset
- Internal labeled data

**Performance Metrics**:
| Metric | Value |
|--------|-------|
| Accuracy | 97.2% |
| Precision | 96.8% |
| Recall | 95.4% |
| F1-Score | 96.1% |

### 2. LSTM Sequence Detector

**Purpose**: Detection of multi-stage attacks and temporal patterns

**Architecture**:
```
Input (50 features) 
  → Bidirectional LSTM (128 hidden, 2 layers)
  → Multi-head Attention (4 heads)
  → Global Average Pooling
  → Dense (128) → ReLU → Dropout
  → Dense (2) → Softmax
```

**Input**: Sequences of 20 network events

**Training Configuration**:
- Optimizer: Adam (lr=0.001)
- Loss: Cross-entropy
- Batch size: 64
- Early stopping patience: 10

### 3. Isolation Forest

**Purpose**: Unsupervised anomaly detection for zero-day threats

**Configuration**:
- n_estimators: 200
- contamination: 0.1
- max_samples: 'auto'

**Key Advantage**: No labeled data required; learns normal traffic patterns

### 4. Autoencoder

**Purpose**: Reconstruction-based anomaly detection

**Architecture**:
```
Encoder: 50 → 128 → 64 → 32 → 16 (latent)
Decoder: 16 → 32 → 64 → 128 → 50
```

**Anomaly Score**: Reconstruction error (MSE)
- Threshold: mean + 2*std of training reconstruction errors

### 5. Stacking Ensemble

**Purpose**: Combine predictions from all models

**Weights** (configurable):
- XGBoost: 35%
- LSTM: 25%
- Isolation Forest: 20%
- Autoencoder: 20%

**Final Decision**: Weighted voting with confidence calibration

## DRL Policy Engine

### PPO Agent

**Algorithm**: Proximal Policy Optimization (PPO)

**State Space** (12 dimensions):
| Feature | Range | Description |
|---------|-------|-------------|
| threat_score | 0-1 | Detection confidence |
| src_reputation | 0-1 | IP reputation score |
| asset_criticality | 0-1 | Target importance (normalized) |
| traffic_volume | 0-1 | Normalized traffic rate |
| protocol_risk | 0-1 | Protocol-based risk |
| time_risk | 0-1 | Time-of-day risk |
| historical_alerts | 0-1 | Past alert count (normalized) |
| is_internal | 0/1 | Internal traffic flag |
| port_sensitivity | 0-1 | Target port risk |
| connection_freq | 0-1 | Connection frequency |
| payload_anomaly | 0-1 | Payload anomaly score |
| geo_risk | 0-1 | Geographic risk |

**Action Space** (8 actions):
| Action | Description |
|--------|-------------|
| ALLOW | Allow traffic |
| DENY | Block traffic |
| RATE_LIMIT_LOW | Light rate limiting (1000 pps) |
| RATE_LIMIT_MEDIUM | Medium rate limiting (100 pps) |
| RATE_LIMIT_HIGH | Strict rate limiting (10 pps) |
| QUARANTINE_SHORT | Isolate for 1 hour |
| QUARANTINE_LONG | Isolate for 24 hours |
| MONITOR | Enhanced monitoring |

**Reward Function**:
```
R = α(blocked_threats) - β(false_positives) - γ(latency_impact) + δ(compliance_score)

Where:
  α = 1.0  (blocked threat bonus)
  β = 2.0  (false positive penalty)
  γ = 0.5  (latency penalty)
  δ = 0.3  (compliance bonus)
```

**Network Architecture**:
```
Policy Network:
  State (12) → Dense (256) → ReLU → Dense (256) → ReLU → Dense (8) → Softmax

Value Network:
  State (12) → Dense (256) → ReLU → Dense (256) → ReLU → Dense (1)
```

**Training Parameters**:
- Learning rate: 3e-4
- Discount factor (γ): 0.99
- GAE λ: 0.95
- Clipping ε: 0.2
- Entropy coefficient: 0.01
- Value coefficient: 0.5

## Feature Engineering

### Statistical Features
- packet_size_mean, packet_size_std, packet_size_min/max
- inter_arrival_time_mean, inter_arrival_time_std
- byte_rate, packet_rate
- tcp_flag_ratios (SYN, ACK, FIN, RST)

### Behavioral Features
- src_ip_entropy, dst_ip_entropy
- src_port_entropy, dst_port_entropy
- connection_fan_out, connection_fan_in
- protocol_distribution

### Contextual Features
- asset_criticality
- user_privilege_level
- time_risk_score
- geo_risk_score
- historical_alert_count

## Model Versioning

Models are versioned using semantic versioning:
- MAJOR: Breaking changes (different feature set)
- MINOR: Performance improvements
- PATCH: Bug fixes

Current versions:
- XGBoost: 1.2.0
- LSTM: 1.1.0
- Isolation Forest: 1.0.2
- Autoencoder: 1.0.1
- PPO Agent: 1.3.0

## Model Update Process

1. **Data Collection**: Continuous collection from production
2. **Validation**: Hold-out set evaluation
3. **Shadow Deployment**: Run new model alongside production
4. **A/B Testing**: Compare performance metrics
5. **Gradual Rollout**: Progressive traffic shift
6. **Monitoring**: Performance dashboards and alerts

## Explainability

SHAP values are computed for all detection decisions:
- Feature contribution to threat score
- Model-level contribution breakdown
- Natural language explanations

Example output:
```json
{
  "top_factors": [
    {"feature": "syn_ratio", "contribution": 0.32, "direction": "+"},
    {"feature": "connection_freq", "contribution": 0.28, "direction": "+"},
    {"feature": "src_reputation", "contribution": -0.15, "direction": "-"}
  ],
  "explanation": "High threat score primarily due to elevated SYN packet ratio (0.85) and abnormal connection frequency (150 conn/min), partially offset by moderate source reputation (0.4)."
}
```
