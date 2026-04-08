# SENTINEL ML Model Architecture

This document describes the machine learning models, feature engineering pipeline, and training infrastructure used by the SENTINEL AI Engine and DRL Engine.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Feature Engineering](#feature-engineering)
- [XGBoost Classifier](#xgboost-classifier)
- [LSTM Sequence Detector](#lstm-sequence-detector)
- [Isolation Forest](#isolation-forest)
- [Autoencoder Anomaly Detector](#autoencoder-anomaly-detector)
- [Stacking Ensemble](#stacking-ensemble)
- [PPO DRL Agent](#ppo-drl-agent)
- [Model Versioning and Deployment](#model-versioning-and-deployment)
- [Retraining Pipeline](#retraining-pipeline)

---

## Architecture Overview

SENTINEL uses a multi-model ensemble architecture for threat detection, combined with a deep reinforcement learning agent for autonomous policy generation.

```
Raw Traffic Data
      |
      v
+---------------------+
| Feature Extraction   |
| - Statistical        |
| - Behavioral         |
| - Contextual         |
+---------------------+
      |
      v
+---------------------+     +---------------------+
| Supervised Models    |     | Unsupervised Models |
| - XGBoost Classifier|     | - Isolation Forest  |
| - LSTM Sequence      |     | - Autoencoder       |
+---------------------+     +---------------------+
      |                           |
      +----------+----------------+
                 |
                 v
       +-------------------+
       | Stacking Ensemble  |
       | (Meta-Learner)     |
       +-------------------+
                 |
                 v
         Detection Result
         (is_threat, confidence, type)
                 |
                 v
       +-------------------+
       | PPO DRL Agent      |
       | (Policy Decision)  |
       +-------------------+
                 |
                 v
       Policy Action (DENY, ALLOW, RATE_LIMIT, MONITOR, ...)
```

---

## Feature Engineering

Three feature extractors run in parallel to generate a comprehensive feature vector from raw network data.

### Statistical Features

**Module:** `ai-engine/features/statistical.py`

Extracts numerical distributions from traffic metadata:

- Byte count statistics (mean, std, min, max, percentiles for sent/received).
- Packet rate and inter-arrival time distributions.
- Connection duration statistics.
- Protocol distribution ratios (TCP/UDP/ICMP).
- Port entropy and destination diversity metrics.

### Behavioral Features

**Module:** `ai-engine/features/behavioral.py`

Captures temporal and session-level patterns:

- Request frequency and burstiness over sliding windows.
- Session duration and idle time distributions.
- Connection establishment patterns (SYN/ACK ratios).
- Failed connection rates.
- Periodic activity detection (beaconing).

### Contextual Features

**Module:** `ai-engine/features/contextual.py`

Enriches with environmental context:

- Time-of-day and day-of-week encoding.
- Source IP reputation scores.
- Geolocation risk factors.
- Asset criticality of destination.
- Historical alert density for source/destination pair.

### Combined Feature Vector

The combined feature vector has 50 dimensions by default, passed to all detection models.

---

## XGBoost Classifier

**Module:** `ai-engine/models/supervised/xgboost_detector.py`

### Architecture

Gradient-boosted decision tree ensemble using the XGBoost library. Performs multi-class classification across all threat categories.

### Hyperparameters

| Parameter            | Value  | Description                           |
|----------------------|--------|---------------------------------------|
| `n_estimators`       | 300    | Number of boosting rounds             |
| `max_depth`          | 8      | Maximum tree depth                    |
| `learning_rate`      | 0.05   | Shrinkage per round                   |
| `subsample`          | 0.8    | Row sampling ratio                    |
| `colsample_bytree`   | 0.8    | Feature sampling ratio per tree       |
| `min_child_weight`   | 3      | Minimum sum of instance weight        |
| `gamma`              | 0.1    | Minimum loss reduction for split      |
| `reg_alpha`          | 0.1    | L1 regularization                     |
| `reg_lambda`         | 1.0    | L2 regularization                     |
| `objective`          | `multi:softprob` | Multi-class probability output |
| `tree_method`        | `hist` | Histogram-based split finding         |

### Input/Output

- **Input:** Feature vector of shape `(n_features,)` or batch `(n_samples, n_features)`, StandardScaler normalized.
- **Output:** Per-class probabilities, predicted class, confidence score, and threat category label.

### Threat Categories

Defined in `models/base.py`:

- `benign`
- `malware`
- `brute_force`
- `port_scan`
- `dos`
- `data_exfiltration`
- `lateral_movement`
- `privilege_escalation`
- `unknown`

### Training Data Requirements

- Minimum 500 labelled samples for initial training.
- Balanced representation across threat categories.
- 80/20 train/validation split with stratification.
- StandardScaler fitted on training data and persisted with the model.

### Performance Targets

| Metric            | Target  |
|-------------------|---------|
| F1 (weighted)     | >= 0.90 |
| Accuracy          | >= 0.92 |
| Precision (weighted) | >= 0.90 |
| Recall (weighted) | >= 0.88 |
| Inference latency (p95) | < 5ms per sample |

### Artefacts

- `xgboost_model.joblib` -- serialized XGBClassifier.
- `xgboost_scaler.joblib` -- fitted StandardScaler.
- `xgboost_meta.json` -- version, last updated, metrics, parameters.

---

## LSTM Sequence Detector

**Module:** `ai-engine/models/supervised/lstm_sequence.py`

### Architecture

Bidirectional LSTM with soft-attention mechanism for temporal attack pattern recognition.

```
Input (batch, seq_len, input_size)
        |
        v
  Bidirectional LSTM (2 layers, hidden=128)
        |
        v
  Soft Attention (Linear -> Tanh -> Linear -> Softmax)
        |
        v
  Context Vector (2 * hidden_size)
        |
        v
  Classifier (Linear -> ReLU -> Dropout -> Linear)
        |
        v
  Class Logits (num_classes)
```

### Configuration

| Parameter        | Value  | Description                             |
|------------------|--------|-----------------------------------------|
| `input_size`     | 50     | Feature vector dimension per timestep   |
| `hidden_size`    | 128    | LSTM hidden state dimension             |
| `num_layers`     | 2      | Stacked LSTM layers                     |
| `dropout`        | 0.3    | Dropout rate                            |
| `sequence_length`| 32     | Number of timesteps per sequence        |
| `learning_rate`  | 1e-3   | Adam optimizer learning rate            |
| `batch_size`     | 64     | Training batch size                     |
| `max_epochs`     | 50     | Maximum training epochs                 |

### Input/Output

- **Input:** Sequence tensor of shape `(batch, 32, 50)` representing 32 consecutive network events.
- **Output:** Per-class probabilities via softmax, predicted class, confidence score.

### Training Details

- Optimizer: Adam with ReduceLROnPlateau scheduler (patience=3, factor=0.5).
- Loss: CrossEntropyLoss.
- Gradient clipping: max_norm=1.0.
- Early stopping: patience=7 epochs.
- Device: CUDA if available, CPU fallback.

### Performance Targets

| Metric            | Target  |
|-------------------|---------|
| Accuracy          | >= 0.88 |
| Final loss        | < 0.3   |
| Inference latency (p95) | < 10ms per sequence |

### Artefacts

- `lstm_model.pt` -- PyTorch state dict.
- `lstm_meta.json` -- version, config, metrics.

---

## Isolation Forest

**Module:** `ai-engine/models/unsupervised/isolation_forest.py`

### Architecture

Scikit-learn Isolation Forest for unsupervised anomaly detection. Isolates anomalies by random recursive partitioning.

### Configuration

| Parameter        | Value  | Description                              |
|------------------|--------|------------------------------------------|
| `n_estimators`   | 200    | Number of isolation trees                |
| `contamination`  | 0.1    | Expected proportion of anomalies         |
| `max_samples`    | auto   | Subsampling for tree construction        |
| `max_features`   | 1.0    | Feature subsampling ratio                |
| `random_state`   | 42     | Reproducibility seed                     |

### Input/Output

- **Input:** Feature vector `(n_features,)` or batch `(n_samples, n_features)`.
- **Output:** Anomaly score, binary anomaly flag, confidence mapped from the anomaly score.

### Training Data Requirements

- Train on predominantly normal (benign) traffic.
- No labels required (unsupervised).
- Minimum 1000 samples recommended for stable isolation boundaries.

---

## Autoencoder Anomaly Detector

**Module:** `ai-engine/models/unsupervised/autoencoder.py`

### Architecture

Symmetric encoder-decoder with batch normalization for reconstruction-based anomaly detection.

```
Input (input_dim=50)
    |
    v
Encoder:
  Linear(50, 25) -> BatchNorm -> ReLU -> Dropout(0.2)
  Linear(25, 16) -> BatchNorm -> ReLU -> Dropout(0.2)
  Linear(16, latent_dim)
    |
    v
Latent Space (dim=16)
    |
    v
Decoder:
  Linear(latent_dim, 16) -> BatchNorm -> ReLU -> Dropout(0.2)
  Linear(16, 25) -> BatchNorm -> ReLU
  Linear(25, 50)
    |
    v
Reconstruction (input_dim=50)
```

### Configuration

| Parameter              | Value  | Description                               |
|------------------------|--------|-------------------------------------------|
| `input_dim`            | 50     | Feature vector dimension                  |
| `latent_dim`           | 16     | Bottleneck dimension                      |
| `dropout`              | 0.2    | Dropout rate                              |
| `learning_rate`        | 1e-3   | Adam optimizer learning rate              |
| `batch_size`           | 128    | Training batch size                       |
| `max_epochs`           | 100    | Maximum training epochs                   |
| `threshold_percentile` | 95.0   | Percentile of training error for threshold|

### Input/Output

- **Input:** Feature vector `(n_features,)`, z-score normalized using training mean/std.
- **Output:** Reconstruction error (MSE), anomaly flag (error > threshold), confidence score.

### Anomaly Detection Logic

1. Normalize input using stored training mean and standard deviation.
2. Pass through encoder-decoder to get reconstruction.
3. Calculate mean squared error between input and reconstruction.
4. If MSE exceeds the learned threshold (95th percentile of training errors), flag as anomaly.
5. Map error magnitude to a 0-1 confidence score.

### Training Data Requirements

- Train on normal (benign) traffic only.
- No labels required.
- Minimum 1000 samples.
- The threshold is automatically set at the 95th percentile of training reconstruction errors.

### Artefacts

- `autoencoder_model.pt` -- PyTorch state dict.
- `autoencoder_meta.json` -- version, config, threshold, normalization parameters.

---

## Stacking Ensemble

**Module:** `ai-engine/models/ensemble/stacking_classifier.py`

### Architecture

Two-level stacking that combines outputs from all base detectors:

1. **Base level:** Each detector (XGBoost, LSTM, Isolation Forest, Autoencoder) produces an `(is_threat, confidence)` pair.
2. **Meta level:** A logistic regression meta-learner trained on base-detector outputs produces the final verdict.

### Fallback Mode

When no trained meta-learner is available, the ensemble falls back to **weighted average voting**:

- Each detector contributes its confidence weighted by its assigned weight.
- A sample is flagged as a threat if the weighted threat vote ratio >= 0.5 and the weighted confidence >= the threshold (default 0.85).

### Default Detector Weights

| Detector         | Weight |
|------------------|--------|
| XGBoost          | 0.35   |
| LSTM             | 0.25   |
| Isolation Forest | 0.20   |
| Autoencoder      | 0.20   |

### Meta-Learner Training

- Input: concatenated `(is_threat, confidence)` pairs from all base detectors, shape `(n_samples, 2 * n_detectors)`.
- Model: Multinomial logistic regression (L-BFGS solver, C=1.0, max_iter=1000).
- Requires labelled data (same format as XGBoost training).

### Artefacts

- `meta_learner.joblib` -- serialized LogisticRegression.
- `ensemble_meta.json` -- detector weights, threshold.

---

## PPO DRL Agent

**Module:** `drl-engine/agent/ppo_agent.py`

### Architecture

Proximal Policy Optimization agent implemented with stable-baselines3 for autonomous firewall policy generation.

**Custom feature extractor:**

```
Input (state_dim)
    |
    v
Linear(state_dim, 256) -> LayerNorm -> ReLU
Linear(256, 128) -> LayerNorm -> ReLU
    |
    v
Features (128)
    |
    +-- Policy head: Linear(128, 64) -> Tanh -> Linear(64, action_dim)
    +-- Value head:  Linear(128, 64) -> Tanh -> Linear(64, 1)
```

### PPO Hyperparameters

| Parameter        | Value  | Description                          |
|------------------|--------|--------------------------------------|
| `learning_rate`  | 3e-4   | Policy optimizer learning rate       |
| `n_steps`        | 2048   | Steps per rollout                    |
| `batch_size`     | 64     | Minibatch size for updates           |
| `n_epochs`       | 10     | Epochs per update                    |
| `gamma`          | 0.99   | Discount factor                      |
| `gae_lambda`     | 0.95   | GAE lambda                           |
| `clip_range`     | 0.2    | PPO clipping range                   |
| `ent_coef`       | 0.01   | Entropy coefficient                  |
| `max_grad_norm`  | 0.5    | Gradient clipping                    |

### State Space

Built by `agent/state_builder.py`. Encodes the current security state as a continuous vector:

- Threat score (0-1).
- Asset criticality (1-5, normalized).
- Source IP reputation.
- Destination port risk category.
- Protocol risk factor.
- Time-of-day risk.
- Geo-risk indicator.
- Historical alert count for source.
- Current policy count and utilization.
- Recent false positive rate.

### Action Space

Defined in `agent/action_space.py`. Discrete actions:

| Code | Action       | Description                                      |
|------|-------------|--------------------------------------------------|
| 0    | ALLOW       | Permit traffic                                   |
| 1    | DENY        | Block traffic                                    |
| 2    | RATE_LIMIT  | Throttle traffic to a safe rate                  |
| 3    | MONITOR     | Allow but increase monitoring                    |
| 4    | QUARANTINE  | Isolate the source for investigation             |
| 5    | REDIRECT    | Redirect to honeypot for intelligence gathering  |

### Reward Function

Defined in `agent/reward_function.py`. Multi-objective reward:

- **+1.0** for blocking a confirmed threat.
- **-1.0** for false positive (blocking benign traffic).
- **-0.5** for allowing a confirmed threat.
- **+0.2** for allowing benign traffic (reward correct passthrough).
- Penalty proportional to latency impact.
- Bonus for maintaining compliance score.

### Training

The `DRLTrainer` collects experiences (state, action, reward) from feedback submitted via the `/api/v1/feedback` endpoint and trains the agent in batch.

### Artefacts

- `ppo_sentinel.zip` -- stable-baselines3 model checkpoint.
- `metadata.json` -- version, state/action dimensions, save timestamp.

---

## Model Versioning and Deployment

### Version Format

- Supervised models: `YYYYMMDD.HHMMSS` timestamp-based versioning.
- DRL agent: semantic versioning `MAJOR.MINOR.PATCH`, auto-incremented on save.
- Default (untrained) models: `1.0.0-default`.

### Storage Layout

```
/models/
  xgboost/
    xgboost_model.joblib
    xgboost_scaler.joblib
    xgboost_meta.json
  lstm/
    lstm_model.pt
    lstm_meta.json
  isolation_forest/
    isolation_forest_model.joblib
    isolation_forest_meta.json
  autoencoder/
    autoencoder_model.pt
    autoencoder_meta.json
  ensemble/
    meta_learner.joblib
    ensemble_meta.json
  drl/
    ppo_sentinel.zip
    metadata.json
  staging/        # candidate models awaiting promotion
  backup/         # timestamped backups of replaced models
```

### Hot Reload

- `POST /api/v1/models/reload` reloads all detection models from disk without service restart.
- `POST /api/v1/model/load` (DRL) reloads the PPO agent.

### Health Monitoring

- `GET /health` on the AI Engine returns per-model readiness status.
- `GET /api/v1/models/status` returns detailed version, metrics, and last-updated for each model.

---

## Retraining Pipeline

**Module:** `ai-engine/learning/retraining_pipeline.py`

### Safe Retraining Flow

1. Parse incoming labelled samples into feature matrix and label vector.
2. Evaluate the current production model on the new data to establish a baseline F1 score.
3. Train a candidate model in the staging directory with 80/20 stratified train/validation split.
4. Compare the candidate's validation F1 with the production baseline.
5. If improvement >= threshold (default 2%), promote the candidate:
   - Backup the current production model with a timestamp.
   - Replace production artefacts with the candidate.
6. If improvement is below threshold, save to staging for manual review.

### Metrics Tracked

- F1 score (weighted).
- Accuracy.
- Precision (weighted).
- Recall (weighted).
- Number of training and validation samples.
- Number of classes.

### API

`POST /api/v1/models/retrain` triggers on-demand retraining.

**Request:**

```json
{
  "model": "xgboost",
  "samples": [
    { "features": { "f1": 0.1, "f2": 0.2 }, "label": 0 },
    { "features": { "f1": 0.9, "f2": 0.8 }, "label": 1 }
  ]
}
```

Minimum 50 samples required. Returns job ID, status, old/new metrics, and promotion result.

### Feedback Loop

1. Analysts submit feedback via `POST /api/v1/feedback` on detection results.
2. Feedback is stored in Redis with a 30-day TTL.
3. When sufficient feedback accumulates (>= 100 samples), the system is ready for retraining.
4. `GET /api/v1/feedback/stats` reports feedback count and retrain readiness.
