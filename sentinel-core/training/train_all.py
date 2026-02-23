#!/usr/bin/env python3
"""
SENTINEL Training Pipeline -- train_all.py

Orchestrates the full training workflow for all detection models:
  1. XGBoost classifier
  2. Isolation Forest anomaly detector
  3. Autoencoder anomaly detector
  4. LSTM sequence detector
  5. Stacking ensemble (meta-learner)
  6. DRL PPO agent

Supports:
  - Per-model checkpointing (resume after Spot interruption)
  - GPU / CPU device selection
  - Row-limiting for CI / quick tests
  - Training on CIC-IDS2018, CIC-IDS2017, UNSW-NB15

Usage:
  python training/train_all.py \\
      --data-path training/datasets/data \\
      --dataset cicids2018 \\
      --device cuda \\
      --output-path backend/ai-engine/trained_models
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

# Ensure the project root is importable (training package + backend services)
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend" / "ai-engine"))
sys.path.insert(0, str(PROJECT_ROOT / "backend" / "drl-engine"))

from training.data_loader import (
    LABEL_TO_IDX,
    N_FEATURES,
    THREAT_CATEGORIES,
    load_dataset,
    load_multiple_datasets,
)
from training.spot_handler import SpotInterruptionHandler, install_signal_handlers

logger = logging.getLogger("sentinel.training")

ALL_MODELS = [
    "xgboost",
    "isolation_forest",
    "autoencoder",
    "lstm",
    "ensemble",
    "drl",
]

# ── Checkpoint helpers ───────────────────────────────────────────────────────

def _ckpt_path(output_dir: str) -> str:
    return os.path.join(output_dir, ".training_checkpoint.json")


def _load_checkpoint(output_dir: str) -> Dict[str, Any]:
    path = _ckpt_path(output_dir)
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def _save_checkpoint(output_dir: str, state: Dict[str, Any]) -> None:
    os.makedirs(output_dir, exist_ok=True)
    path = _ckpt_path(output_dir)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


# ── Model trainers ───────────────────────────────────────────────────────────

def train_xgboost(
    data: Dict, output_dir: str, device: str
) -> Dict[str, float]:
    """Train XGBoost classifier."""
    from models.supervised.xgboost_detector import XGBoostDetector
    from models.base import ThreatCategory

    logger.info("Training XGBoost classifier...")
    model_dir = os.path.join(output_dir, "xgboost")

    n_classes = data.get("n_classes") or len(ThreatCategory.all_categories())
    params = {
        "objective": "multi:softprob",
        "num_class": n_classes,
        "max_depth": 8,
        "learning_rate": 0.1,
        "n_estimators": 200,
        "min_child_weight": 1,
        "gamma": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "reg_alpha": 0.1,
        "reg_lambda": 1.0,
        "tree_method": "hist",
        "n_jobs": -1,
        "random_state": 42,
    }
    if device == "cuda":
        params["tree_method"] = "hist"
        params["device"] = "cuda"

    detector = XGBoostDetector(params=params)
    metrics = detector.train(
        data["X_train"],
        data["y_train"],
        feature_names=data["feature_names"],
        eval_set=(data["X_test"], data["y_test"]),
    )
    detector.save_model(model_dir)

    # Evaluate on test set
    from sklearn.metrics import classification_report
    y_pred = detector.model.predict(data["X_test"])
    report = classification_report(
        data["y_test"], y_pred, output_dict=True, zero_division=0,
    )
    metrics["test_accuracy"] = report["accuracy"]
    metrics["test_f1_weighted"] = report["weighted avg"]["f1-score"]

    logger.info("XGBoost test accuracy: %.4f  F1: %.4f",
                metrics["test_accuracy"], metrics["test_f1_weighted"])
    return metrics


def train_isolation_forest(
    data: Dict, output_dir: str, device: str
) -> Dict[str, float]:
    """Train Isolation Forest on benign traffic."""
    from models.unsupervised.isolation_forest import IsolationForestDetector

    logger.info("Training Isolation Forest...")
    model_dir = os.path.join(output_dir, "isolation_forest")

    # Use only benign samples for unsupervised training
    benign_idx = LABEL_TO_IDX["benign"]
    benign_mask = data["y_train"] == benign_idx
    X_benign = data["X_train"][benign_mask]

    if len(X_benign) < 100:
        logger.warning("Very few benign samples (%d), using all data", len(X_benign))
        X_benign = data["X_train"]

    detector = IsolationForestDetector()
    metrics = detector.train(X_benign)
    detector.save_model(model_dir)

    # Evaluate: anomaly detection performance on test set
    test_preds = detector.predict_batch(data["X_test"])
    pred_threats = np.array([p["is_threat"] for p in test_preds])
    true_threats = data["y_test"] != benign_idx

    from sklearn.metrics import precision_score, recall_score, f1_score
    metrics["test_precision"] = float(precision_score(true_threats, pred_threats, zero_division=0))
    metrics["test_recall"] = float(recall_score(true_threats, pred_threats, zero_division=0))
    metrics["test_f1"] = float(f1_score(true_threats, pred_threats, zero_division=0))

    logger.info("Isolation Forest test P/R/F1: %.4f / %.4f / %.4f",
                metrics["test_precision"], metrics["test_recall"], metrics["test_f1"])
    return metrics


def train_autoencoder(
    data: Dict, output_dir: str, device: str
) -> Dict[str, float]:
    """Train Autoencoder on benign traffic."""
    import torch
    from models.unsupervised.autoencoder import AutoencoderDetector

    logger.info("Training Autoencoder (device=%s)...", device)
    model_dir = os.path.join(output_dir, "autoencoder")

    benign_idx = LABEL_TO_IDX["benign"]
    benign_mask = data["y_train"] == benign_idx
    X_benign = data["X_train"][benign_mask]

    if len(X_benign) < 100:
        logger.warning("Very few benign samples (%d), using all data", len(X_benign))
        X_benign = data["X_train"]

    config = {
        "input_dim": N_FEATURES,
        "latent_dim": 16,
        "hidden_dims": [128, 64, 32],
        "learning_rate": 0.001,
        "batch_size": 256,
        "epochs": 100,
        "early_stopping_patience": 10,
    }

    detector = AutoencoderDetector(config=config)
    if device == "cuda" and torch.cuda.is_available():
        detector.device = torch.device("cuda")
        if detector.model is not None:
            detector.model = detector.model.to(detector.device)

    metrics = detector.train(X_benign)
    detector.save_model(model_dir)

    # Evaluate
    test_preds = detector.predict_batch(data["X_test"])
    pred_threats = np.array([p["is_threat"] for p in test_preds])
    true_threats = data["y_test"] != benign_idx

    from sklearn.metrics import precision_score, recall_score, f1_score
    metrics["test_precision"] = float(precision_score(true_threats, pred_threats, zero_division=0))
    metrics["test_recall"] = float(recall_score(true_threats, pred_threats, zero_division=0))
    metrics["test_f1"] = float(f1_score(true_threats, pred_threats, zero_division=0))

    logger.info("Autoencoder test P/R/F1: %.4f / %.4f / %.4f",
                metrics["test_precision"], metrics["test_recall"], metrics["test_f1"])
    return metrics


def train_lstm(
    data: Dict, output_dir: str, device: str
) -> Dict[str, float]:
    """Train LSTM sequence detector."""
    import torch
    from models.supervised.lstm_sequence import LSTMSequenceDetector

    logger.info("Training LSTM (device=%s)...", device)
    model_dir = os.path.join(output_dir, "lstm")

    seq_len = 20
    n_features = N_FEATURES

    # Create sequences from flat features by sliding window over samples.
    # Each sample is treated as one timestep; we group consecutive samples
    # into windows of seq_len.
    X_train = data["X_train"]
    y_train = data["y_train"]

    n_sequences = len(X_train) // seq_len
    if n_sequences < 10:
        logger.warning("Not enough data for LSTM sequences, replicating rows")
        n_sequences = max(10, n_sequences)
        needed = n_sequences * seq_len
        repeats = (needed // len(X_train)) + 1
        X_train = np.tile(X_train, (repeats, 1))[:needed]
        y_train = np.tile(y_train, repeats)[:needed]
        n_sequences = len(X_train) // seq_len

    X_seq = X_train[: n_sequences * seq_len].reshape(n_sequences, seq_len, n_features)
    # Binary label per sequence: 1 if any sample in the window is an attack
    y_seq_full = y_train[: n_sequences * seq_len].reshape(n_sequences, seq_len)
    y_seq = (y_seq_full != LABEL_TO_IDX["benign"]).any(axis=1).astype(np.int64)

    # Validation split
    split = max(1, int(0.8 * n_sequences))
    X_train_seq, X_val_seq = X_seq[:split], X_seq[split:]
    y_train_seq, y_val_seq = y_seq[:split], y_seq[split:]

    config = {
        "input_size": n_features,
        "hidden_size": 128,
        "num_layers": 2,
        "num_classes": 2,
        "dropout": 0.3,
        "sequence_length": seq_len,
        "learning_rate": 0.001,
        "batch_size": 64,
        "epochs": 50,
    }

    detector = LSTMSequenceDetector(config=config)
    if device == "cuda" and torch.cuda.is_available():
        detector.device = torch.device("cuda")
        if detector.model is not None:
            detector.model = detector.model.to(detector.device)

    metrics = detector.train(X_train_seq, y_train_seq, X_val_seq, y_val_seq)
    detector.save_model(model_dir)

    # Evaluate on validation sequences
    from sklearn.metrics import accuracy_score, f1_score
    val_preds = []
    detector.model.eval()
    with torch.no_grad():
        for i in range(len(X_val_seq)):
            result = detector.predict(X_val_seq[i])
            val_preds.append(1 if result["is_threat"] else 0)

    metrics["test_accuracy"] = float(accuracy_score(y_val_seq, val_preds))
    metrics["test_f1"] = float(f1_score(y_val_seq, val_preds, zero_division=0))

    logger.info("LSTM test accuracy: %.4f  F1: %.4f",
                metrics["test_accuracy"], metrics["test_f1"])
    return metrics


def train_ensemble(
    data: Dict, output_dir: str, device: str
) -> Dict[str, float]:
    """Train stacking ensemble meta-learner over base detector outputs."""
    from models.base import ThreatCategory
    from models.supervised.xgboost_detector import XGBoostDetector
    from models.unsupervised.isolation_forest import IsolationForestDetector
    from models.unsupervised.autoencoder import AutoencoderDetector
    from models.supervised.lstm_sequence import LSTMSequenceDetector
    from models.ensemble.stacking_classifier import StackingEnsemble

    logger.info("Training stacking ensemble meta-learner...")
    ensemble_dir = os.path.join(output_dir, "ensemble")

    # Load base detectors from their trained artifacts
    detectors = {}
    xgb_dir = os.path.join(output_dir, "xgboost")
    if os.path.exists(xgb_dir):
        detectors["xgboost"] = XGBoostDetector(model_path=xgb_dir)
    ifo_dir = os.path.join(output_dir, "isolation_forest")
    if os.path.exists(ifo_dir):
        detectors["isolation_forest"] = IsolationForestDetector(model_path=ifo_dir)
    ae_dir = os.path.join(output_dir, "autoencoder")
    if os.path.exists(ae_dir):
        detectors["autoencoder"] = AutoencoderDetector(model_path=ae_dir)
    lstm_dir = os.path.join(output_dir, "lstm")
    if os.path.exists(lstm_dir):
        detectors["lstm"] = LSTMSequenceDetector(model_path=lstm_dir)

    if len(detectors) < 2:
        logger.warning("Need at least 2 base detectors; skipping ensemble training")
        return {"skipped": True, "reason": "insufficient_detectors"}

    ensemble = StackingEnsemble(base_detectors=detectors, use_meta_learner=True)

    # Build meta-features: each row = [det1_threat_score, det2_threat_score, ...]
    logger.info("Generating meta-features from %d base detectors on training data...",
                len(detectors))
    X_test = data["X_test"]
    y_test = data["y_test"]

    benign_idx = LABEL_TO_IDX["benign"]
    y_binary = (y_test != benign_idx).astype(np.int64)

    meta_rows = []
    det_order = list(ensemble.weights.keys())
    batch_size = 500
    for start in range(0, len(X_test), batch_size):
        end = min(start + batch_size, len(X_test))
        for i in range(start, end):
            row = []
            for name in det_order:
                if name not in detectors:
                    row.append(0.5)
                    continue
                try:
                    result = detectors[name].predict(X_test[i])
                    conf = result.get("confidence", 0.5)
                    score = conf if result.get("is_threat") else 1.0 - conf
                    row.append(score)
                except Exception:
                    row.append(0.5)
            meta_rows.append(row)
        if (end - start) > 0:
            logger.info("  Meta-features: %d / %d", end, len(X_test))

    X_meta = np.array(meta_rows, dtype=np.float64)
    ensemble.train_meta_learner(X_meta, y_binary)
    ensemble.save(ensemble_dir)

    metrics = ensemble._metrics.get("meta_learner", {})
    logger.info("Ensemble meta-learner metrics: %s", metrics)
    return metrics


def train_drl(
    data: Dict, output_dir: str, device: str
) -> Dict[str, float]:
    """Train DRL PPO agent for firewall policy decisions."""
    logger.info("Training DRL PPO agent (device=%s)...", device)
    model_dir = os.path.join(output_dir, "drl")
    os.makedirs(model_dir, exist_ok=True)

    try:
        import torch
        import gymnasium as gym
        from stable_baselines3 import PPO
        from stable_baselines3.common.vec_env import DummyVecEnv
    except ImportError as exc:
        logger.warning("DRL dependencies not available: %s", exc)
        return {"skipped": True, "reason": str(exc)}

    # Build a simplified firewall-policy environment that uses the dataset
    # statistics as context for state construction.
    state_dim = 12
    n_actions = 8

    class FirewallEnv(gym.Env):
        """Lightweight Gym environment for PPO training on threat contexts."""
        metadata = {"render_modes": []}

        def __init__(self, X: np.ndarray, y: np.ndarray):
            super().__init__()
            self.X = X
            self.y = y
            self.observation_space = gym.spaces.Box(
                low=-10.0, high=10.0, shape=(state_dim,), dtype=np.float32,
            )
            self.action_space = gym.spaces.Discrete(n_actions)
            self._idx = 0
            self._step_count = 0
            self._max_steps = 200

        def _build_state(self, idx: int) -> np.ndarray:
            row = self.X[idx % len(self.X)]
            is_threat = int(self.y[idx % len(self.y)] != LABEL_TO_IDX["benign"])
            threat_score = float(np.clip(np.mean(np.abs(row[:5])), 0, 1))
            return np.array([
                threat_score,
                float(np.clip(row[0], -1, 1)),   # src_reputation proxy
                0.5,                               # asset_criticality
                float(np.clip(np.std(row[:10]), 0, 5) / 5),  # traffic_volume proxy
                float(np.clip(row[2], 0, 1)),      # protocol_risk proxy
                0.3,                               # time_risk
                float(np.clip(row[3], 0, 1)),      # historical_alerts proxy
                float(is_threat),                  # is_internal
                float(np.clip(row[4], 0, 1)),      # port_sensitivity proxy
                float(np.clip(row[5], 0, 1)),      # connection_freq proxy
                float(np.clip(np.mean(row[6:10]), 0, 1)),  # payload_anomaly proxy
                0.2,                               # geo_risk
            ], dtype=np.float32)

        def reset(self, *, seed=None, options=None):
            super().reset(seed=seed)
            self._idx = np.random.randint(0, len(self.X))
            self._step_count = 0
            return self._build_state(self._idx), {}

        def step(self, action: int):
            is_threat = int(self.y[self._idx % len(self.y)] != LABEL_TO_IDX["benign"])

            # Reward: correct blocking of threats, correct allowing of benign
            if is_threat:
                # DENY(1), QUARANTINE(5,6) = good; ALLOW(0) = bad
                if action in (1, 2, 3, 4, 5, 6):
                    reward = 1.0
                elif action == 0:
                    reward = -2.0
                else:
                    reward = 0.3
            else:
                # ALLOW(0), MONITOR(7) = good; DENY(1) = bad
                if action in (0, 7):
                    reward = 1.0
                elif action == 1:
                    reward = -1.5
                else:
                    reward = -0.3

            self._step_count += 1
            self._idx += 1
            done = self._step_count >= self._max_steps
            truncated = False

            next_state = self._build_state(self._idx)
            return next_state, reward, done, truncated, {}

    env = DummyVecEnv([lambda: FirewallEnv(data["X_train"], data["y_train"])])

    ppo_kwargs = dict(
        policy="MlpPolicy",
        env=env,
        learning_rate=3e-4,
        n_steps=2048,
        batch_size=64,
        n_epochs=10,
        gamma=0.99,
        gae_lambda=0.95,
        clip_range=0.2,
        ent_coef=0.01,
        vf_coef=0.5,
        verbose=1,
        seed=42,
    )
    if device == "cuda":
        import torch as _torch
        if _torch.cuda.is_available():
            ppo_kwargs["device"] = "cuda"
        else:
            ppo_kwargs["device"] = "cpu"
    else:
        ppo_kwargs["device"] = "cpu"

    model = PPO(**ppo_kwargs)

    total_timesteps = 50_000
    logger.info("PPO training for %d timesteps...", total_timesteps)
    model.learn(total_timesteps=total_timesteps, progress_bar=False)

    model_path = os.path.join(model_dir, "ppo_firewall")
    model.save(model_path)

    # Evaluate
    eval_env = FirewallEnv(data["X_test"], data["y_test"])
    total_reward = 0.0
    correct_actions = 0
    n_eval = min(1000, len(data["X_test"]))
    obs, _ = eval_env.reset()
    for _ in range(n_eval):
        action, _ = model.predict(obs, deterministic=True)
        obs, reward, done, truncated, _ = eval_env.step(int(action))
        total_reward += reward
        if reward > 0:
            correct_actions += 1
        if done:
            obs, _ = eval_env.reset()

    metrics = {
        "total_timesteps": total_timesteps,
        "eval_mean_reward": float(total_reward / n_eval),
        "eval_correct_rate": float(correct_actions / n_eval),
    }

    # Save metadata
    with open(os.path.join(model_dir, "drl_meta.json"), "w") as f:
        json.dump({
            "algorithm": "PPO",
            "state_dim": state_dim,
            "n_actions": n_actions,
            "total_timesteps": total_timesteps,
            "metrics": metrics,
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }, f, indent=2)

    logger.info("DRL eval: mean_reward=%.4f  correct_rate=%.4f",
                metrics["eval_mean_reward"], metrics["eval_correct_rate"])
    return metrics


# ── Training dispatcher ──────────────────────────────────────────────────────

TRAINERS = {
    "xgboost":          train_xgboost,
    "isolation_forest":  train_isolation_forest,
    "autoencoder":       train_autoencoder,
    "lstm":              train_lstm,
    "ensemble":          train_ensemble,
    "drl":               train_drl,
}


def run_training(args: argparse.Namespace) -> None:
    output_dir = os.path.abspath(args.output_path)
    os.makedirs(output_dir, exist_ok=True)

    # Load checkpoint
    ckpt = _load_checkpoint(output_dir)
    completed_models = set(ckpt.get("completed", []))

    # Emergency save function for Spot handler
    def emergency_save():
        _save_checkpoint(output_dir, ckpt)
        logger.warning("Emergency checkpoint saved.")

    spot_handler = SpotInterruptionHandler(
        save_fn=emergency_save,
        checkpoint_dir=output_dir,
    )
    spot_handler.start()
    install_signal_handlers(emergency_save)

    # Load data
    logger.info("Loading dataset: %s (max_rows=%s)", args.dataset, args.max_rows)
    data_dir = os.path.abspath(args.data_path)

    datasets_to_load = [d.strip() for d in args.dataset.split(",")]
    if len(datasets_to_load) == 1:
        data = load_dataset(
            data_dir, datasets_to_load[0],
            max_rows=args.max_rows,
        )
    else:
        data = load_multiple_datasets(
            data_dir, datasets_to_load,
            max_rows_per_dataset=args.max_rows,
        )

    logger.info("Data loaded: train=%d  test=%d  features=%d",
                len(data["X_train"]), len(data["X_test"]), data["X_train"].shape[1])

    # Determine which models to train
    models = args.models if args.models else ALL_MODELS

    all_metrics: Dict[str, Any] = ckpt.get("metrics", {})
    start_time = time.time()

    for model_name in models:
        if spot_handler.interrupted:
            logger.warning("Spot interruption detected -- stopping training loop")
            break

        if model_name in completed_models and not args.force:
            logger.info("Skipping %s (already completed, use --force to retrain)", model_name)
            continue

        trainer_fn = TRAINERS.get(model_name)
        if trainer_fn is None:
            logger.warning("Unknown model: %s", model_name)
            continue

        logger.info("=" * 60)
        logger.info("Training: %s", model_name.upper())
        logger.info("=" * 60)

        try:
            t0 = time.time()
            metrics = trainer_fn(data, output_dir, args.device)
            elapsed = time.time() - t0
            metrics["training_time_seconds"] = elapsed

            all_metrics[model_name] = metrics
            completed_models.add(model_name)
            ckpt["completed"] = list(completed_models)
            ckpt["metrics"] = all_metrics
            _save_checkpoint(output_dir, ckpt)

            logger.info("Completed %s in %.1f seconds", model_name, elapsed)

        except Exception:
            logger.exception("FAILED to train %s", model_name)
            all_metrics[model_name] = {"error": True}

    spot_handler.stop()

    total_time = time.time() - start_time

    # Write summary report
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": args.dataset,
        "device": args.device,
        "max_rows": args.max_rows,
        "total_time_seconds": total_time,
        "models_trained": list(completed_models),
        "metrics": all_metrics,
    }
    report_path = os.path.join(output_dir, "training_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info("")
    logger.info("=" * 60)
    logger.info("TRAINING COMPLETE")
    logger.info("=" * 60)
    logger.info("Total time:     %.1f seconds (%.1f minutes)", total_time, total_time / 60)
    logger.info("Models trained: %s", list(completed_models))
    logger.info("Output dir:     %s", output_dir)
    logger.info("Report:         %s", report_path)
    logger.info("")
    for name, m in all_metrics.items():
        if isinstance(m, dict) and "error" not in m:
            logger.info("  %s: %s", name, {k: f"{v:.4f}" if isinstance(v, float) else v
                                            for k, v in m.items()})


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SENTINEL Training Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--data-path", required=True,
        help="Path to directory containing dataset subdirectories",
    )
    parser.add_argument(
        "--dataset", default="cicids2018",
        help="Dataset name (cicids2018, cicids2017, unsw_nb15) or comma-separated list",
    )
    parser.add_argument(
        "--models", nargs="*", choices=ALL_MODELS, default=None,
        help="Specific models to train (default: all)",
    )
    parser.add_argument(
        "--max-rows", type=int, default=None,
        help="Limit rows per dataset (for CI / quick runs)",
    )
    parser.add_argument(
        "--device", choices=["cpu", "cuda"], default="cpu",
        help="Device for PyTorch models (default: cpu)",
    )
    parser.add_argument(
        "--output-path",
        default=str(PROJECT_ROOT / "backend" / "ai-engine" / "trained_models"),
        help="Directory to save trained models",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Retrain models even if checkpoint shows them as completed",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    args = parse_args()
    logger.info("SENTINEL Training Pipeline")
    logger.info("  Dataset:    %s", args.dataset)
    logger.info("  Data path:  %s", args.data_path)
    logger.info("  Device:     %s", args.device)
    logger.info("  Max rows:   %s", args.max_rows or "unlimited")
    logger.info("  Models:     %s", args.models or "all")
    logger.info("  Output:     %s", args.output_path)
    logger.info("")

    run_training(args)


if __name__ == "__main__":
    main()
