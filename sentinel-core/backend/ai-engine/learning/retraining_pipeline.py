"""
Model retraining pipeline with safe staging, comparison, and promotion.

Trains a candidate model in a staging directory, evaluates it against the
current production artefact, and promotes only when the improvement exceeds
the configured threshold — all with automatic backups.
"""
import json
import logging
import os
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

try:
    from sklearn.metrics import (
        accuracy_score,
        f1_score,
        precision_score,
        recall_score,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from xgboost import XGBClassifier
except ImportError as exc:
    raise ImportError(
        f"scikit-learn and xgboost are required for RetrainingPipeline: {exc}"
    ) from exc

logger = logging.getLogger(__name__)


@dataclass
class RetrainJob:
    """Immutable result object returned by a retraining run."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    model_name: str = ""
    status: str = "pending"
    samples_used: int = 0
    promoted: bool = False
    old_metrics: Dict[str, float] = field(default_factory=dict)
    new_metrics: Dict[str, float] = field(default_factory=dict)
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class RetrainingPipeline:
    """
    Safely retrains models and promotes them only on measurable improvement.

    Usage::

        pipeline = RetrainingPipeline(
            models_dir="/models",
            staging_dir="/models/staging",
            backup_dir="/models/backup",
            improvement_threshold=0.02,
        )
        job = pipeline.retrain_xgboost(samples)
        print(job.status, job.promoted, job.new_metrics)
    """

    def __init__(
        self,
        models_dir: str,
        staging_dir: str,
        backup_dir: str,
        improvement_threshold: float = 0.02,
    ):
        self.models_dir = models_dir
        self.staging_dir = staging_dir
        self.backup_dir = backup_dir
        self.improvement_threshold = improvement_threshold

        os.makedirs(self.staging_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def retrain_xgboost(self, samples: List[Dict[str, Any]]) -> RetrainJob:
        """
        Retrain the XGBoost model on new labelled samples.

        Each sample: ``{"features": {"f1": 0.1, …}, "label": 0|1|…}``.
        Trains in staging, compares F1 with the production model, and
        promotes only if improvement >= *self.improvement_threshold*.
        """
        job = RetrainJob(model_name="xgboost")
        job.started_at = datetime.utcnow().isoformat()
        job.samples_used = len(samples)

        try:
            X, y = self._parse_samples(samples)

            job.old_metrics = self._evaluate_existing_model(X, y)
            new_model, new_scaler, job.new_metrics = self._train_new_model(X, y)

            old_f1 = job.old_metrics.get("f1_weighted", 0.0)
            new_f1 = job.new_metrics.get("f1_weighted", 0.0)
            improvement = new_f1 - old_f1

            if improvement >= self.improvement_threshold:
                self._promote_model(new_model, new_scaler, job.new_metrics)
                job.promoted = True
                job.status = "promoted"
                logger.info(
                    "XGBoost model promoted: F1 %.4f → %.4f (+%.4f)",
                    old_f1, new_f1, improvement,
                )
            else:
                self._save_to_staging(new_model, new_scaler, job.new_metrics)
                job.promoted = False
                job.status = "staged"
                logger.info(
                    "XGBoost model staged (not promoted): F1 %.4f → %.4f "
                    "(+%.4f < threshold %.4f)",
                    old_f1, new_f1, improvement, self.improvement_threshold,
                )

        except Exception as exc:
            logger.error("XGBoost retraining failed: %s", exc)
            job.status = "failed"
            job.error = str(exc)

        job.completed_at = datetime.utcnow().isoformat()
        return job

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_samples(
        samples: List[Dict[str, Any]],
    ) -> tuple:
        feature_keys = sorted(samples[0]["features"].keys())

        X = np.array(
            [[s["features"].get(k, 0.0) for k in feature_keys] for s in samples],
            dtype=np.float32,
        )
        y = np.array([s["label"] for s in samples], dtype=np.int64)

        return X, y

    def _evaluate_existing_model(
        self, X: np.ndarray, y: np.ndarray
    ) -> Dict[str, float]:
        """Score the current production model on the new data."""
        model_file = os.path.join(self.models_dir, "xgboost", "xgboost_model.joblib")
        scaler_file = os.path.join(self.models_dir, "xgboost", "xgboost_scaler.joblib")

        if not os.path.exists(model_file):
            logger.info("No existing production model found; baseline F1 = 0")
            return {"f1_weighted": 0.0, "accuracy": 0.0}

        try:
            model = joblib.load(model_file)
            X_eval = X.copy()
            if os.path.exists(scaler_file):
                X_eval = joblib.load(scaler_file).transform(X_eval)

            preds = model.predict(X_eval)

            return {
                "f1_weighted": float(
                    f1_score(y, preds, average="weighted", zero_division=0)
                ),
                "accuracy": float(accuracy_score(y, preds)),
                "precision_weighted": float(
                    precision_score(y, preds, average="weighted", zero_division=0)
                ),
                "recall_weighted": float(
                    recall_score(y, preds, average="weighted", zero_division=0)
                ),
            }

        except Exception as exc:
            logger.warning("Failed to evaluate existing model: %s", exc)
            return {"f1_weighted": 0.0, "accuracy": 0.0, "error": str(exc)}

    @staticmethod
    def _train_new_model(
        X: np.ndarray, y: np.ndarray
    ) -> tuple:
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_val_s = scaler.transform(X_val)

        n_classes = int(np.max(y) + 1)

        model = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            gamma=0.1,
            reg_alpha=0.1,
            reg_lambda=1.0,
            objective="multi:softprob",
            num_class=n_classes,
            eval_metric="mlogloss",
            use_label_encoder=False,
            n_jobs=-1,
            random_state=42,
            tree_method="hist",
            early_stopping_rounds=15,
        )

        model.fit(X_train_s, y_train, eval_set=[(X_val_s, y_val)], verbose=False)

        val_preds = model.predict(X_val_s)

        metrics = {
            "f1_weighted": float(
                f1_score(y_val, val_preds, average="weighted", zero_division=0)
            ),
            "accuracy": float(accuracy_score(y_val, val_preds)),
            "precision_weighted": float(
                precision_score(y_val, val_preds, average="weighted", zero_division=0)
            ),
            "recall_weighted": float(
                recall_score(y_val, val_preds, average="weighted", zero_division=0)
            ),
            "n_train": len(X_train),
            "n_val": len(X_val),
            "n_classes": n_classes,
        }

        return model, scaler, metrics

    def _promote_model(
        self, model: Any, scaler: Any, metrics: Dict[str, float]
    ) -> None:
        """Backup current production model, then overwrite with the new one."""
        prod_dir = os.path.join(self.models_dir, "xgboost")

        if os.path.exists(prod_dir):
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
            backup_dest = os.path.join(self.backup_dir, f"xgboost_{ts}")
            shutil.copytree(prod_dir, backup_dest)
            logger.info("Production model backed up to %s", backup_dest)

        os.makedirs(prod_dir, exist_ok=True)
        joblib.dump(model, os.path.join(prod_dir, "xgboost_model.joblib"))
        joblib.dump(scaler, os.path.join(prod_dir, "xgboost_scaler.joblib"))

        meta = {
            "version": datetime.utcnow().strftime("%Y%m%d.%H%M%S"),
            "last_updated": datetime.utcnow().isoformat(),
            "metrics": metrics,
        }
        with open(os.path.join(prod_dir, "xgboost_meta.json"), "w") as fh:
            json.dump(meta, fh, indent=2)

    def _save_to_staging(
        self, model: Any, scaler: Any, metrics: Dict[str, float]
    ) -> None:
        staging = os.path.join(self.staging_dir, "xgboost")
        os.makedirs(staging, exist_ok=True)

        joblib.dump(model, os.path.join(staging, "xgboost_model.joblib"))
        joblib.dump(scaler, os.path.join(staging, "xgboost_scaler.joblib"))

        meta = {
            "version": f"staged-{datetime.utcnow().strftime('%Y%m%d.%H%M%S')}",
            "last_updated": datetime.utcnow().isoformat(),
            "metrics": metrics,
        }
        with open(os.path.join(staging, "xgboost_meta.json"), "w") as fh:
            json.dump(meta, fh, indent=2)
