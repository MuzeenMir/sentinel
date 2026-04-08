"""SENTINEL Model Registry -- lifecycle management for ML models.

Tracks model versions, metrics, and promotion status. Stores metadata in
PostgreSQL (model_registry table) and artifacts on disk or S3.

Replaces ad-hoc file-based model management with a proper registry that
supports staging/production promotion and A/B model serving.

Usage::

    registry = ModelRegistry(db_url="postgresql://...")
    registry.register(
        name="xgboost", version="2.1.0", model_type="xgboost",
        artifact_path="/models/xgboost/v2.1.0",
        metrics={"accuracy": 0.97, "f1": 0.95, "fpr": 0.02},
    )
    registry.promote("xgboost", "2.1.0", "production")
    prod = registry.get_production_model("xgboost")
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ModelVersion:
    name: str
    version: str
    model_type: str
    framework: str = ""
    artifact_path: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = "staging"
    created_at: float = field(default_factory=time.time)
    promoted_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "model_type": self.model_type,
            "framework": self.framework,
            "artifact_path": self.artifact_path,
            "metrics": self.metrics,
            "parameters": self.parameters,
            "status": self.status,
            "created_at": self.created_at,
            "promoted_at": self.promoted_at,
        }


class ModelRegistry:
    """In-process model registry backed by PostgreSQL or local JSON."""

    def __init__(self, db_url: Optional[str] = None, local_path: Optional[str] = None):
        self._db_url = db_url
        self._local_path = local_path or os.path.join(
            os.environ.get("MODEL_PATH", "/models"), "registry.json"
        )
        self._models: Dict[str, Dict[str, ModelVersion]] = {}
        self._load()

    def _load(self) -> None:
        if self._db_url:
            self._load_from_db()
        elif os.path.exists(self._local_path):
            self._load_from_file()

    def _load_from_file(self) -> None:
        try:
            with open(self._local_path, "r") as f:
                data = json.load(f)
            for name, versions in data.items():
                self._models[name] = {}
                for ver_key, ver_data in versions.items():
                    self._models[name][ver_key] = ModelVersion(**ver_data)
            logger.info("Loaded %d models from %s", sum(len(v) for v in self._models.values()), self._local_path)
        except Exception as exc:
            logger.warning("Could not load registry from %s: %s", self._local_path, exc)

    def _load_from_db(self) -> None:
        try:
            import psycopg2
            conn = psycopg2.connect(self._db_url)
            cur = conn.cursor()
            cur.execute("SELECT name, version, model_type, framework, artifact_path, metrics, parameters, status, promoted_at FROM model_registry")
            for row in cur.fetchall():
                name, version = row[0], row[1]
                if name not in self._models:
                    self._models[name] = {}
                self._models[name][version] = ModelVersion(
                    name=name, version=version, model_type=row[2],
                    framework=row[3] or "", artifact_path=row[4] or "",
                    metrics=row[5] or {}, parameters=row[6] or {},
                    status=row[7] or "staging",
                )
            conn.close()
            logger.info("Loaded models from database")
        except Exception as exc:
            logger.warning("Could not load registry from DB: %s", exc)

    def _save(self) -> None:
        if self._db_url:
            return
        try:
            os.makedirs(os.path.dirname(self._local_path), exist_ok=True)
            data = {}
            for name, versions in self._models.items():
                data[name] = {v: mv.to_dict() for v, mv in versions.items()}
            with open(self._local_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.error("Failed to save registry: %s", exc)

    def register(
        self,
        name: str,
        version: str,
        model_type: str,
        artifact_path: str = "",
        metrics: Optional[Dict[str, Any]] = None,
        parameters: Optional[Dict[str, Any]] = None,
        framework: str = "",
    ) -> ModelVersion:
        """Register a new model version."""
        mv = ModelVersion(
            name=name, version=version, model_type=model_type,
            framework=framework, artifact_path=artifact_path,
            metrics=metrics or {}, parameters=parameters or {},
        )
        if name not in self._models:
            self._models[name] = {}
        self._models[name][version] = mv
        self._save()
        logger.info("Registered model %s v%s (status=%s)", name, version, mv.status)
        return mv

    def promote(self, name: str, version: str, target_status: str = "production") -> bool:
        """Promote a model version to the target status.

        When promoting to production, the previous production version is
        automatically archived.
        """
        if name not in self._models or version not in self._models[name]:
            return False

        if target_status == "production":
            for v, mv in self._models[name].items():
                if mv.status == "production" and v != version:
                    mv.status = "archived"
                    logger.info("Archived previous production model %s v%s", name, v)

        self._models[name][version].status = target_status
        self._models[name][version].promoted_at = time.time()
        self._save()
        logger.info("Promoted %s v%s to %s", name, version, target_status)
        return True

    def get_production_model(self, name: str) -> Optional[ModelVersion]:
        """Return the current production version of a model."""
        if name not in self._models:
            return None
        for mv in self._models[name].values():
            if mv.status == "production":
                return mv
        return None

    def get_all_versions(self, name: str) -> List[ModelVersion]:
        """Return all versions of a model."""
        return list(self._models.get(name, {}).values())

    def list_models(self) -> Dict[str, List[str]]:
        """Return a dict of model names to their version strings."""
        return {name: list(versions.keys()) for name, versions in self._models.items()}


class DriftDetector:
    """Monitors model performance for concept drift and data drift.

    Tracks prediction distributions and accuracy metrics over sliding
    windows. When drift exceeds the configured threshold, triggers a
    retraining signal.
    """

    def __init__(self, window_size: int = 1000, drift_threshold: float = 0.15):
        self._window_size = window_size
        self._drift_threshold = drift_threshold
        self._predictions: List[float] = []
        self._actuals: List[int] = []
        self._baseline_mean: Optional[float] = None
        self._baseline_std: Optional[float] = None

    def set_baseline(self, predictions: List[float]) -> None:
        """Set the baseline prediction distribution from training/validation data."""
        import statistics
        self._baseline_mean = statistics.mean(predictions)
        self._baseline_std = statistics.stdev(predictions) if len(predictions) > 1 else 0.01

    def record(self, prediction: float, actual: Optional[int] = None) -> None:
        self._predictions.append(prediction)
        if actual is not None:
            self._actuals.append(actual)
        if len(self._predictions) > self._window_size:
            self._predictions = self._predictions[-self._window_size:]
        if len(self._actuals) > self._window_size:
            self._actuals = self._actuals[-self._window_size:]

    def check_drift(self) -> Dict[str, Any]:
        """Check for prediction distribution drift."""
        if not self._predictions or self._baseline_mean is None:
            return {"drift_detected": False, "reason": "insufficient_data"}

        import statistics
        current_mean = statistics.mean(self._predictions)
        shift = abs(current_mean - self._baseline_mean)
        normalized_shift = shift / max(self._baseline_std, 0.001)
        drift_detected = normalized_shift > (self._drift_threshold / max(self._baseline_std, 0.001))

        result = {
            "drift_detected": drift_detected,
            "baseline_mean": round(self._baseline_mean, 4),
            "current_mean": round(current_mean, 4),
            "shift": round(shift, 4),
            "normalized_shift": round(normalized_shift, 4),
            "threshold": self._drift_threshold,
            "sample_size": len(self._predictions),
        }

        if drift_detected:
            logger.warning("Model drift detected: shift=%.4f threshold=%.4f", shift, self._drift_threshold)

        return result


class RetrainingPipeline:
    """Orchestrates automated model retraining when drift is detected.

    In production this would trigger a training job on SageMaker or
    a Kubernetes Job. This implementation provides the orchestration
    logic and hooks.
    """

    def __init__(self, registry: ModelRegistry, train_script: str = "training/train_all.py"):
        self._registry = registry
        self._train_script = train_script
        self._last_retrain: Optional[float] = None
        self._min_retrain_interval = 3600

    def should_retrain(self, drift_result: Dict[str, Any]) -> bool:
        if not drift_result.get("drift_detected"):
            return False
        if self._last_retrain and (time.time() - self._last_retrain) < self._min_retrain_interval:
            return False
        return True

    def trigger_retrain(self, model_name: str, reason: str = "drift_detected") -> Dict[str, Any]:
        """Trigger a retraining job. Returns job metadata."""
        self._last_retrain = time.time()
        job = {
            "job_id": f"retrain-{model_name}-{int(time.time())}",
            "model_name": model_name,
            "reason": reason,
            "status": "submitted",
            "triggered_at": time.time(),
            "train_script": self._train_script,
        }
        logger.info("Retraining triggered for %s: %s", model_name, job["job_id"])
        return job

    def on_training_complete(self, model_name: str, version: str, metrics: Dict[str, Any], artifact_path: str) -> ModelVersion:
        """Called when training completes -- register the new version as staging."""
        mv = self._registry.register(
            name=model_name, version=version, model_type=model_name,
            artifact_path=artifact_path, metrics=metrics,
        )
        prod = self._registry.get_production_model(model_name)
        if prod and self._is_improvement(prod.metrics, metrics):
            self._registry.promote(model_name, version, "production")
            logger.info("Auto-promoted %s v%s to production (improvement over v%s)", model_name, version, prod.version)
        else:
            logger.info("Model %s v%s registered as staging (no improvement)", model_name, version)
        return mv

    @staticmethod
    def _is_improvement(old_metrics: Dict[str, Any], new_metrics: Dict[str, Any]) -> bool:
        old_f1 = old_metrics.get("f1", 0)
        new_f1 = new_metrics.get("f1", 0)
        old_fpr = old_metrics.get("false_positive_rate", 1)
        new_fpr = new_metrics.get("false_positive_rate", 1)
        return new_f1 >= old_f1 and new_fpr <= old_fpr
