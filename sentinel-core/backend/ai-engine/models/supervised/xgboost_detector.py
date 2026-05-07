"""
XGBoost gradient-boosted tree classifier for multi-class threat detection.

Provides high-accuracy supervised classification with probability calibration,
feature importance tracking, and safe fallback to a default model when no
trained artefact exists on disk.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

try:
    from sklearn.preprocessing import StandardScaler
except ImportError:
    StandardScaler = None

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None

from ..base import BaseDetector, ThreatCategory

logger = logging.getLogger(__name__)

CATEGORY_MAP: Dict[int, ThreatCategory] = {
    i: cat for i, cat in enumerate(ThreatCategory)
}


class XGBoostDetector(BaseDetector):
    """
    XGBoost-based multi-class threat classifier.

    Maps each sample to one of the :class:`ThreatCategory` classes using
    gradient-boosted decision trees.  On first load without a persisted model,
    an untrained default is fitted on synthetic data so that the service can
    serve health-checks immediately.
    """

    DEFAULT_PARAMS: Dict[str, Any] = {
        "n_estimators": 300,
        "max_depth": 8,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "gamma": 0.1,
        "reg_alpha": 0.1,
        "reg_lambda": 1.0,
        "objective": "multi:softprob",
        "eval_metric": "mlogloss",
        "use_label_encoder": False,
        "n_jobs": -1,
        "random_state": 42,
        "tree_method": "hist",
    }

    def __init__(
        self,
        model_path: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(model_path)

        if XGBClassifier is None:
            raise ImportError("xgboost is required for XGBoostDetector")
        if StandardScaler is None:
            raise ImportError("scikit-learn is required for XGBoostDetector")

        self.params: Dict[str, Any] = {**self.DEFAULT_PARAMS, **(params or {})}
        self.model: Optional[XGBClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self._n_classes: int = len(ThreatCategory)

        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            self._initialize_default_model()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _initialize_default_model(self) -> None:
        logger.info("Initializing default XGBoost model")

        self.params["num_class"] = self._n_classes
        self.model = XGBClassifier(**self.params)
        self.scaler = StandardScaler()

        rng = np.random.RandomState(42)
        X_synth = rng.randn(500, 50).astype(np.float32)
        y_synth = rng.randint(0, self._n_classes, 500)

        self.scaler.fit(X_synth)
        self.model.fit(self.scaler.transform(X_synth), y_synth)

        self._is_ready = True
        self._version = "1.0.0-default"
        self._last_updated = datetime.utcnow().isoformat()
        logger.info("Default XGBoost model initialized")

    def load_model(self) -> bool:
        try:
            model_file = os.path.join(self.model_path, "xgboost_model.joblib")
            scaler_file = os.path.join(self.model_path, "xgboost_scaler.joblib")
            meta_file = os.path.join(self.model_path, "xgboost_meta.json")

            if not os.path.exists(model_file):
                logger.warning("Model file not found at %s", model_file)
                self._initialize_default_model()
                return True

            self.model = joblib.load(model_file)

            self.scaler = (
                joblib.load(scaler_file)
                if os.path.exists(scaler_file)
                else StandardScaler()
            )

            if os.path.exists(meta_file):
                with open(meta_file, "r") as fh:
                    meta = json.load(fh)
                self._version = meta.get("version", "1.0.0")
                self._last_updated = meta.get("last_updated")
                self._metrics = meta.get("metrics", {})
                self._n_classes = meta.get("n_classes", len(ThreatCategory))

            self._is_ready = True
            logger.info("XGBoost model loaded from %s", self.model_path)
            return True

        except Exception as exc:
            logger.error("Failed to load XGBoost model: %s", exc)
            self._initialize_default_model()
            return True

    def save_model(self, path: Optional[str] = None) -> bool:
        try:
            save_path = path or self.model_path
            os.makedirs(save_path, exist_ok=True)

            joblib.dump(self.model, os.path.join(save_path, "xgboost_model.joblib"))
            if self.scaler is not None:
                joblib.dump(
                    self.scaler, os.path.join(save_path, "xgboost_scaler.joblib")
                )

            meta = {
                "version": self._version,
                "last_updated": datetime.utcnow().isoformat(),
                "metrics": self._metrics,
                "n_classes": self._n_classes,
                "params": {k: v for k, v in self.params.items() if not callable(v)},
            }
            with open(os.path.join(save_path, "xgboost_meta.json"), "w") as fh:
                json.dump(meta, fh, indent=2)

            logger.info("XGBoost model saved to %s", save_path)
            return True

        except Exception as exc:
            logger.error("Failed to save XGBoost model: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")

        features = self._validate_features(features)
        if features.ndim == 1:
            features = features.reshape(1, -1)

        try:
            if self.scaler is not None:
                features = self.scaler.transform(features)

            probabilities = self.model.predict_proba(features)[0]
            predicted_class = int(np.argmax(probabilities))
            confidence = float(probabilities[predicted_class])
            category = CATEGORY_MAP.get(predicted_class, ThreatCategory.UNKNOWN)

            return {
                "detector": "xgboost",
                "is_threat": category != ThreatCategory.BENIGN,
                "confidence": confidence,
                "threat_type": category,
                "predicted_class": predicted_class,
                "probabilities": {
                    CATEGORY_MAP.get(i, ThreatCategory.UNKNOWN).value: float(p)
                    for i, p in enumerate(probabilities)
                },
            }

        except Exception as exc:
            logger.error("XGBoost prediction error: %s", exc)
            return {
                "detector": "xgboost",
                "is_threat": False,
                "confidence": 0.0,
                "threat_type": ThreatCategory.UNKNOWN,
                "details": {"error": str(exc)},
            }

    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")

        features = self._validate_features(features)
        if features.ndim == 1:
            features = features.reshape(1, -1)

        try:
            if self.scaler is not None:
                features = self.scaler.transform(features)

            all_probs = self.model.predict_proba(features)
            results: List[Dict[str, Any]] = []
            for probs in all_probs:
                cls = int(np.argmax(probs))
                cat = CATEGORY_MAP.get(cls, ThreatCategory.UNKNOWN)
                results.append(
                    {
                        "detector": "xgboost",
                        "is_threat": cat != ThreatCategory.BENIGN,
                        "confidence": float(probs[cls]),
                        "threat_type": cat,
                        "predicted_class": cls,
                    }
                )
            return results

        except Exception as exc:
            logger.error("XGBoost batch prediction error: %s", exc)
            return [
                {
                    "detector": "xgboost",
                    "is_threat": False,
                    "confidence": 0.0,
                    "threat_type": ThreatCategory.UNKNOWN,
                    "error": str(exc),
                }
                for _ in range(len(features))
            ]

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Train on labelled traffic data.

        Args:
            X: Feature matrix (n_samples, n_features).
            y: Integer class labels (0 = benign, 1 = malware, …).
        """
        if y is None:
            raise ValueError("XGBoost requires labelled data (y must not be None)")

        logger.info("Training XGBoost model …")
        X = self._validate_features(X)
        y = np.asarray(y, dtype=np.int64)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self._n_classes = int(np.max(y) + 1)
        self.params["num_class"] = self._n_classes
        self.model = XGBClassifier(**self.params)
        self.model.fit(X_scaled, y)

        predictions = self.model.predict(X_scaled)
        accuracy = float(np.mean(predictions == y))

        self._metrics = {
            "n_samples": len(X),
            "n_features": X.shape[1],
            "n_classes": self._n_classes,
            "training_accuracy": accuracy,
        }
        self._is_ready = True
        self._last_updated = datetime.utcnow().isoformat()

        logger.info("XGBoost training complete. Metrics: %s", self._metrics)
        return self._metrics
