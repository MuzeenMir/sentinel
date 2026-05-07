"""
End-to-end prediction service: raw traffic → features → ensemble → result.

Orchestrates feature extraction, ensemble inference, severity mapping,
result formatting, and optional Redis caching of predictions.
"""

import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

SEVERITY_THRESHOLDS = [
    (0.9, "critical"),
    (0.7, "high"),
    (0.4, "medium"),
    (0.0, "low"),
]


class PredictionService:
    """
    Facade that owns the full prediction pipeline.

    Construction mirrors the initialisation in ``app.py``::

        svc = PredictionService(
            feature_extractors={"statistical": ..., "behavioral": ..., ...},
            ensemble=stacking_ensemble,
            redis_client=redis_client,   # optional
        )
        result = svc.predict(traffic_data, context)
    """

    def __init__(
        self,
        feature_extractors: Dict[str, Any],
        ensemble: Any,
        redis_client: Optional[Any] = None,
    ):
        self.feature_extractors = feature_extractors
        self.ensemble = ensemble
        self.redis_client = redis_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(
        self,
        traffic_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run the full prediction pipeline on a single traffic sample.

        Returns a dict with at least: detection_id, is_threat, confidence,
        severity, threat_type, model_verdicts, timestamp.
        """
        start = time.monotonic()
        detection_id = str(uuid.uuid4())

        try:
            merged = {**traffic_data, **(context or {})}

            all_features = self._extract_features(merged)
            feature_vector = self._features_to_vector(all_features)

            ensemble_result = self.ensemble.predict(feature_vector)

            confidence = ensemble_result.get("confidence", 0.0)
            is_threat = ensemble_result.get("is_threat", False)
            severity = self._confidence_to_severity(confidence) if is_threat else "info"
            latency_ms = (time.monotonic() - start) * 1000

            result = {
                "detection_id": detection_id,
                "is_threat": is_threat,
                "confidence": confidence,
                "severity": severity,
                "threat_type": ensemble_result.get("threat_type", "unknown"),
                "model_verdicts": ensemble_result.get("model_verdicts", {}),
                "timestamp": datetime.utcnow().isoformat(),
                "latency_ms": round(latency_ms, 2),
            }

            self._cache_result(result)
            return result

        except Exception as exc:
            logger.error("Prediction failed for %s: %s", detection_id, exc)
            return {
                "detection_id": detection_id,
                "is_threat": False,
                "confidence": 0.0,
                "severity": "info",
                "threat_type": "unknown",
                "model_verdicts": {},
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(exc),
            }

    def predict_batch(
        self, traffic_batch: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Run prediction on every sample in *traffic_batch*."""
        return [self.predict(sample, sample.get("context")) for sample in traffic_batch]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _extract_features(self, data: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
        groups: Dict[str, Dict[str, float]] = {}
        for name, extractor in self.feature_extractors.items():
            try:
                groups[name] = extractor.extract(data)
            except Exception as exc:
                logger.error("Feature extractor '%s' failed: %s", name, exc)
                groups[name] = {}
        return groups

    @staticmethod
    def _features_to_vector(feature_groups: Dict[str, Dict[str, float]]) -> np.ndarray:
        """Flatten all feature groups into a single ordered float32 vector."""
        values: List[float] = []
        for group_name in sorted(feature_groups):
            group = feature_groups[group_name]
            for key in sorted(group):
                val = group[key]
                values.append(float(val) if val is not None else 0.0)

        if not values:
            values = [0.0] * 50

        return np.array(values, dtype=np.float32)

    @staticmethod
    def _confidence_to_severity(confidence: float) -> str:
        for threshold, label in SEVERITY_THRESHOLDS:
            if confidence >= threshold:
                return label
        return "low"

    def _cache_result(self, result: Dict[str, Any]) -> None:
        if self.redis_client is None:
            return
        try:
            key = f"ai_engine:prediction:{result['detection_id']}"
            serialisable = {
                k: (v if isinstance(v, (str, int, float, bool)) else json.dumps(v))
                for k, v in result.items()
            }
            self.redis_client.hset(key, mapping=serialisable)
            self.redis_client.expire(key, 3600)
        except Exception as exc:
            logger.warning("Failed to cache prediction result: %s", exc)
