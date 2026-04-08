"""Model-agnostic SHAP-based explanation generator for SENTINEL AI decisions."""
import logging
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

try:
    import shap

    _SHAP_AVAILABLE = True
except ImportError:
    _SHAP_AVAILABLE = False
    logger.warning("SHAP library not available — falling back to approximate explanations")


class SHAPExplainer:

    def __init__(self, background_samples: int = 100) -> None:
        self._background_samples = background_samples
        self._explainer: Optional[Any] = None
        self._ready = _SHAP_AVAILABLE

    def is_ready(self) -> bool:
        return self._ready

    def explain_detection(
        self, features: Dict[str, Any], prediction: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            if self._ready:
                return self._shap_explain(features, prediction)
            return self._approximate_explain(features, prediction)
        except Exception:
            logger.exception("SHAP explanation failed, falling back to approximate")
            return self._approximate_explain(features, prediction)

    # ------------------------------------------------------------------
    # SHAP-based path
    # ------------------------------------------------------------------

    def _shap_explain(
        self, features: Dict[str, Any], prediction: Dict[str, Any]
    ) -> Dict[str, Any]:
        feature_names = sorted(features.keys())
        feature_values = np.array(
            [self._to_numeric(features[f]) for f in feature_names]
        ).reshape(1, -1)

        background = np.zeros((self._background_samples, len(feature_names)))
        explainer = shap.KernelExplainer(
            lambda x: np.full(x.shape[0], prediction.get("confidence", 0.5)),
            background,
        )
        shap_values = explainer.shap_values(feature_values)[0]

        importance = self._build_importance(feature_names, feature_values[0], shap_values)
        importance.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

        return {
            "method": "shap_kernel",
            "feature_importance": importance,
            "top_factors": importance[:5],
            "base_value": float(explainer.expected_value),
            "prediction_value": prediction.get("confidence", 0.0),
        }

    # ------------------------------------------------------------------
    # Approximate fallback (no SHAP library)
    # ------------------------------------------------------------------

    def _approximate_explain(
        self, features: Dict[str, Any], prediction: Dict[str, Any]
    ) -> Dict[str, Any]:
        confidence = prediction.get("confidence", 0.5)
        feature_names = sorted(features.keys())
        importance: List[Dict[str, Any]] = []

        weights = self._derive_weights(feature_names)

        for name in feature_names:
            raw = features[name]
            numeric = self._to_numeric(raw)
            weight = weights.get(name, 1.0 / max(len(feature_names), 1))
            approx_shap = numeric * weight * (confidence - 0.5)

            importance.append({
                "feature": name,
                "value": raw,
                "shap_value": round(float(approx_shap), 6),
                "direction": "threat" if approx_shap > 0 else "benign",
                "magnitude": round(abs(float(approx_shap)), 6),
            })

        importance.sort(key=lambda x: x["magnitude"], reverse=True)

        return {
            "method": "approximate_weighted",
            "feature_importance": importance,
            "top_factors": importance[:5],
            "base_value": 0.5,
            "prediction_value": confidence,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_importance(
        names: List[str],
        values: np.ndarray,
        shap_vals: np.ndarray,
    ) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for i, name in enumerate(names):
            sv = float(shap_vals[i])
            result.append({
                "feature": name,
                "value": float(values[i]),
                "shap_value": round(sv, 6),
                "direction": "threat" if sv > 0 else "benign",
                "magnitude": round(abs(sv), 6),
            })
        return result

    @staticmethod
    def _to_numeric(value: Any) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return float(hash(value) % 100) / 100.0
        return 0.0

    @staticmethod
    def _derive_weights(feature_names: List[str]) -> Dict[str, float]:
        known_weights: Dict[str, float] = {
            "threat_score": 0.25,
            "anomaly_score": 0.20,
            "confidence": 0.15,
            "severity": 0.15,
            "src_reputation": 0.10,
            "dst_reputation": 0.10,
            "packet_rate": 0.08,
            "byte_rate": 0.08,
            "connection_count": 0.07,
            "geo_risk": 0.06,
            "time_risk": 0.05,
            "protocol_risk": 0.05,
            "port_risk": 0.05,
            "payload_entropy": 0.07,
            "asset_criticality": 0.10,
        }
        weights: Dict[str, float] = {}
        uniform = 1.0 / max(len(feature_names), 1)
        for name in feature_names:
            weights[name] = known_weights.get(name, uniform)
        return weights
