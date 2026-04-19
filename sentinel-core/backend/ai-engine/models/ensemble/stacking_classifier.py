"""
Stacking ensemble classifier combining multiple threat detectors.

Uses a meta-learner (logistic regression by default) trained on the output
of base detectors to produce a single unified verdict.  Falls back to
weighted-average voting when no meta-learner has been trained.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

try:
    from sklearn.linear_model import LogisticRegression
except ImportError:
    LogisticRegression = None  # type: ignore[assignment,misc]

from ..base import ThreatCategory

logger = logging.getLogger(__name__)


class StackingEnsemble:
    """
    Combines predictions from heterogeneous base detectors via stacking.

    Construction:
        >>> ensemble = StackingEnsemble(base_detectors=detectors, threshold=0.85)
        >>> ensemble.load("/models/ensemble")      # optional trained meta-learner
        >>> result = ensemble.predict(features)
    """

    def __init__(
        self,
        base_detectors: Dict[str, Any],
        threshold: float = 0.85,
        weights: Optional[Any] = None,
        use_meta_learner: bool = True,
    ):
        if LogisticRegression is None:
            raise ImportError("scikit-learn is required for StackingEnsemble")

        self.base_detectors = base_detectors
        self.threshold = threshold
        self._use_meta_learner = use_meta_learner
        self.meta_learner: Optional[LogisticRegression] = None
        self.detector_weights: Dict[str, float] = {}

        if base_detectors:
            names = list(base_detectors.keys())
            if weights is not None:
                # weights may be a list (positional) or dict
                if isinstance(weights, dict):
                    raw = {k: float(v) for k, v in weights.items()}
                else:
                    raw = {name: float(w) for name, w in zip(names, weights)}
                total = sum(raw.values()) or 1.0
                self.detector_weights = {k: v / total for k, v in raw.items()}
            else:
                w = 1.0 / len(base_detectors)
                self.detector_weights = {name: w for name in names}

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def is_ready(self) -> bool:
        if not self.base_detectors:
            return False
        return all(d.is_ready() for d in self.base_detectors.values())

    @property
    def weights(self) -> Dict[str, float]:
        """Public alias for detector_weights."""
        return self.detector_weights

    def update_weights(self, new_weights: Dict[str, float]) -> None:
        """Update detector weights, normalising so they sum to 1."""
        total = sum(new_weights.values()) or 1.0
        self.detector_weights = {k: v / total for k, v in new_weights.items()}

    def update_threshold(self, value: float) -> None:
        """Set decision threshold, clamped to [0.0, 1.0]."""
        self.threshold = max(0.0, min(1.0, float(value)))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self, path: str) -> bool:
        try:
            ml_file = os.path.join(path, "meta_learner.joblib")
            meta_file = os.path.join(path, "ensemble_meta.json")

            if os.path.exists(ml_file):
                self.meta_learner = joblib.load(ml_file)

            if os.path.exists(meta_file):
                with open(meta_file, "r") as fh:
                    meta = json.load(fh)
                self.detector_weights = meta.get(
                    "detector_weights", self.detector_weights
                )
                self.threshold = meta.get("threshold", self.threshold)

            logger.info("Ensemble configuration loaded from %s", path)
            return True

        except Exception as exc:
            logger.error("Failed to load ensemble: %s", exc)
            return False

    def save(self, path: str) -> bool:
        try:
            os.makedirs(path, exist_ok=True)

            if self.meta_learner is not None:
                joblib.dump(
                    self.meta_learner, os.path.join(path, "meta_learner.joblib")
                )

            meta = {
                "detector_weights": self.detector_weights,
                "threshold": self.threshold,
                "detectors": list(self.base_detectors.keys()),
            }
            with open(os.path.join(path, "ensemble_meta.json"), "w") as fh:
                json.dump(meta, fh, indent=2)

            logger.info("Ensemble saved to %s", path)
            return True

        except Exception as exc:
            logger.error("Failed to save ensemble: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(
        self,
        features: np.ndarray,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Run all base detectors and combine their outputs.

        *context* may carry asset_criticality, time_risk, user_role etc. to
        boost the threat_score upward when relevant risk factors are present.
        """
        verdicts = self._collect_verdicts(features)

        if not verdicts:
            return {
                "is_threat": False,
                "threat_score": 0.0,
                "confidence": 0.0,
                "threat_type": ThreatCategory.UNKNOWN.value,
                "model_verdicts": {},
                "ensemble_details": {
                    "threshold": self.threshold,
                    "n_detectors": len(self.base_detectors),
                    "consensus": 0.0,
                },
            }

        if self._use_meta_learner and self.meta_learner is not None:
            result = self._predict_meta(verdicts)
        else:
            result = self._predict_weighted(verdicts)

        if context:
            result = self._apply_context_boost(result, context)
        return result

    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        if features.ndim == 1:
            return [self.predict(features)]
        return [self.predict(features[i]) for i in range(len(features))]

    # ------------------------------------------------------------------
    # Meta-learner training
    # ------------------------------------------------------------------

    def train_meta_learner(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """
        Train the stacking meta-learner on base-detector outputs.

        *X*: feature matrix fed to base detectors (n_samples, n_features).
        *y*: integer labels (0 = benign, 1+ = threat classes).

        This is the slow-but-convenient path: each row in X is fed one at a
        time through every base detector. For large training sets (>10k rows)
        prefer :meth:`fit_meta_learner_from_features`, which accepts a
        pre-computed meta-feature matrix produced in batched mode by the
        caller.
        """
        logger.info("Training ensemble meta-learner (per-sample path) …")

        meta_rows: List[np.ndarray] = []
        for i in range(len(X)):
            verdicts = self._collect_verdicts(X[i])
            meta_rows.append(self._verdicts_to_meta_features(verdicts).ravel())

        meta_X = np.array(meta_rows, dtype=np.float32)
        return self.fit_meta_learner_from_features(meta_X, y)

    def fit_meta_learner_from_features(
        self, meta_X: np.ndarray, y: np.ndarray
    ) -> Dict[str, float]:
        """
        Fit the logistic-regression meta-learner on pre-computed meta features.

        *meta_X* must already contain one row per training sample with the
        base-detector outputs stacked column-wise (shape: n_samples × n_meta).
        Use this when the caller has generated meta features in batched mode
        (the fast path used by ``train_all.py``).
        """
        logger.info(
            "Fitting meta-learner on pre-computed meta features (shape=%s)",
            meta_X.shape,
        )

        self.meta_learner = LogisticRegression(
            max_iter=1000,
            solver="lbfgs",
            C=1.0,
        )
        self.meta_learner.fit(meta_X, y)

        preds = self.meta_learner.predict(meta_X)
        accuracy = float(np.mean(preds == y))

        logger.info("Meta-learner training complete. Accuracy: %.4f", accuracy)
        return {"accuracy": accuracy, "n_samples": int(len(y))}

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _collect_verdicts(self, features: np.ndarray) -> Dict[str, Dict[str, Any]]:
        verdicts: Dict[str, Dict[str, Any]] = {}
        for name, detector in self.base_detectors.items():
            try:
                if not detector.is_ready():
                    logger.warning("Detector '%s' not ready, skipping", name)
                    continue
                verdicts[name] = detector.predict(features)
            except Exception as exc:
                logger.error("Detector '%s' failed: %s", name, exc)
                # Exclude failed detectors from verdicts — they should not
                # influence the ensemble output or appear in model_verdicts.
        return verdicts

    def _apply_context_boost(
        self, result: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Boost threat_score based on context risk factors."""
        boost = 0.0
        criticality = float(context.get("asset_criticality", 0))
        if criticality >= 4:
            boost += (criticality - 3) * 0.05  # +0.05 per step above 3
        if str(context.get("user_role", "")).lower() in ("admin", "administrator"):
            boost += 0.03
        time_risk = float(context.get("time_risk", 0))
        if time_risk >= 0.8:
            boost += 0.02

        if boost > 0:
            result = dict(result)
            result["threat_score"] = min(1.0, result.get("threat_score", 0.0) + boost)
        return result

    def _verdicts_to_meta_features(self, verdicts: Dict[str, Dict]) -> np.ndarray:
        feats: List[float] = []
        for name in sorted(self.base_detectors.keys()):
            v = verdicts.get(name, {})
            feats.append(float(v.get("is_threat", False)))
            feats.append(float(v.get("confidence", 0.0)))
        return np.array(feats, dtype=np.float32).reshape(1, -1)

    # -- meta-learner path ---

    def _predict_meta(self, verdicts: Dict[str, Dict]) -> Dict[str, Any]:
        meta_feats = self._verdicts_to_meta_features(verdicts)

        try:
            probs = self.meta_learner.predict_proba(meta_feats)[0]
            cls = int(np.argmax(probs))
            confidence = float(probs[cls])
            is_threat = cls != 0
        except Exception as exc:
            logger.error("Meta-learner failed, falling back to weighted vote: %s", exc)
            return self._predict_weighted(verdicts)

        threat_score = confidence if is_threat else 0.0
        consensus = sum(1 for v in verdicts.values() if v.get("is_threat")) / max(
            len(verdicts), 1
        )
        return {
            "is_threat": is_threat and confidence >= self.threshold,
            "threat_score": float(threat_score),
            "confidence": confidence,
            "threat_type": self._resolve_threat_type(verdicts, is_threat),
            "model_verdicts": self._format_verdicts(verdicts),
            "ensemble_details": {
                "threshold": self.threshold,
                "n_detectors": len(self.base_detectors),
                "consensus": float(consensus),
            },
        }

    # -- weighted-average fallback ---

    def _predict_weighted(self, verdicts: Dict[str, Dict]) -> Dict[str, Any]:
        weighted_conf = 0.0
        threat_votes = 0.0
        total_w = 0.0

        for name, v in verdicts.items():
            w = self.detector_weights.get(name, 1.0 / len(verdicts))
            weighted_conf += w * v.get("confidence", 0.0)
            if v.get("is_threat", False):
                threat_votes += w
            total_w += w

        if total_w > 0:
            weighted_conf /= total_w
            threat_ratio = threat_votes / total_w
        else:
            weighted_conf = 0.0
            threat_ratio = 0.0

        is_threat = threat_ratio >= 0.5 and weighted_conf >= self.threshold
        threat_score = (
            float(weighted_conf) if is_threat else float(weighted_conf * threat_ratio)
        )
        consensus = threat_ratio

        return {
            "is_threat": is_threat,
            "threat_score": float(threat_score),
            "confidence": float(weighted_conf),
            "threat_type": self._resolve_threat_type(verdicts, is_threat),
            "model_verdicts": self._format_verdicts(verdicts),
            "ensemble_details": {
                "threshold": self.threshold,
                "n_detectors": len(self.base_detectors),
                "consensus": float(consensus),
            },
        }

    # -- helpers ---

    @staticmethod
    def _threat_type_str(tt: Any) -> str:
        return tt.value if hasattr(tt, "value") else str(tt)

    def _resolve_threat_type(self, verdicts: Dict[str, Dict], is_threat: bool) -> str:
        if not is_threat:
            return ThreatCategory.BENIGN.value

        scores: Dict[str, float] = {}
        for name, v in verdicts.items():
            if not v.get("is_threat", False):
                continue
            tt = self._threat_type_str(v.get("threat_type", ThreatCategory.UNKNOWN))
            w = self.detector_weights.get(name, 1.0 / len(verdicts))
            scores[tt] = scores.get(tt, 0.0) + w * v.get("confidence", 0.0)

        if scores:
            return max(scores, key=scores.get)  # type: ignore[arg-type]
        return ThreatCategory.UNKNOWN.value

    def _calculate_consensus(self, verdicts: Dict[str, Dict]) -> float:
        """Fraction of detectors that agree on threat verdict [0, 1]."""
        if not verdicts:
            return 0.0
        threat_count = sum(1 for v in verdicts.values() if v.get("is_threat"))
        majority = max(threat_count, len(verdicts) - threat_count)
        return float(majority) / len(verdicts)

    def _format_verdicts(self, verdicts: Dict[str, Dict]) -> Dict[str, Any]:
        return {
            name: {
                "is_threat": v.get("is_threat", False),
                "confidence": v.get("confidence", 0.0),
                "threat_type": self._threat_type_str(
                    v.get("threat_type", ThreatCategory.UNKNOWN)
                ),
            }
            for name, v in verdicts.items()
        }
