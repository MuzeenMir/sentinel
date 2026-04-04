"""
Base classes for SENTINEL threat detection models.

Defines the abstract detector interface and the canonical threat taxonomy
that all model implementations share.
"""
import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


class ThreatCategory(str, Enum):
    """Canonical threat taxonomy used across all detectors."""

    BENIGN = "benign"
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DOS = "dos"
    PROBE = "probe"
    BRUTE_FORCE = "brute_force"
    BOTNET = "botnet"
    UNKNOWN = "unknown"


class BaseDetector(ABC):
    """
    Abstract base class for all SENTINEL threat detection models.

    Concrete subclasses must implement predict, predict_batch, train,
    load_model, and save_model.  The base class provides feature validation
    and standard metadata accessors used by the health-check and model-status
    endpoints.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self._is_ready: bool = False
        self._version: str = "0.0.0"
        self._last_updated: Optional[str] = None
        self._metrics: Dict[str, Any] = {}

    def is_ready(self) -> bool:
        return self._is_ready

    def get_version(self) -> str:
        return self._version

    def get_last_updated(self) -> Optional[str]:
        return self._last_updated

    def get_metrics(self) -> Dict[str, Any]:
        return dict(self._metrics)

    def _validate_features(self, features) -> np.ndarray:
        """Coerce *features* to a finite float32 ndarray, raising on bad input."""
        if isinstance(features, (list, tuple)):
            features = np.array(features, dtype=np.float32)
        elif not isinstance(features, np.ndarray):
            raise ValueError(
                f"Features must be a numpy array or list, got {type(features).__name__}"
            )

        features = features.astype(np.float32, copy=False)

        if not np.isfinite(features).all():
            raise ValueError("Features contain non-finite values (NaN or Inf)")

        return features

    # ------------------------------------------------------------------
    # Abstract interface every detector must implement
    # ------------------------------------------------------------------

    @abstractmethod
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """Return a prediction dict for a single sample."""

    @abstractmethod
    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Return a list of prediction dicts for a batch of samples."""

    @abstractmethod
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> Dict[str, float]:
        """Train (or retrain) the model and return training metrics."""

    @abstractmethod
    def load_model(self) -> bool:
        """Load model weights / artefacts from *self.model_path*."""

    @abstractmethod
    def save_model(self, path: Optional[str] = None) -> bool:
        """Persist model weights / artefacts to *path* (or *self.model_path*)."""
