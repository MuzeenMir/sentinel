"""Custom detector interface for the SENTINEL SDK.

Subclass ``BaseCustomDetector`` to build your own threat-detection
logic, then call ``register()`` to push it to the AI engine so it
participates in the ensemble scoring pipeline.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict

from sdk.exceptions import APIError, SentinelError, ValidationError
from sdk.models import DetectionResult

if TYPE_CHECKING:
    from sdk.client import SentinelClient

logger = logging.getLogger("sentinel-sdk")


class BaseCustomDetector(ABC):
    """Abstract base for user-defined detection plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique detector name (used as registration key)."""

    @abstractmethod
    def detect(self, features: Dict[str, Any]) -> DetectionResult:
        """Run detection logic on a feature dict and return a result."""

    def register(self, client: SentinelClient) -> bool:
        """Register this detector with the SENTINEL AI engine.

        Returns *True* on success.  Raises on network / auth errors.
        """
        if not self.name:
            raise ValidationError("Detector name must be non-empty")
        try:
            client._post("/api/v1/detectors/register", json={
                "name": self.name,
                "type": "custom",
                "version": getattr(self, "version", "1.0.0"),
                "description": getattr(self, "description", ""),
            })
            logger.info("Detector '%s' registered successfully", self.name)
            return True
        except APIError as exc:
            logger.error("Detector registration failed: %s", exc)
            raise
