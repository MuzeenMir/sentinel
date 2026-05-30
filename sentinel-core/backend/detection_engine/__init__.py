"""Detection-as-code registry API."""

from detection_engine.registry import (
    DetectionRegistry,
    DetectionValidationError,
    SigmaRule,
    load_registry,
)
from detection_engine.types import Detector, Finding

__all__ = [
    "DetectionRegistry",
    "DetectionValidationError",
    "Detector",
    "Finding",
    "SigmaRule",
    "load_registry",
]
