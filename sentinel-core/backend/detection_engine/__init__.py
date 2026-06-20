"""Detection-as-code registry API.

STATUS: EXPERIMENTAL / OFFLINE TOOLING (audit SUB-01, 2026-06-19). This registry
is real and unit-tested (tests/test_detection_engine.py, test_detection_rules.py)
but is NOT yet imported by any runtime service — no ai-engine / data-collector
ingest path consumes it. Treat it as a library staged for a future wiring task,
not an active detection pipeline. Do not present it as live detection coverage
until a service consumes load_registry()/DetectionRegistry at runtime.
"""

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
