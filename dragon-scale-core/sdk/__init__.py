"""DRAGON_SCALE Python SDK — programmatic access to the DRAGON_SCALE security platform."""

from sdk.client import DragonScaleClient
from sdk.detectors import BaseCustomDetector
from sdk.exceptions import (
    APIError,
    AuthenticationError,
    RateLimitError,
    DragonScaleError,
    ValidationError,
)
from sdk.models import Alert, Assessment, DetectionResult, Explanation, Policy, Threat

__all__ = [
    "DragonScaleClient",
    "BaseCustomDetector",
    "DetectionResult",
    "Threat",
    "Alert",
    "Policy",
    "Assessment",
    "Explanation",
    "DragonScaleError",
    "AuthenticationError",
    "APIError",
    "RateLimitError",
    "ValidationError",
]
