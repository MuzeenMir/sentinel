"""SENTINEL Python SDK — programmatic access to the SENTINEL security platform."""

from sdk.client import SentinelClient
from sdk.detectors import BaseCustomDetector
from sdk.exceptions import (
    APIError,
    AuthenticationError,
    RateLimitError,
    SentinelError,
    ValidationError,
)
from sdk.models import Alert, Assessment, DetectionResult, Explanation, Policy, Threat

__all__ = [
    "SentinelClient",
    "BaseCustomDetector",
    "DetectionResult",
    "Threat",
    "Alert",
    "Policy",
    "Assessment",
    "Explanation",
    "SentinelError",
    "AuthenticationError",
    "APIError",
    "RateLimitError",
    "ValidationError",
]
