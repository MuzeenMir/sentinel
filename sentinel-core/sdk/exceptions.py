"""SENTINEL SDK exception hierarchy."""

from __future__ import annotations

from typing import Any, Dict, Optional


class SentinelError(Exception):
    """Base exception for all SENTINEL SDK errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class AuthenticationError(SentinelError):
    """Raised when login fails or a token is rejected."""


class APIError(SentinelError):
    """Raised when the API returns a non-success status code."""

    def __init__(
        self,
        message: str,
        status_code: int = 0,
        response_body: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, details=response_body)
        self.status_code = status_code
        self.response_body = response_body or {}


class RateLimitError(APIError):
    """Raised when the API returns HTTP 429."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[float] = None,
        **kwargs: Any,
    ):
        super().__init__(message, status_code=429, **kwargs)
        self.retry_after = retry_after


class ValidationError(SentinelError):
    """Raised when request parameters fail client-side validation."""
