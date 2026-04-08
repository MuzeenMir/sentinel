"""Shared resilience patterns for SENTINEL services: circuit breaker, retry, structured logging.

Provides enterprise-grade fault tolerance for inter-service calls.

Usage::

    from resilience import circuit_breaker, retry_with_backoff, setup_structured_logging

    setup_structured_logging("ai-engine")

    @circuit_breaker("auth-service")
    @retry_with_backoff(max_retries=3)
    def call_auth_service(token):
        ...
"""

import json
import logging
import os
import sys
import threading
import time
from functools import wraps
from typing import Any, Optional

# ── Structured JSON Logging ──────────────────────────────────────────


class JSONFormatter(logging.Formatter):
    """Emit structured JSON log lines for log aggregation (ELK, Loki, CloudWatch)."""

    def __init__(self, service_name: str = "sentinel"):
        super().__init__()
        self._service = service_name
        self._hostname = os.environ.get("HOSTNAME", "unknown")

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "service": self._service,
            "hostname": self._hostname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "tenant_id"):
            log_entry["tenant_id"] = record.tenant_id
        if hasattr(record, "user"):
            log_entry["user"] = record.user
        return json.dumps(log_entry, default=str)


def setup_structured_logging(service_name: str, level: str = "INFO") -> None:
    """Configure structured JSON logging for a service."""
    use_json = os.environ.get("LOG_FORMAT", "text").lower() == "json"

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if use_json:
        handler.setFormatter(JSONFormatter(service_name))
    else:
        handler.setFormatter(logging.Formatter(
            f"%(asctime)s [{service_name}] %(levelname)s %(name)s %(message)s"
        ))
    root.addHandler(handler)


# ── Circuit Breaker ──────────────────────────────────────────────────


class CircuitBreakerOpen(Exception):
    """Raised when the circuit is open and calls are rejected."""
    pass


class _CircuitBreaker:
    """Thread-safe circuit breaker (closed -> open -> half-open -> closed)."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ):
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._success_threshold = success_threshold

        self._state = self.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == self.OPEN:
                if time.time() - self._last_failure_time >= self._recovery_timeout:
                    self._state = self.HALF_OPEN
                    self._success_count = 0
            return self._state

    def record_success(self) -> None:
        with self._lock:
            if self._state == self.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self._success_threshold:
                    self._state = self.CLOSED
                    self._failure_count = 0
            elif self._state == self.CLOSED:
                self._failure_count = max(0, self._failure_count - 1)

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._state == self.HALF_OPEN:
                self._state = self.OPEN
            elif self._failure_count >= self._failure_threshold:
                self._state = self.OPEN
                logging.getLogger("sentinel.circuit_breaker").warning(
                    "Circuit breaker '%s' OPEN after %d failures",
                    self.name, self._failure_count,
                )


_breakers: dict[str, _CircuitBreaker] = {}
_breakers_lock = threading.Lock()


def _get_breaker(name: str, **kwargs) -> _CircuitBreaker:
    with _breakers_lock:
        if name not in _breakers:
            _breakers[name] = _CircuitBreaker(name, **kwargs)
        return _breakers[name]


def circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 30.0,
):
    """Decorator: wraps a function with a named circuit breaker."""

    def decorator(f):
        breaker = _get_breaker(name, failure_threshold=failure_threshold,
                               recovery_timeout=recovery_timeout)

        @wraps(f)
        def wrapper(*args, **kwargs):
            if breaker.state == _CircuitBreaker.OPEN:
                raise CircuitBreakerOpen(
                    f"Circuit breaker '{name}' is open; call rejected"
                )
            try:
                result = f(*args, **kwargs)
                breaker.record_success()
                return result
            except CircuitBreakerOpen:
                raise
            except Exception:
                breaker.record_failure()
                raise

        wrapper.breaker = breaker
        return wrapper

    return decorator


# ── Retry with Exponential Backoff ───────────────────────────────────


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 30.0,
    exponential_base: float = 2.0,
    retryable_exceptions: tuple = (Exception,),
):
    """Decorator: retries a function with exponential backoff on failure."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return f(*args, **kwargs)
                except retryable_exceptions as exc:
                    last_exception = exc
                    if attempt == max_retries:
                        break
                    delay = min(base_delay * (exponential_base ** attempt), max_delay)
                    logging.getLogger("sentinel.retry").warning(
                        "Retry %d/%d for %s after %.1fs: %s",
                        attempt + 1, max_retries, f.__qualname__, delay, exc,
                    )
                    time.sleep(delay)
            raise last_exception

        return wrapper

    return decorator


# ── Health Check Registry ────────────────────────────────────────────


class HealthCheck:
    """Aggregates health checks from multiple subsystems."""

    def __init__(self, service_name: str):
        self._service = service_name
        self._checks: dict[str, callable] = {}

    def register(self, name: str, check_fn: callable) -> None:
        self._checks[name] = check_fn

    def check_all(self) -> dict:
        results = {}
        overall = "healthy"
        for name, fn in self._checks.items():
            try:
                status = fn()
                results[name] = {"status": "ok"} if status else {"status": "degraded"}
                if not status:
                    overall = "degraded"
            except Exception as exc:
                results[name] = {"status": "error", "error": str(exc)}
                overall = "unhealthy"
        return {
            "service": self._service,
            "status": overall,
            "checks": results,
            "timestamp": time.time(),
        }
