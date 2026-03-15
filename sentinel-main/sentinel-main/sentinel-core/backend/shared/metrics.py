"""SENTINEL shared Prometheus metrics middleware for Flask services.

Usage in any service's app.py:
    from shared.metrics import setup_metrics
    setup_metrics(app, service_name="ai-engine")

This exposes a /metrics endpoint with standard HTTP request metrics
plus custom SENTINEL counters.
"""

import time
import uuid
import logging
from functools import wraps
from typing import Optional

from flask import Flask, Response, request, g

logger = logging.getLogger("sentinel.metrics")

try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        Info,
        generate_latest,
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        REGISTRY,
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.info("prometheus_client not installed; metrics disabled")


def setup_metrics(app: Flask, service_name: str = "sentinel") -> None:
    """Instrument a Flask app with Prometheus metrics and correlation IDs."""

    if not PROMETHEUS_AVAILABLE:
        @app.route("/metrics")
        def metrics_stub():
            return Response("prometheus_client not installed", status=501)
        _setup_correlation_ids(app, service_name)
        return

    http_requests = Counter(
        "sentinel_http_requests_total",
        "Total HTTP requests",
        ["service", "method", "endpoint", "status"],
    )
    http_latency = Histogram(
        "sentinel_http_request_duration_seconds",
        "HTTP request latency",
        ["service", "method", "endpoint"],
        buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    )
    service_info = Info("sentinel_service", "Service metadata")
    service_info.info({"name": service_name, "version": "1.0.0"})

    @app.before_request
    def _before():
        g.start_time = time.time()

    @app.after_request
    def _after(response):
        if request.path == "/metrics":
            return response
        latency = time.time() - getattr(g, "start_time", time.time())
        endpoint = request.endpoint or "unknown"
        http_requests.labels(
            service=service_name,
            method=request.method,
            endpoint=endpoint,
            status=response.status_code,
        ).inc()
        http_latency.labels(
            service=service_name,
            method=request.method,
            endpoint=endpoint,
        ).observe(latency)
        return response

    @app.route("/metrics")
    def metrics_endpoint():
        return Response(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)

    _setup_correlation_ids(app, service_name)
    logger.info("Prometheus metrics enabled for %s", service_name)


def _setup_correlation_ids(app: Flask, service_name: str) -> None:
    """Add correlation ID to every request for distributed tracing."""

    @app.before_request
    def _set_correlation_id():
        correlation_id = request.headers.get("X-Correlation-ID")
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        g.correlation_id = correlation_id
        g.service_name = service_name

    @app.after_request
    def _add_correlation_header(response):
        cid = getattr(g, "correlation_id", None)
        if cid:
            response.headers["X-Correlation-ID"] = cid
        return response


class StructuredLogger:
    """JSON structured logger with correlation IDs.

    Usage:
        slog = StructuredLogger("ai-engine")
        slog.info("Detection complete", threat_id="T-123", confidence=0.95)
    """

    def __init__(self, service: str):
        self._logger = logging.getLogger(f"sentinel.{service}")
        self._service = service

    def _log(self, level: int, msg: str, **kwargs) -> None:
        import json
        from flask import has_request_context
        extra = {"service": self._service}
        if has_request_context():
            extra["correlation_id"] = getattr(g, "correlation_id", None)
        extra.update(kwargs)
        self._logger.log(level, "%s | %s", msg, json.dumps(extra))

    def info(self, msg: str, **kwargs) -> None:
        self._log(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs) -> None:
        self._log(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs) -> None:
        self._log(logging.ERROR, msg, **kwargs)

    def critical(self, msg: str, **kwargs) -> None:
        self._log(logging.CRITICAL, msg, **kwargs)
