"""Shared Prometheus metrics instrumentation for SENTINEL backend services.

Provides:
- Standard HTTP request metrics (counter + histogram) via Flask hooks
- Domain-specific gauges/counters for the Grafana dashboard
- An unauthenticated ``/metrics`` endpoint in Prometheus exposition format

Usage in a Flask service::

    from metrics import init_metrics, THREATS_DETECTED
    app = Flask(__name__)
    init_metrics(app, service_name="ai-engine")
    THREATS_DETECTED.labels(severity="critical").inc()

When ``prometheus_client`` is not installed the module degrades to no-ops
so services can run without it in minimal dev environments.
"""

from __future__ import annotations

import logging
import time
from functools import wraps
from typing import Any, Optional

from flask import Flask, Response, g, request

logger = logging.getLogger(__name__)

_PROM_AVAILABLE = False
try:
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        CONTENT_TYPE_LATEST,
        REGISTRY,
    )
    _PROM_AVAILABLE = True
except ImportError:
    logger.info("prometheus_client not installed; Prometheus metrics disabled")

# ---------------------------------------------------------------------------
# Shared metric definitions (only created when prometheus_client is available)
# ---------------------------------------------------------------------------
if _PROM_AVAILABLE:
    HTTP_REQUESTS = Counter(
        "sentinel_http_requests_total",
        "Total HTTP requests",
        ["service", "method", "endpoint", "status"],
    )
    HTTP_DURATION = Histogram(
        "sentinel_http_request_duration_seconds",
        "HTTP request latency",
        ["service", "method", "endpoint"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    )
    THREATS_DETECTED = Counter(
        "sentinel_threats_detected_total",
        "Threats detected by the AI engine",
        ["severity"],
    )
    DETECTION_LATENCY = Histogram(
        "sentinel_detection_latency_seconds",
        "AI detection pipeline latency",
        ["model"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
    )
    EBPF_EVENTS = Counter(
        "sentinel_ebpf_events_total",
        "eBPF events collected",
        ["event_type"],
    )
    HARDENING_POSTURE = Gauge(
        "sentinel_hardening_posture_score",
        "CIS hardening posture score (0-100)",
    )
    XDP_PACKETS = Counter(
        "sentinel_xdp_packets_total",
        "Packets processed by XDP collector",
        ["action"],
    )
    FIM_ALERTS = Counter(
        "sentinel_fim_alerts_total",
        "File integrity monitoring alerts",
    )
    ALERTS_CREATED = Counter(
        "sentinel_alerts_created_total",
        "Alerts created by the alert service",
        ["severity"],
    )
    POLICIES_APPLIED = Counter(
        "sentinel_policies_applied_total",
        "Firewall policies applied by the policy orchestrator",
        ["action"],
    )
    DRL_DECISIONS = Counter(
        "sentinel_drl_decisions_total",
        "DRL policy decisions made",
        ["action"],
    )
    SERVICE_INFO = Gauge(
        "sentinel_service_info",
        "Static service metadata",
        ["service", "version"],
    )
else:
    class _Noop:
        """No-op metric stub that silently swallows all calls."""
        def labels(self, *a: Any, **kw: Any) -> "_Noop":
            return self
        def inc(self, *a: Any, **kw: Any) -> None: ...
        def dec(self, *a: Any, **kw: Any) -> None: ...
        def set(self, *a: Any, **kw: Any) -> None: ...
        def observe(self, *a: Any, **kw: Any) -> None: ...
        def time(self) -> "_NoopTimer":
            return _NoopTimer()

    class _NoopTimer:
        def __enter__(self) -> "_NoopTimer": return self
        def __exit__(self, *a: Any) -> None: ...

    _noop = _Noop()
    HTTP_REQUESTS = _noop      # type: ignore[assignment]
    HTTP_DURATION = _noop      # type: ignore[assignment]
    THREATS_DETECTED = _noop   # type: ignore[assignment]
    DETECTION_LATENCY = _noop  # type: ignore[assignment]
    EBPF_EVENTS = _noop        # type: ignore[assignment]
    HARDENING_POSTURE = _noop  # type: ignore[assignment]
    XDP_PACKETS = _noop        # type: ignore[assignment]
    FIM_ALERTS = _noop         # type: ignore[assignment]
    ALERTS_CREATED = _noop     # type: ignore[assignment]
    POLICIES_APPLIED = _noop   # type: ignore[assignment]
    DRL_DECISIONS = _noop      # type: ignore[assignment]
    SERVICE_INFO = _noop       # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------


def init_metrics(app: Flask, service_name: str = "sentinel-service") -> None:
    """Register ``before_request`` / ``after_request`` hooks and ``/metrics``."""
    if not _PROM_AVAILABLE:
        logger.info("Prometheus metrics disabled (prometheus_client not installed)")
        return

    SERVICE_INFO.labels(service=service_name, version="1.0.0").set(1)

    @app.before_request
    def _start_timer() -> None:
        g._prom_start = time.monotonic()

    @app.after_request
    def _record_metrics(response: Response) -> Response:
        if request.path == "/metrics" or request.path == "/health":
            return response
        elapsed = time.monotonic() - getattr(g, "_prom_start", time.monotonic())
        endpoint = request.endpoint or request.path
        HTTP_REQUESTS.labels(
            service=service_name,
            method=request.method,
            endpoint=endpoint,
            status=response.status_code,
        ).inc()
        HTTP_DURATION.labels(
            service=service_name,
            method=request.method,
            endpoint=endpoint,
        ).observe(elapsed)
        return response

    @app.route("/metrics")
    def prometheus_metrics() -> Response:
        return Response(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)

    logger.info("Prometheus metrics initialized for %s", service_name)
