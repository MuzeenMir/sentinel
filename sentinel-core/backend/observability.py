"""Shared OpenTelemetry instrumentation and structured logging for SENTINEL.

Provides:
- OpenTelemetry tracing + metrics via ``init_telemetry()``
- Structured JSON logging via ``configure_logging()``

Usage in a Flask service::

    from observability import init_telemetry, configure_logging
    app = Flask(__name__)
    configure_logging(service_name="auth-service")
    init_telemetry(app, service_name="auth-service")

When the OTel SDK is not installed or the endpoint is not configured,
all calls are safe no-ops so services run without observability in dev.
"""

import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from functools import wraps

logger = logging.getLogger(__name__)

_OTEL_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
_SERVICE_NAME = os.environ.get("OTEL_SERVICE_NAME", "sentinel-service")


# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------


class _JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects for machine parsing."""

    def __init__(self, service_name: str = "sentinel-service"):
        super().__init__()
        self._service = service_name

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self._service,
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = "".join(traceback.format_exception(*record.exc_info))
        for attr in ("request_id", "user_id", "trace_id", "span_id"):
            val = getattr(record, attr, None)
            if val is not None:
                entry[attr] = val
        return json.dumps(entry, default=str)


def configure_logging(
    service_name: str = "sentinel-service",
    level: int = logging.INFO,
    json_output: bool | None = None,
) -> None:
    """Set up root logger with structured JSON (production) or human (dev).

    ``json_output`` defaults to True unless SENTINEL_LOG_FORMAT=text is set.
    """
    if json_output is None:
        json_output = os.environ.get("SENTINEL_LOG_FORMAT", "json").lower() != "text"

    root = logging.getLogger()
    root.setLevel(level)

    if root.handlers:
        root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if json_output:
        handler.setFormatter(_JSONFormatter(service_name))
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
        )
    root.addHandler(handler)

_tracer = None
_meter = None


def init_telemetry(app=None, service_name: str | None = None):
    """Bootstrap OpenTelemetry tracing and metrics.

    Safe to call even when the OTel SDK is not installed -- silently
    falls back to no-op instrumentation.
    """
    global _tracer, _meter, _SERVICE_NAME

    if service_name:
        _SERVICE_NAME = service_name
        os.environ.setdefault("OTEL_SERVICE_NAME", service_name)

    if not _OTEL_ENDPOINT:
        logger.info("OTEL_EXPORTER_OTLP_ENDPOINT not set; telemetry disabled")
        return

    try:
        from opentelemetry import trace, metrics
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME as SN
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

        resource = Resource.create({SN: _SERVICE_NAME})

        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=_OTEL_ENDPOINT, insecure=True))
        )
        trace.set_tracer_provider(tracer_provider)
        _tracer = trace.get_tracer(_SERVICE_NAME)

        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=_OTEL_ENDPOINT, insecure=True),
            export_interval_millis=30000,
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        _meter = metrics.get_meter(_SERVICE_NAME)

        if app is not None:
            try:
                from opentelemetry.instrumentation.flask import FlaskInstrumentor
                FlaskInstrumentor().instrument_app(app)
            except ImportError:
                pass

        logger.info("OpenTelemetry initialized: endpoint=%s service=%s", _OTEL_ENDPOINT, _SERVICE_NAME)

    except ImportError:
        logger.info("OpenTelemetry SDK not installed; telemetry disabled")
    except Exception as exc:
        logger.warning("OpenTelemetry init failed (non-fatal): %s", exc)


def get_tracer():
    """Return the global tracer (or a no-op stub)."""
    if _tracer:
        return _tracer
    try:
        from opentelemetry import trace
        return trace.get_tracer(_SERVICE_NAME)
    except ImportError:
        return _NoOpTracer()


def get_meter():
    """Return the global meter (or a no-op stub)."""
    if _meter:
        return _meter
    try:
        from opentelemetry import metrics
        return metrics.get_meter(_SERVICE_NAME)
    except ImportError:
        return _NoOpMeter()


def traced(name: str | None = None):
    """Decorator to wrap a function in an OTel span."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            span_name = name or f.__qualname__
            if hasattr(tracer, "start_as_current_span"):
                with tracer.start_as_current_span(span_name):
                    return f(*args, **kwargs)
            return f(*args, **kwargs)
        return wrapper
    return decorator


class _NoOpTracer:
    def start_as_current_span(self, *a, **kw):
        return _NoOpContextManager()

    def start_span(self, *a, **kw):
        return _NoOpSpan()


class _NoOpMeter:
    def create_counter(self, *a, **kw):
        return _NoOpInstrument()

    def create_histogram(self, *a, **kw):
        return _NoOpInstrument()

    def create_up_down_counter(self, *a, **kw):
        return _NoOpInstrument()


class _NoOpSpan:
    def set_attribute(self, *a, **kw): pass
    def set_status(self, *a, **kw): pass
    def end(self): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass


class _NoOpContextManager:
    def __enter__(self): return _NoOpSpan()
    def __exit__(self, *a): pass


class _NoOpInstrument:
    def add(self, *a, **kw): pass
    def record(self, *a, **kw): pass
