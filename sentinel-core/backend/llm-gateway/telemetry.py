"""OpenTelemetry spans for the copilot model/tool calls.

No-op safe: if OpenTelemetry is not installed or no exporter is configured, the
``span`` context manager is a harmless pass-through, so importing and calling it
never requires a tracing backend (consistent with the sibling services).
"""

from __future__ import annotations

import contextlib
from typing import Any, Iterator

try:  # OTel is an optional runtime dependency.
    from opentelemetry import trace as _trace

    _tracer = _trace.get_tracer("llm-gateway.copilot")
except Exception:  # pragma: no cover - otel not present
    _tracer = None


@contextlib.contextmanager
def span(name: str, **attributes: Any) -> Iterator[None]:
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            try:
                current.set_attribute(key, value)
            except Exception:  # pragma: no cover - attribute coercion guard
                pass
        yield
