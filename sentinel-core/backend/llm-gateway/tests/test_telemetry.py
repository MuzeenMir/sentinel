"""Telemetry spans must be no-op safe without a configured exporter."""

from telemetry import span


def test_span_is_noop_safe_and_reentrant():
    with span("copilot.model_call", iteration=1):
        with span("copilot.tool_call", tool="get_threat_score"):
            pass  # must not raise even with no OTel exporter configured


def test_span_yields_control():
    ran = False
    with span("x"):
        ran = True
    assert ran is True
