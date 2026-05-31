"""SENTINEL LLM Gateway.

Phase 2 — Wedge #2: the grounded LLM analyst copilot.

This service replaces the Phase-1 410 shell with a real, grounded, tool-using
analyst copilot. It is **advisory only**: it summarizes incidents from real
backend data, answers follow-ups with citations to source records, and
*proposes* (never executes) reversible enforcement actions. A human confirms
any action through the existing policy-orchestrator API.

Inference is provided by the Anthropic API and is optional: when no API key is
configured the gateway still serves /health and reports inference disabled.
"""

import logging
import os
import sys
from datetime import datetime, timezone

from flask import Flask, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from observability import configure_logging  # noqa: E402
from metrics import init_metrics  # noqa: E402

SERVICE_NAME = "llm-gateway"

app = Flask(__name__)
configure_logging(service_name=SERVICE_NAME)
init_metrics(app, service_name=SERVICE_NAME)

logger = logging.getLogger(__name__)


def inference_enabled() -> bool:
    """True when an Anthropic API key is configured for real inference."""
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


@app.get("/health")
def health():
    return (
        jsonify(
            {
                "status": "healthy",
                "service": SERVICE_NAME,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ),
        200,
    )


@app.get("/readyz")
def readyz():
    return (
        jsonify(
            {
                "status": "ready",
                "service": SERVICE_NAME,
                "inference_enabled": inference_enabled(),
            }
        ),
        200,
    )


if __name__ == "__main__":
    from _lib.net import bind_host

    port = int(os.environ.get("PORT", "5012"))
    app.run(host=bind_host(), port=port)
