"""FastAPI app surface for the api-gateway port.

The Flask gateway remains the production runtime until K1.1e. This module grows
route parity incrementally while reusing stable helpers from ``app.py``.
"""

from __future__ import annotations

import time

from fastapi import FastAPI

import app as flask_gateway


asgi = FastAPI(title="SENTINEL API Gateway")


@asgi.get("/health")
def health_check() -> dict[str, object]:
    """Health check endpoint matching the Flask gateway response shape."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "request_stats": flask_gateway.get_request_stats(),
    }


@asgi.get("/readyz")
def readyz() -> dict[str, str]:
    """Readiness probe for the ASGI runtime."""
    return {"status": "ready"}
