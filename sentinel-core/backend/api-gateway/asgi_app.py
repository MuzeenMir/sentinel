"""FastAPI app surface for the api-gateway port.

The Flask gateway remains the production runtime until K1.1e. This module grows
route parity incrementally while reusing stable helpers from ``app.py``.
"""

from __future__ import annotations

import time

import requests
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

import app as flask_gateway


asgi = FastAPI(title="SENTINEL API Gateway")
asgi.add_middleware(
    CORSMiddleware,
    allow_origins=flask_gateway._load_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address, default_limits=["200 per hour"])
asgi.state.limiter = limiter
asgi.add_middleware(SlowAPIMiddleware)


@asgi.exception_handler(RateLimitExceeded)
async def rate_limit_handler(
    _request: Request, _exc: RateLimitExceeded
) -> JSONResponse:
    return JSONResponse(
        {
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later.",
        },
        status_code=429,
    )


def require_current_user(request: Request) -> dict[str, object] | JSONResponse:
    """Resolve the authenticated user using Flask gateway token semantics."""
    auth_header = request.headers.get("authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    elif request.query_params.get("token"):
        token = request.query_params.get("token")
    if not token:
        return JSONResponse({"error": "Authorization token required"}, status_code=401)

    try:
        response = requests.post(
            f"{flask_gateway.app.config['AUTH_SERVICE_URL']}/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if response.status_code != 200:
            return JSONResponse({"error": "Invalid token"}, status_code=401)
        user_info = response.json()
        return dict(user_info["user"])
    except requests.exceptions.RequestException:
        return JSONResponse(
            {"error": "Authentication service unavailable"}, status_code=503
        )


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


@asgi.get("/api/v1/test-rate-limit")
@limiter.limit("5 per minute")
def test_rate_limit(request: Request) -> dict[str, object]:
    """Test rate limiting functionality."""
    return {"message": "Rate limit test successful", "timestamp": time.time()}
