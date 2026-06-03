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


def require_role(
    request: Request, required_role: str
) -> dict[str, object] | JSONResponse:
    """Resolve an authenticated user and require a specific role."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    if current_user.get("role") != required_role:
        return JSONResponse({"error": "Insufficient permissions"}, status_code=403)
    return current_user


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


@asgi.post("/api/v1/auth/verify")
def auth_verify(request: Request) -> JSONResponse:
    """Verify authentication token through the auth service."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        response = requests.post(
            f"{flask_gateway.app.config['AUTH_SERVICE_URL']}/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Auth service unavailable"}, status_code=503)


@asgi.api_route(
    "/api/v1/auth/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE"],
)
async def auth_proxy(path: str, request: Request) -> JSONResponse:
    """Proxy authentication requests to auth service."""
    if path.startswith("/") or not flask_gateway._AUTH_PATH_RE.fullmatch(path):
        return JSONResponse({"error": "Invalid path"}, status_code=400)

    auth_url = f"{flask_gateway.app.config['AUTH_SERVICE_URL']}/api/v1/auth/{path}"
    headers = {}
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header

    try:
        if request.method == "GET":
            params = dict(request.query_params)
            params.pop("token", None)
            response = requests.get(auth_url, params=params, headers=headers)
        elif request.method == "POST":
            response = requests.post(
                auth_url, json=await request.json(), headers=headers
            )
        elif request.method == "PUT":
            response = requests.put(
                auth_url, json=await request.json(), headers=headers
            )
        else:
            response = requests.delete(auth_url, headers=headers)
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Auth service unavailable"}, status_code=503)


@asgi.get("/api/v1/threats")
def get_threats(request: Request) -> JSONResponse:
    """Get detected threats."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user

    params = dict(request.query_params)
    params.pop("token", None)
    try:
        response = requests.get(
            f"{flask_gateway.app.config['DATA_COLLECTOR_URL']}/api/v1/threats",
            headers={"Authorization": request.headers.get("Authorization")},
            params=params,
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse(
            {"error": "Data collector service unavailable"}, status_code=503
        )


@asgi.post("/api/v1/threats")
async def create_threat(request: Request) -> JSONResponse:
    """Create a new threat (manual entry)."""
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        response = requests.post(
            f"{flask_gateway.app.config['DATA_COLLECTOR_URL']}/api/v1/threats",
            headers={"Authorization": request.headers.get("Authorization")},
            json=await request.json(),
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse(
            {"error": "Data collector service unavailable"}, status_code=503
        )


@asgi.get("/api/v1/test-rate-limit")
@limiter.limit("5 per minute")
def test_rate_limit(request: Request) -> dict[str, object]:
    """Test rate limiting functionality."""
    return {"message": "Rate limit test successful", "timestamp": time.time()}
