"""
Shared JWT authentication and RBAC middleware for SENTINEL internal services.

Internal services (ai-engine, drl-engine, xai-service, compliance-engine,
policy-orchestrator) call auth-service /api/v1/auth/verify to validate every
inbound JWT.  The verified user dict is injected into Flask's g context so
route handlers can inspect role and identity without re-decoding the token.

Environment variables
---------------------
AUTH_SERVICE_URL : URL of the auth-service (default: http://auth-service:5000)
AUTH_VERIFY_TIMEOUT : seconds to wait for auth-service (default: 3)
"""

import logging
import os
from functools import wraps

import requests
from flask import g, jsonify, request

logger = logging.getLogger(__name__)

_AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "http://auth-service:5000")
_VERIFY_ENDPOINT = f"{_AUTH_SERVICE_URL}/api/v1/auth/verify"
_VERIFY_TIMEOUT = int(os.environ.get("AUTH_VERIFY_TIMEOUT", "3"))

# Roles in descending privilege order.
_ROLE_HIERARCHY = ["admin", "operator", "security_analyst", "auditor", "viewer"]


def _verify_token(token: str) -> dict | None:
    """
    Call auth-service to verify *token*.

    Returns the user dict on success, or None if the token is invalid /
    expired / revoked.  Network failures are treated as authentication
    failures (fail-closed security posture).
    """
    try:
        resp = requests.post(
            _VERIFY_ENDPOINT,
            headers={"Authorization": f"Bearer {token}"},
            timeout=_VERIFY_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("user")
        logger.warning(
            "auth-service rejected token (HTTP %s): %s",
            resp.status_code,
            resp.text[:200],
        )
        return None
    except requests.exceptions.RequestException as exc:
        logger.error("Failed to reach auth-service for token verification: %s", exc)
        return None


def require_auth(f):
    """
    Decorator: verify Bearer JWT via auth-service.

    On success the verified user dict is available as ``flask.g.current_user``.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token required"}), 401

        token = auth_header.split(" ", 1)[1]
        user = _verify_token(token)
        if user is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


def require_role(*allowed_roles: str):
    """
    Decorator: enforce that the authenticated user's role is one of
    *allowed_roles*.  Must be applied **after** ``require_auth``.

    Roles accepted (case-insensitive):
        admin, operator, security_analyst, auditor, viewer
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return jsonify({"error": "Authentication required"}), 401

            user_role = (user.get("role") or "").lower()
            normalised = [r.lower() for r in allowed_roles]

            if user_role not in normalised:
                logger.warning(
                    "Authorisation denied: user %s (role=%s) attempted %s %s",
                    user.get("username"),
                    user_role,
                    request.method,
                    request.path,
                )
                return jsonify({"error": "Insufficient permissions"}), 403

            return f(*args, **kwargs)

        return decorated

    return decorator
