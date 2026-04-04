"""Shared authentication middleware for SENTINEL backend services.

Provides ``require_auth`` and ``require_role`` decorators that verify
JWT tokens by calling the auth-service ``/api/v1/auth/verify`` endpoint.
On success the authenticated user dict is stored on ``flask.g.current_user``.

The auth-service call is protected by a circuit breaker (from
``resilience.py``) so that a downstream auth-service outage doesn't
cascade to every request across every service.

Usage::

    from auth_middleware import require_auth, require_role

    @app.route("/api/v1/alerts")
    @require_auth
    def list_alerts():
        user = g.current_user
        ...

    @app.route("/api/v1/admin/users")
    @require_role("admin")
    def admin_users():
        ...
"""

import logging
import os
from functools import wraps
from typing import Optional

import requests
from flask import g, jsonify, request

from resilience import CircuitBreakerOpen, circuit_breaker, retry_with_backoff

logger = logging.getLogger(__name__)

AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "http://auth-service:5000")
AUTH_VERIFY_TIMEOUT = int(os.environ.get("AUTH_VERIFY_TIMEOUT", "5"))


@circuit_breaker("auth-service", failure_threshold=5, recovery_timeout=30.0)
@retry_with_backoff(
    max_retries=1,
    base_delay=0.3,
    retryable_exceptions=(requests.exceptions.ConnectionError, requests.exceptions.Timeout),
)
def _verify_token(token: str) -> Optional[dict]:
    """Call auth-service to verify a JWT and return the user dict, or *None*."""
    resp = requests.post(
        f"{AUTH_SERVICE_URL}/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
        timeout=AUTH_VERIFY_TIMEOUT,
    )
    if resp.status_code == 200:
        data = resp.json()
        return data.get("user")
    return None


def _extract_token() -> Optional[str]:
    """Extract Bearer token from the Authorization header or query param."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return request.args.get("token")


def require_auth(f):
    """Decorator: reject unauthenticated requests.

    On success ``g.current_user`` is set to the user dict returned by
    auth-service (keys: id, username, email, role, tenant_id, ...).
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({"error": "Authorization token required"}), 401

        try:
            user = _verify_token(token)
        except CircuitBreakerOpen:
            logger.warning("Auth-service circuit breaker open; rejecting request")
            return jsonify({"error": "Authentication service temporarily unavailable"}), 503
        except requests.exceptions.RequestException as exc:
            logger.error("Auth-service communication error: %s", exc)
            return jsonify({"error": "Authentication service unavailable"}), 503

        if user is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


def require_role(*allowed_roles: str):
    """Decorator: require the authenticated user to have one of *allowed_roles*.

    Must be applied as ``@require_role("admin")`` or
    ``@require_role("admin", "security_analyst")``.

    When used as a decorator the inner function is automatically wrapped
    with ``@require_auth``, so callers do **not** need to stack both
    decorators.
    """

    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated(*args, **kwargs):
            user_role = g.current_user.get("role", "")
            if user_role not in allowed_roles:
                logger.warning(
                    "Access denied: user=%s role=%s required=%s endpoint=%s",
                    g.current_user.get("username"),
                    user_role,
                    allowed_roles,
                    request.path,
                )
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)

        return decorated

    return decorator
