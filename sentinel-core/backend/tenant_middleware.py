"""Shared multi-tenancy middleware for SENTINEL services.

Extracts tenant context from the authenticated user (set by auth_middleware)
and makes it available via Flask's ``g`` object for downstream query scoping.

Usage in routes::

    from tenant_middleware import get_tenant_id, require_tenant

    @app.route("/api/v1/alerts")
    @require_auth
    @require_tenant
    def list_alerts():
        tid = get_tenant_id()
        # ... scope your query with WHERE tenant_id = tid

Environment variables
---------------------
DEFAULT_TENANT_ID : fallback tenant ID when none is present (single-tenant mode).
MULTI_TENANT_MODE : set to ``true`` to enforce tenant isolation strictly.
"""

import logging
import os
from functools import wraps

from flask import g, jsonify, request

logger = logging.getLogger(__name__)

_DEFAULT_TENANT_ID: int | None = (
    int(os.environ["DEFAULT_TENANT_ID"])
    if os.environ.get("DEFAULT_TENANT_ID")
    else None
)
_MULTI_TENANT = os.environ.get("MULTI_TENANT_MODE", "false").lower() == "true"


def get_tenant_id() -> int | None:
    """Return the current request's tenant ID, or *None* in single-tenant mode."""
    return getattr(g, "tenant_id", _DEFAULT_TENANT_ID)


def require_tenant(f):
    """Decorator: ensure a valid tenant_id is present on the request context.

    Must be applied **after** ``require_auth`` so that ``g.current_user``
    is available.  The tenant ID is read from the JWT user claim
    ``tenant_id``.  In single-tenant mode an absent tenant ID falls back to
    ``DEFAULT_TENANT_ID``.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        user = getattr(g, "current_user", None)
        tenant_id = None

        if user:
            tenant_id = user.get("tenant_id")

        if tenant_id is None:
            tenant_id = _DEFAULT_TENANT_ID

        if _MULTI_TENANT and tenant_id is None:
            logger.warning(
                "Tenant isolation enforced but no tenant_id in token for user %s",
                user.get("username") if user else "unknown",
            )
            return jsonify({"error": "Tenant context required"}), 403

        g.tenant_id = tenant_id
        return f(*args, **kwargs)

    return decorated


class TenantScope:
    """Helper for building tenant-scoped SQL queries.

    Example::

        scope = TenantScope(tenant_id=get_tenant_id())
        query = f"SELECT * FROM alerts WHERE 1=1 {scope.where_clause()}"
        params = scope.params()
    """

    def __init__(self, tenant_id: int | None = None):
        self._tid = tenant_id if tenant_id is not None else get_tenant_id()

    def where_clause(self, column: str = "tenant_id") -> str:
        if self._tid is None:
            return ""
        return f"AND {column} = %s"

    def params(self) -> tuple:
        if self._tid is None:
            return ()
        return (self._tid,)

    @property
    def tenant_id(self) -> int | None:
        return self._tid
