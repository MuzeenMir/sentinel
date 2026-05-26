"""Runtime tenancy wiring — issues per-transaction ``SET LOCAL app.tenant_id``.

T-028 closes the CLAUDE.md hard constraint *"audit log append-only at PG role
level (not app code)"* by switching the runtime DSN to ``sentinel_app``
(NOSUPERUSER NOBYPASSRLS) and binding the tenant context into every
transaction so the RLS policies installed by migration 20260417_003 actually
fire.

Design (per T-028 scoping doc, 2026-05-24):

- Listener registered on the SQLAlchemy session ``after_begin`` event. Fires
  every time a transaction begins, including fresh transactions started
  mid-request after a commit. This is the *tx-scoped* mechanism — rejected
  alternatives are pool checkout/checkin ``SET`` (manual reset, leak-prone)
  and per-route ``before_request`` (conflicts with flask-sqlalchemy's lazy
  auto-begin and only covers the first tx of a request).
- Tenant ID read from Flask ``g.tenant_id`` (set by ``tenant_middleware``
  after JWT-based auth resolves the caller).
- Fail-closed: when no Flask request context exists or no tenant_id is
  present, **no** ``SET LOCAL`` is issued. The RLS policies use
  ``current_setting('app.tenant_id', true)`` (the ``true`` flag returns NULL
  rather than erroring on absent), and ``tenant_id = NULL::bigint`` is
  false for every row → zero rows visible. This is the desired posture: no
  context means no data.
- Dialect guard: only fires on PostgreSQL. SQLite in-memory test paths and
  any other dialect are skipped — they have no GUC to set anyway.
- ``set_config('app.tenant_id', :tid, true)`` is used instead of ``SET LOCAL
  app.tenant_id = '<tid>'``. Both are equivalent and tx-scoped, but
  ``set_config`` accepts bound parameters, avoiding any SQL-construction in
  the hot path.

Migrations remain untouched — Alembic runs as ``sentinel`` (BYPASSRLS) and
never reaches this listener.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from flask import g, has_request_context
from sqlalchemy import event, text

logger = logging.getLogger(__name__)


def _default_tenant_id() -> int | None:
    """Read ``DEFAULT_TENANT_ID`` from env at call time (not import) so tests
    that ``monkeypatch.setenv`` see the change."""
    raw = os.environ.get("DEFAULT_TENANT_ID")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def apply_tenant_to_connection(connection: Any) -> None:
    """Issue ``SELECT set_config('app.tenant_id', :tid, true)`` on ``connection``.

    Tenant ID resolution order:

    1. Flask ``g.tenant_id`` (set by ``tenant_middleware`` after auth resolves
       the caller). Authoritative for tenant-scoped, authenticated routes.
    2. ``DEFAULT_TENANT_ID`` env var. Single-tenant fallback that lets
       pre-auth routes (e.g. ``/auth/login``) still satisfy RLS so the
       initial admin lookup succeeds. Multi-tenant deployments leave this
       unset; pre-auth lookups then need a tenant hint in the request.

    Skipped if not in a Flask request context (background jobs / module
    import); those paths must call ``apply_tenant_to_connection`` directly
    after manually setting ``g.tenant_id`` or via ``set_config`` themselves.
    Skipped on non-PostgreSQL dialects.

    Exposed for direct invocation (e.g. in tests) and called by the
    ``after_begin`` listener installed via :func:`install_set_local_listener`.
    """
    if connection.dialect.name != "postgresql":
        return
    if not has_request_context():
        return
    tid = getattr(g, "tenant_id", None)
    if tid is None:
        tid = _default_tenant_id()
    if tid is None:
        return
    connection.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": str(int(tid))},
    )


def install_set_local_listener(db: Any) -> None:
    """Register the ``after_begin`` listener on ``db.session``.

    Call once at application startup, after the Flask-SQLAlchemy ``db``
    instance is initialised and bound to the Flask app.
    """

    @event.listens_for(db.session, "after_begin")
    def _set_tenant_on_tx(session, transaction, connection):
        apply_tenant_to_connection(connection)
