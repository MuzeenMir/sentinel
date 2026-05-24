"""Unit tests for _lib.tenancy.apply_tenant_to_connection.

The end-to-end RLS + role-grant behavior is verified by
sentinel-core/scripts/runtime_role_isolation_check.sh against a real
Postgres. These tests cover the per-tx handler's pure-Python logic:

- dialect guard skips non-postgresql backends
- request-context guard skips when there is no Flask request in scope
- absent tenant_id skips (fail-closed at the RLS layer)
- present tenant_id issues set_config with the tenant_id as text
- non-int tenant_id values are coerced via int() before binding
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, g  # noqa: E402

from _lib.tenancy import apply_tenant_to_connection  # noqa: E402


def _pg_conn():
    conn = MagicMock()
    conn.dialect.name = "postgresql"
    return conn


def _captured_call(conn):
    """Extract the (sql_text, params) of the single execute call on ``conn``."""
    assert (
        conn.execute.call_count == 1
    ), f"expected exactly one execute call, got {conn.execute.call_count}"
    args, kwargs = conn.execute.call_args
    sql = str(args[0])
    params = args[1] if len(args) > 1 else kwargs.get("parameters") or {}
    return sql, params


def test_skips_non_postgresql_dialect():
    conn = MagicMock()
    conn.dialect.name = "sqlite"
    app = Flask(__name__)
    with app.test_request_context("/"):
        g.tenant_id = 42
        apply_tenant_to_connection(conn)
    conn.execute.assert_not_called()


def test_skips_without_request_context():
    conn = _pg_conn()
    apply_tenant_to_connection(conn)
    conn.execute.assert_not_called()


def test_skips_without_tenant_id():
    conn = _pg_conn()
    app = Flask(__name__)
    with app.test_request_context("/"):
        apply_tenant_to_connection(conn)
    conn.execute.assert_not_called()


def test_issues_set_config_with_tenant_id():
    conn = _pg_conn()
    app = Flask(__name__)
    with app.test_request_context("/"):
        g.tenant_id = 7
        apply_tenant_to_connection(conn)
    sql, params = _captured_call(conn)
    assert "set_config" in sql
    assert "app.tenant_id" in sql
    assert params == {"tid": "7"}


def test_coerces_string_tenant_id_to_int_text():
    conn = _pg_conn()
    app = Flask(__name__)
    with app.test_request_context("/"):
        g.tenant_id = "12"
        apply_tenant_to_connection(conn)
    _, params = _captured_call(conn)
    assert params == {"tid": "12"}


def test_rejects_non_numeric_tenant_id():
    """A non-int-convertible tenant_id is a bug upstream; surface it loudly
    rather than silently issuing no SET (which would be a hidden tenant
    leak in single-tenant fall-through paths)."""
    import pytest

    conn = _pg_conn()
    app = Flask(__name__)
    with app.test_request_context("/"):
        g.tenant_id = "not-a-number"
        with pytest.raises(ValueError):
            apply_tenant_to_connection(conn)
