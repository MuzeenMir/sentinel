"""
Tests for the SENTINEL SOC2 audit logger (PG-backed, T-031).

Validates:
- audit_log() inserts into PG audit_log, sets app.tenant_id, commits
- query_audit_log() reads from PG with filters
- get_audit_stats() reads from PG with category counts
- audit_log() rolls back + logs structured failure with PII redaction
- verify_integrity() detects tampered records
- _compute_integrity_hash() is deterministic
"""

import json
import os
import sys

import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_logger import (  # noqa: E402
    AuditCategory,
    audit_log,
    query_audit_log,
    get_audit_stats,
    verify_integrity,
    _compute_integrity_hash,
)


# ---------------------------------------------------------------------------
# PG fakes — replace Redis sorted-set fakes from pre-T-031.
# ---------------------------------------------------------------------------


class FakeCursor:
    def __init__(self, rows=None):
        self.rows = list(rows) if rows is not None else []
        self.statements = []
        self.params = []

    def execute(self, sql, params=None):
        self.statements.append(str(sql))
        self.params.append(params or {})

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_obj = cursor
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self, *_args, **_kwargs):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


# ===================================================================
# AuditCategory enum — unchanged by T-031
# ===================================================================


class TestAuditCategory:
    def test_all_categories_exist(self):
        expected = {
            "auth",
            "authorization",
            "data_access",
            "config_change",
            "system",
            "compliance",
            "policy",
            "alert",
        }
        values = {c.value for c in AuditCategory}
        assert values == expected

    def test_string_enum(self):
        assert AuditCategory.AUTH == "auth"
        assert isinstance(AuditCategory.AUTH, str)


# ===================================================================
# audit_log() — PG insert path
# ===================================================================


class TestAuditLogPG:
    def test_returns_record_id(self, monkeypatch):
        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        monkeypatch.setenv("DATABASE_URL", "postgresql://sentinel_app:test@db/sentinel")
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            rid = audit_log(
                AuditCategory.AUTH,
                "login_success",
                actor="user:1",
                tenant_id=7,
            )

        assert rid is not None
        assert rid.startswith("audit_")

    def test_audit_log_inserts_into_postgres_and_not_redis(self, monkeypatch):
        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        redis_client = MagicMock()
        monkeypatch.setenv("DATABASE_URL", "postgresql://sentinel_app:test@db/sentinel")
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            rid = audit_log(
                AuditCategory.AUTH,
                "login_success",
                actor="user:1",
                tenant_id=7,
                resource="auth-service",
                detail={"ip": "127.0.0.1"},
                redis_client=redis_client,
            )

        assert rid.startswith("audit_")
        assert any("INSERT INTO audit_log" in sql for sql in cursor.statements)
        assert any("set_config('app.tenant_id'" in sql for sql in cursor.statements)
        assert conn.committed is True
        redis_client.zadd.assert_not_called()

    def test_event_hash_is_canonical_column_digest(self, monkeypatch):
        # The stored event_hash MUST be the column-derivable canonical digest so
        # verify_audit_chain.py can recompute it from the DB row (wedge #3).
        from audit_merkle import canonical_event_digest

        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        monkeypatch.setenv("DATABASE_URL", "postgresql://sentinel_app:test@db/sentinel")
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(
                AuditCategory.AUTH,
                "login_success",
                actor="user:1",
                tenant_id=7,
                resource="auth-service",
                detail={"ip": "10.0.0.1"},
            )

        idx = next(
            i for i, s in enumerate(cursor.statements) if "INSERT INTO audit_log" in s
        )
        params = cursor.params[idx]
        expected = canonical_event_digest(
            tenant_id=params["tenant_id"],
            category=params["category"],
            action=params["action"],
            resource_id=params["resource_id"],
            user_id=params["user_id"],
            timestamp=params["timestamp"],
            details=json.loads(params["details"]),
        )
        assert params["event_hash"] == expected

    def test_audit_log_sets_tenant_context_before_insert(self, monkeypatch):
        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(
                AuditCategory.AUTH,
                "login_success",
                actor="user:1",
                tenant_id=42,
            )

        set_config_idx = next(
            i for i, sql in enumerate(cursor.statements) if "set_config" in sql
        )
        insert_idx = next(
            i
            for i, sql in enumerate(cursor.statements)
            if "INSERT INTO audit_log" in sql
        )
        assert set_config_idx < insert_idx

    def test_audit_log_omits_set_config_when_no_tenant(self, monkeypatch):
        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        monkeypatch.delenv("DEFAULT_TENANT_ID", raising=False)
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(
                AuditCategory.SYSTEM,
                "service_start",
            )

        assert not any("set_config" in sql for sql in cursor.statements)
        assert any("INSERT INTO audit_log" in sql for sql in cursor.statements)

    def test_audit_log_uses_default_tenant_when_no_explicit_tenant(self, monkeypatch):
        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        monkeypatch.setenv("DEFAULT_TENANT_ID", "1")
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(
                AuditCategory.AUTH,
                "user_registered",
                actor="user:7",
            )

        assert any("set_config('app.tenant_id'" in sql for sql in cursor.statements)
        assert cursor.params[-1]["tenant_id"] == 1

    def test_default_actor_is_system(self, monkeypatch):
        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.SYSTEM, "boot")

        params = cursor.params[-1]
        details_json = params.get("details")
        details = (
            json.loads(details_json) if isinstance(details_json, str) else details_json
        )
        assert details["actor"] == "system"

    def test_user_id_parsed_from_actor(self, monkeypatch):
        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.AUTH, "x", actor="user:42")

        assert cursor.params[-1]["user_id"] == 42

    def test_user_id_null_for_non_user_actor(self, monkeypatch):
        cursor = FakeCursor()
        conn = FakeConnection(cursor)
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.SYSTEM, "boot", actor="system")

        assert cursor.params[-1]["user_id"] is None


# ===================================================================
# audit_log() — failure mode
# ===================================================================


class TestAuditLogFailure:
    def test_audit_insert_failure_logs_structured_payload_and_raises(self, monkeypatch):
        class BrokenCursor(FakeCursor):
            def execute(self, sql, params=None):
                if "INSERT INTO audit_log" in str(sql):
                    raise RuntimeError("pg down")
                super().execute(sql, params)

        conn = FakeConnection(BrokenCursor())
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger.logger") as mock_logger:
            with patch("audit_logger._in_request_context", return_value=False):
                with pytest.raises(Exception):
                    audit_log(
                        AuditCategory.AUTH,
                        "login",
                        actor="user:1",
                        detail={"password": "secret", "ip": "1.2.3.4"},
                    )

        assert conn.rolled_back is True
        mock_logger.error.assert_called()
        _, kwargs = mock_logger.error.call_args
        assert kwargs["extra"]["audit_failure"] is True
        serialized = json.dumps(kwargs["extra"]["audit_event"])
        assert "secret" not in serialized
        assert "[REDACTED]" in serialized

    def test_audit_insert_failure_raises_audit_log_error(self, monkeypatch):
        from audit_logger import AuditLogError

        class BrokenCursor(FakeCursor):
            def execute(self, sql, params=None):
                if "INSERT INTO audit_log" in str(sql):
                    raise RuntimeError("pg down")
                super().execute(sql, params)

        conn = FakeConnection(BrokenCursor())
        monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

        with patch("audit_logger._in_request_context", return_value=False):
            with pytest.raises(AuditLogError):
                audit_log(AuditCategory.AUTH, "login", actor="user:1")

    def test_missing_database_url_raises_audit_log_error(self, monkeypatch):
        from audit_logger import AuditLogError

        monkeypatch.delenv("DATABASE_URL", raising=False)

        with patch("audit_logger._in_request_context", return_value=False):
            with pytest.raises(AuditLogError):
                audit_log(AuditCategory.AUTH, "login", actor="user:1")


# ===================================================================
# query_audit_log() — PG read
# ===================================================================


class TestQueryAuditLogPG:
    def test_query_audit_log_reads_pg_and_filters_actor(self, monkeypatch):
        cursor = FakeCursor(
            rows=[
                {
                    "id": 1,
                    "event_id": "11111111-1111-1111-1111-111111111111",
                    "timestamp": "2026-05-26T00:00:00Z",
                    "category": "auth",
                    "action": "login_success",
                    "resource_type": None,
                    "resource_id": "auth-service",
                    "tenant_id": 1,
                    "user_id": 1,
                    "details": {
                        "actor": "user:1",
                        "service": "auth-service",
                        "detail": {},
                    },
                    "event_hash": "a" * 64,
                }
            ]
        )
        monkeypatch.setattr("audit_logger._connect_pg", lambda: FakeConnection(cursor))

        results = query_audit_log(category="auth", actor="user:1", tenant_id=1)

        assert len(results) == 1
        assert results[0]["category"] == "auth"
        assert results[0]["actor"] == "user:1"
        assert any("FROM audit_log" in sql for sql in cursor.statements)

    def test_query_with_limit_clamps_to_1000(self, monkeypatch):
        cursor = FakeCursor(rows=[])
        monkeypatch.setattr("audit_logger._connect_pg", lambda: FakeConnection(cursor))

        query_audit_log(limit=5000)

        params = cursor.params[-1]
        assert params["limit"] <= 1000

    def test_query_no_filters_returns_all(self, monkeypatch):
        cursor = FakeCursor(
            rows=[
                {
                    "id": i,
                    "event_id": f"{i:08d}-0000-0000-0000-000000000000",
                    "timestamp": "2026-05-26T00:00:00Z",
                    "category": "auth",
                    "action": "x",
                    "resource_type": None,
                    "resource_id": "auth",
                    "tenant_id": 1,
                    "user_id": 1,
                    "details": {"actor": "user:1", "service": "x", "detail": {}},
                    "event_hash": "a" * 64,
                }
                for i in range(3)
            ]
        )
        monkeypatch.setattr("audit_logger._connect_pg", lambda: FakeConnection(cursor))

        results = query_audit_log()

        assert len(results) == 3


# ===================================================================
# get_audit_stats() — PG read
# ===================================================================


class TestGetAuditStatsPG:
    def test_get_audit_stats_reads_pg(self, monkeypatch):
        cursor = FakeCursor(
            rows=[
                {"category": "auth", "count": 2},
                {"category": "policy", "count": 1},
            ]
        )
        monkeypatch.setattr("audit_logger._connect_pg", lambda: FakeConnection(cursor))

        stats = get_audit_stats(tenant_id=1)

        assert stats["total_events"] == 3
        assert stats["by_category"] == {"auth": 2, "policy": 1}
        assert "retention_days" in stats
        assert any("FROM audit_log" in sql for sql in cursor.statements)

    def test_get_audit_stats_empty(self, monkeypatch):
        cursor = FakeCursor(rows=[])
        monkeypatch.setattr("audit_logger._connect_pg", lambda: FakeConnection(cursor))

        stats = get_audit_stats()

        assert stats["total_events"] == 0
        assert stats["by_category"] == {}


# ===================================================================
# verify_integrity() — pure-function, unchanged by storage swap
# ===================================================================


class TestVerifyIntegrity:
    def test_valid_record(self):
        record = {"action": "test", "actor": "user:1"}
        record["integrity_hash"] = _compute_integrity_hash(record)
        assert verify_integrity(record) is True

    def test_tampered_record(self):
        record = {"action": "test", "actor": "user:1"}
        record["integrity_hash"] = _compute_integrity_hash(record)
        record["actor"] = "user:HACKER"
        assert verify_integrity(record) is False

    def test_missing_hash_returns_false(self):
        assert verify_integrity({"action": "test"}) is False

    def test_verify_preserves_hash_field(self):
        record = {"action": "test"}
        record["integrity_hash"] = _compute_integrity_hash({"action": "test"})
        original_hash = record["integrity_hash"]
        verify_integrity(record)
        assert record["integrity_hash"] == original_hash


# ===================================================================
# _compute_integrity_hash() — pure-function
# ===================================================================


class TestIntegrityHash:
    def test_deterministic(self):
        record = {"a": 1, "b": "two"}
        h1 = _compute_integrity_hash(record)
        h2 = _compute_integrity_hash(record)
        assert h1 == h2

    def test_different_records_different_hash(self):
        h1 = _compute_integrity_hash({"action": "login"})
        h2 = _compute_integrity_hash({"action": "logout"})
        assert h1 != h2

    def test_key_order_irrelevant(self):
        h1 = _compute_integrity_hash({"a": 1, "b": 2})
        h2 = _compute_integrity_hash({"b": 2, "a": 1})
        assert h1 == h2
