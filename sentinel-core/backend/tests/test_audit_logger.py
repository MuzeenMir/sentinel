"""
Tests for the SENTINEL SOC2 audit logger.

Validates:
- audit_log() records to Redis sorted sets with integrity hashes
- query_audit_log() filters by category, time range, and actor
- get_audit_stats() returns counts by category
- verify_integrity() detects tampered records
- Fallback to stdout when Redis is unavailable
"""
import json
import os
import sys
import time
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_logger import (
    AuditCategory,
    audit_log,
    query_audit_log,
    get_audit_stats,
    verify_integrity,
    _compute_integrity_hash,
)


# ---------------------------------------------------------------------------
# Fake Redis that stores sorted sets and hashes in-memory
# ---------------------------------------------------------------------------

class FakeRedis:
    def __init__(self):
        self.sorted_sets = {}   # key -> list of (score, member)
        self.hashes = {}        # key -> dict
        self.expiry = {}

    def zadd(self, key, mapping):
        if key not in self.sorted_sets:
            self.sorted_sets[key] = []
        for member, score in mapping.items():
            self.sorted_sets[key].append((score, member))
        self.sorted_sets[key].sort(key=lambda x: x[0])

    def zrangebyscore(self, key, min_score, max_score, start=0, num=100):
        entries = self.sorted_sets.get(key, [])
        filtered = [m for s, m in entries if min_score <= s <= max_score]
        return filtered[start:start + num]

    def hincrby(self, key, field, amount=1):
        if key not in self.hashes:
            self.hashes[key] = {}
        current = int(self.hashes[key].get(field, 0))
        self.hashes[key][field] = str(current + amount)

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def expire(self, key, seconds):
        self.expiry[key] = seconds


@pytest.fixture
def fake_redis():
    return FakeRedis()


# ===================================================================
# AuditCategory enum
# ===================================================================

class TestAuditCategory:
    def test_all_categories_exist(self):
        expected = {"auth", "authorization", "data_access", "config_change",
                    "system", "compliance", "policy", "alert"}
        values = {c.value for c in AuditCategory}
        assert values == expected

    def test_string_enum(self):
        assert AuditCategory.AUTH == "auth"
        assert isinstance(AuditCategory.AUTH, str)


# ===================================================================
# audit_log()
# ===================================================================

class TestAuditLog:
    def test_returns_record_id(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            rid = audit_log(
                AuditCategory.AUTH,
                "login_success",
                actor="user:1",
                redis_client=fake_redis,
            )
        assert rid is not None
        assert rid.startswith("audit_")

    def test_stores_in_category_sorted_set(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(
                AuditCategory.AUTH,
                "login_success",
                actor="user:1",
                redis_client=fake_redis,
            )
        assert "sentinel:audit:auth" in fake_redis.sorted_sets
        assert len(fake_redis.sorted_sets["sentinel:audit:auth"]) == 1

    def test_stores_in_global_index(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(
                AuditCategory.SYSTEM,
                "service_start",
                redis_client=fake_redis,
            )
        assert "sentinel:audit:index" in fake_redis.sorted_sets
        assert len(fake_redis.sorted_sets["sentinel:audit:index"]) == 1

    def test_increments_stats(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.AUTH, "a", redis_client=fake_redis)
            audit_log(AuditCategory.AUTH, "b", redis_client=fake_redis)
            audit_log(AuditCategory.SYSTEM, "c", redis_client=fake_redis)

        stats = fake_redis.hashes.get("sentinel:audit:stats", {})
        assert int(stats["total"]) == 3
        assert int(stats["auth"]) == 2
        assert int(stats["system"]) == 1

    def test_record_contains_integrity_hash(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(
                AuditCategory.AUTH,
                "login",
                actor="user:1",
                redis_client=fake_redis,
            )
        raw = fake_redis.sorted_sets["sentinel:audit:auth"][0][1]
        record = json.loads(raw)
        assert "integrity_hash" in record
        assert len(record["integrity_hash"]) == 64  # SHA-256 hex

    def test_record_fields(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(
                AuditCategory.CONFIG_CHANGE,
                "policy_updated",
                actor="user:42",
                resource="policy-orchestrator",
                detail={"policy": "fw-001"},
                tenant_id=7,
                redis_client=fake_redis,
            )
        raw = fake_redis.sorted_sets["sentinel:audit:config_change"][0][1]
        record = json.loads(raw)
        assert record["category"] == "config_change"
        assert record["action"] == "policy_updated"
        assert record["actor"] == "user:42"
        assert record["resource"] == "policy-orchestrator"
        assert record["tenant_id"] == 7
        assert record["detail"] == {"policy": "fw-001"}
        assert "timestamp" in record
        assert "epoch" in record

    def test_sets_ttl_on_category_key(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.ALERT, "fired", redis_client=fake_redis)
        assert "sentinel:audit:alert" in fake_redis.expiry
        # Default 365 days
        assert fake_redis.expiry["sentinel:audit:alert"] == 365 * 86400

    def test_default_actor_is_system(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.SYSTEM, "boot", redis_client=fake_redis)
        raw = fake_redis.sorted_sets["sentinel:audit:system"][0][1]
        record = json.loads(raw)
        assert record["actor"] == "system"

    def test_fallback_to_stdout_when_no_redis(self):
        with patch("audit_logger._in_request_context", return_value=False), \
             patch("audit_logger._get_redis", return_value=None), \
             patch("audit_logger.logger") as mock_logger:
            rid = audit_log(AuditCategory.AUTH, "login", actor="user:1")
        assert rid is not None
        # Should have logged a warning and an info fallback
        mock_logger.warning.assert_called_once()
        mock_logger.info.assert_called_once()

    def test_redis_error_falls_back_gracefully(self):
        broken_redis = MagicMock()
        broken_redis.zadd.side_effect = ConnectionError("Redis down")
        with patch("audit_logger._in_request_context", return_value=False):
            rid = audit_log(AuditCategory.AUTH, "login", redis_client=broken_redis)
        # Still returns an ID (logged to stdout fallback)
        assert rid is not None


# ===================================================================
# query_audit_log()
# ===================================================================

class TestQueryAuditLog:
    def _seed(self, fake_redis, n=5, category=AuditCategory.AUTH, actor="user:1"):
        with patch("audit_logger._in_request_context", return_value=False):
            for i in range(n):
                audit_log(category, f"action_{i}", actor=actor,
                          redis_client=fake_redis)

    def test_query_all(self, fake_redis):
        self._seed(fake_redis, 3)
        results = query_audit_log(fake_redis)
        assert len(results) == 3

    def test_query_by_category(self, fake_redis):
        self._seed(fake_redis, 2, category=AuditCategory.AUTH)
        self._seed(fake_redis, 3, category=AuditCategory.SYSTEM)
        results = query_audit_log(fake_redis, category="auth")
        assert len(results) == 2

    def test_query_by_actor(self, fake_redis):
        self._seed(fake_redis, 2, actor="user:1")
        self._seed(fake_redis, 3, actor="user:2")
        results = query_audit_log(fake_redis, actor="user:1")
        assert len(results) == 2

    def test_query_with_limit(self, fake_redis):
        self._seed(fake_redis, 10)
        results = query_audit_log(fake_redis, limit=3)
        assert len(results) == 3

    def test_query_time_range(self, fake_redis):
        now = time.time()
        results = query_audit_log(fake_redis, start_time=now - 60, end_time=now + 60)
        # No records yet, should return empty
        assert results == []

        self._seed(fake_redis, 2)
        results = query_audit_log(fake_redis, start_time=now - 60, end_time=now + 60)
        assert len(results) == 2

    def test_query_handles_redis_error(self):
        broken = MagicMock()
        broken.zrangebyscore.side_effect = ConnectionError("down")
        results = query_audit_log(broken)
        assert results == []


# ===================================================================
# get_audit_stats()
# ===================================================================

class TestGetAuditStats:
    def test_stats_after_writes(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.AUTH, "a", redis_client=fake_redis)
            audit_log(AuditCategory.AUTH, "b", redis_client=fake_redis)
            audit_log(AuditCategory.POLICY, "c", redis_client=fake_redis)

        stats = get_audit_stats(fake_redis)
        assert stats["total_events"] == 3
        assert stats["by_category"]["auth"] == 2
        assert stats["by_category"]["policy"] == 1
        assert "retention_days" in stats
        assert "timestamp" in stats

    def test_stats_empty(self, fake_redis):
        stats = get_audit_stats(fake_redis)
        assert stats["total_events"] == 0

    def test_stats_handles_error(self):
        broken = MagicMock()
        broken.hgetall.side_effect = ConnectionError("down")
        stats = get_audit_stats(broken)
        assert stats["total_events"] == 0


# ===================================================================
# verify_integrity()
# ===================================================================

class TestVerifyIntegrity:
    def test_valid_record(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.AUTH, "test", actor="user:1",
                      redis_client=fake_redis)

        raw = fake_redis.sorted_sets["sentinel:audit:auth"][0][1]
        record = json.loads(raw)
        assert verify_integrity(record) is True

    def test_tampered_record(self, fake_redis):
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.AUTH, "test", actor="user:1",
                      redis_client=fake_redis)

        raw = fake_redis.sorted_sets["sentinel:audit:auth"][0][1]
        record = json.loads(raw)
        record["actor"] = "user:HACKER"
        assert verify_integrity(record) is False

    def test_missing_hash_returns_false(self):
        assert verify_integrity({"action": "test"}) is False

    def test_verify_preserves_hash_field(self, fake_redis):
        """verify_integrity should not permanently remove the hash from the record."""
        with patch("audit_logger._in_request_context", return_value=False):
            audit_log(AuditCategory.AUTH, "test", redis_client=fake_redis)

        raw = fake_redis.sorted_sets["sentinel:audit:auth"][0][1]
        record = json.loads(raw)
        original_hash = record["integrity_hash"]
        verify_integrity(record)
        assert record["integrity_hash"] == original_hash


# ===================================================================
# _compute_integrity_hash()
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
