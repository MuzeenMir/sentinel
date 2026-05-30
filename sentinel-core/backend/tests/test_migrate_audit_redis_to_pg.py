"""
Tests for the T-031 Redis -> PG audit_log backfill script.

Validates:
- event_id is a deterministic UUIDv5 of the legacy Redis id under a fixed
  T-031 namespace.
- Backfill is idempotent: second run inserts zero new rows and leaves the
  total PG row count stable.
- Malformed records (non-JSON, missing required fields) are quarantined to
  the skipped.jsonl file with a structured reason.
- Verification gate: deletion of Redis keys requires
  new_inserts + pre_existing_matches == successfully_parsed_records.
- Dry-run mode never deletes Redis keys.
"""

import json
import os
import sys
import uuid

import pytest

_scripts_dir = os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
sys.path.insert(0, _scripts_dir)

import migrate_audit_redis_to_pg as script  # noqa: E402


# ---------------------------------------------------------------------------
# Fake Redis (zrange-based sorted set + key deletion)
# ---------------------------------------------------------------------------


class _FakeRedis:
    def __init__(self):
        self._index_members = []  # serialized JSON strings
        self._raw_members = []  # raw bytes not parseable as JSON
        self._deleted_keys = []

    def add(self, record: dict):
        self._index_members.append(json.dumps(record))

    def add_raw(self, raw: str):
        self._raw_members.append(raw)

    def zrange(self, key, start, end):
        if key != "sentinel:audit:index":
            return []
        return [m.encode("utf-8") for m in (self._index_members + self._raw_members)]

    def delete(self, *keys):
        self._deleted_keys.extend(keys)
        return len(keys)


# ---------------------------------------------------------------------------
# Fake PG (captures inserts, supports ON CONFLICT DO NOTHING semantics)
# ---------------------------------------------------------------------------


class _FakePGCursor:
    def __init__(self, pg):
        self.pg = pg

    def execute(self, sql, params=None):
        s = str(sql)
        if "INSERT INTO audit_log" in s:
            event_id = params["event_id"]
            if event_id in self.pg.seen_event_ids:
                # ON CONFLICT (event_id) DO NOTHING -> no insert
                self.pg.last_inserted = 0
                return
            self.pg.seen_event_ids.add(event_id)
            self.pg.rows.append(params)
            self.pg.last_inserted = 1
        elif "set_config" in s:
            self.pg.tenant_id = params.get("tenant_id")
        self.pg.statements.append(s)

    def fetchone(self):
        return (self.pg.last_inserted,)

    def fetchall(self):
        return list(self.pg.rows)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _FakePGConn:
    def __init__(self):
        self.rows = []
        self.seen_event_ids = set()
        self.statements = []
        self.tenant_id = None
        self.last_inserted = 0
        self.committed = 0
        self.rolled_back = 0

    @property
    def row_count(self):
        return len(self.rows)

    def cursor(self, *_args, **_kwargs):
        return _FakePGCursor(self)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@pytest.fixture
def fake_redis():
    return _FakeRedis()


@pytest.fixture
def fake_pg():
    return _FakePGConn()


# ===================================================================
# event_id_from_redis_id
# ===================================================================


class TestEventIdMapping:
    def test_event_id_is_deterministic_from_redis_id(self):
        first = script.event_id_from_redis_id("audit_abc")
        second = script.event_id_from_redis_id("audit_abc")
        assert first == second
        assert isinstance(first, uuid.UUID)

    def test_different_redis_ids_yield_different_event_ids(self):
        a = script.event_id_from_redis_id("audit_abc")
        b = script.event_id_from_redis_id("audit_def")
        assert a != b

    def test_event_id_uses_uuid5_under_t031_namespace(self):
        expected = uuid.uuid5(script.T031_EVENT_NAMESPACE, "audit_abc")
        assert script.event_id_from_redis_id("audit_abc") == expected


# ===================================================================
# backfill behavior
# ===================================================================


class TestBackfillIdempotency:
    def test_first_run_inserts_all_records(self, fake_redis, fake_pg, tmp_path):
        for i in range(3):
            fake_redis.add(
                {
                    "id": f"audit_r{i}",
                    "tenant_id": 1,
                    "category": "auth",
                    "action": "login",
                    "actor": "user:1",
                    "timestamp": "2026-05-10T00:00:00Z",
                    "epoch": 1715299200.0,
                    "detail": {"ip": "127.0.0.1"},
                    "integrity_hash": "a" * 64,
                }
            )

        result = script.backfill(
            redis_client=fake_redis,
            pg=fake_pg,
            skipped_path=tmp_path / "skipped.jsonl",
            delete_after_verify=False,
        )

        assert result.inserted == 3
        assert result.skipped == 0
        assert fake_pg.row_count == 3

    def test_second_run_inserts_zero_and_row_count_stable(
        self, fake_redis, fake_pg, tmp_path
    ):
        fake_redis.add(
            {
                "id": "audit_abc",
                "tenant_id": 1,
                "category": "auth",
                "action": "login",
                "actor": "user:1",
                "timestamp": "2026-05-10T00:00:00Z",
                "epoch": 1715299200.0,
                "detail": {},
                "integrity_hash": "a" * 64,
            }
        )

        first = script.backfill(
            redis_client=fake_redis,
            pg=fake_pg,
            skipped_path=tmp_path / "skipped.jsonl",
            delete_after_verify=False,
        )
        second = script.backfill(
            redis_client=fake_redis,
            pg=fake_pg,
            skipped_path=tmp_path / "skipped.jsonl",
            delete_after_verify=False,
        )

        assert first.inserted == 1
        assert second.inserted == 0
        assert second.pre_existing_matches == 1
        assert fake_pg.row_count == 1


class TestBackfillSkippedRecords:
    def test_malformed_records_go_to_skipped_jsonl(self, tmp_path, fake_redis, fake_pg):
        fake_redis.add_raw("not-json{")
        skipped = tmp_path / "skipped.jsonl"

        result = script.backfill(
            redis_client=fake_redis,
            pg=fake_pg,
            skipped_path=skipped,
            delete_after_verify=False,
        )

        assert result.skipped == 1
        content = skipped.read_text()
        assert "malformed_json" in content
        assert "not-json{" in content

    def test_missing_required_fields_go_to_skipped_jsonl(
        self, tmp_path, fake_redis, fake_pg
    ):
        # Missing 'tenant_id' and 'category'
        fake_redis.add({"id": "audit_x", "action": "login"})
        skipped = tmp_path / "skipped.jsonl"

        result = script.backfill(
            redis_client=fake_redis,
            pg=fake_pg,
            skipped_path=skipped,
            delete_after_verify=False,
        )

        assert result.skipped == 1
        assert result.inserted == 0
        content = skipped.read_text()
        assert "missing_required_field" in content


class TestBackfillVerificationGate:
    def test_skipped_records_block_verification_and_redis_delete(
        self, tmp_path, fake_redis, fake_pg
    ):
        fake_redis.add_raw("not-json{")

        result = script.backfill(
            redis_client=fake_redis,
            pg=fake_pg,
            skipped_path=tmp_path / "skipped.jsonl",
            delete_after_verify=True,
        )

        assert result.verified is False
        assert result.deleted_redis_keys is False
        assert fake_redis._deleted_keys == []

    def test_delete_after_verify_runs_when_counts_match(
        self, tmp_path, fake_redis, fake_pg
    ):
        fake_redis.add(
            {
                "id": "audit_a",
                "tenant_id": 1,
                "category": "auth",
                "action": "login",
                "actor": "user:1",
                "timestamp": "2026-05-10T00:00:00Z",
                "epoch": 1715299200.0,
                "detail": {},
                "integrity_hash": "a" * 64,
            }
        )

        result = script.backfill(
            redis_client=fake_redis,
            pg=fake_pg,
            skipped_path=tmp_path / "skipped.jsonl",
            delete_after_verify=True,
        )

        assert result.deleted_redis_keys is True
        assert "sentinel:audit:index" in fake_redis._deleted_keys

    def test_dry_run_never_deletes(self, tmp_path, fake_redis, fake_pg):
        fake_redis.add(
            {
                "id": "audit_a",
                "tenant_id": 1,
                "category": "auth",
                "action": "login",
                "actor": "user:1",
                "timestamp": "2026-05-10T00:00:00Z",
                "epoch": 1715299200.0,
                "detail": {},
                "integrity_hash": "a" * 64,
            }
        )

        result = script.backfill(
            redis_client=fake_redis,
            pg=fake_pg,
            skipped_path=tmp_path / "skipped.jsonl",
            delete_after_verify=False,
        )

        assert result.deleted_redis_keys is False
        assert fake_redis._deleted_keys == []
