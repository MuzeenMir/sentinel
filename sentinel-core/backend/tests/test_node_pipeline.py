"""Real node-path e2e: auditd event -> Redis stream -> ai-engine -> node_alerts.

The Month-1 spine gate. Marked ``integration`` so it runs against the real
Redis + migrated Postgres of the integration-compose CI job (host-published
ports, see docker-compose.ci.yml); NODE_E2E_DATABASE_URL must be the
node_alerts OWNER role — writes are owner-only (20260627_001).

Local runs skip cleanly when the backing stores are unreachable. CI sets
NODE_E2E_REQUIRE=1 to turn those skips into failures — a silently-skipped
gate is a false green.
"""

import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ai-engine"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data-collector"))

pytestmark = pytest.mark.integration

REDIS_URL = os.environ.get("NODE_E2E_REDIS_URL") or os.environ.get(
    "REDIS_URL", "redis://localhost:6379"
)
DATABASE_URL = os.environ.get("NODE_E2E_DATABASE_URL") or os.environ.get(
    "DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel"
)


def _unreachable(what: str) -> None:
    if os.environ.get("NODE_E2E_REQUIRE"):
        pytest.fail(f"{what} unreachable but NODE_E2E_REQUIRE is set")
    pytest.skip(f"{what} not reachable")


@pytest.fixture(scope="module")
def redis_client():
    redis = pytest.importorskip("redis")
    client = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        client.ping()
    except Exception:
        _unreachable(f"Redis at {REDIS_URL}")
    return client


@pytest.fixture(scope="module")
def pg_conn():
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        conn = psycopg2.connect(DATABASE_URL)
    except Exception:
        _unreachable(f"PostgreSQL at {DATABASE_URL}")
        return  # unreachable (skip/fail raises); proves conn is bound at yield
    yield conn
    conn.close()


def test_malicious_execve_becomes_node_alert(redis_client, pg_conn):
    from node_collector import NodeCollector
    from node_consumer import NodeConsumer
    from node_scoring import RuleScorer

    marker = uuid.uuid4().hex
    stream = f"node:events:test:{marker}"
    group = f"node-detector-test-{marker}"

    collector = NodeCollector(redis_client, stream=stream)
    audit_lines = [
        f"type=SYSCALL msg=audit(1700000000.1:1): syscall=59 pid=4242 uid=0 "
        f'comm="nc" exe="/usr/bin/nc" key="exec-{marker}"',
        'type=EXECVE msg=audit(1700000000.1:1): argc=3 a0="nc" a1="-e" a2="/bin/sh"',
    ]
    assert collector.feed_lines(audit_lines) == 1

    consumer = NodeConsumer(
        redis_client, RuleScorer(), stream=stream, group=group, consumer="test"
    )
    consumer.ensure_group()
    written = consumer.process_once(pg_conn, block_ms=1000, count=10)
    assert written == 1

    try:
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT severity, comm, summary FROM node_alerts "
                "WHERE detail->>'raw' LIKE %s ORDER BY id DESC LIMIT 1",
                (f"%{marker}%",),
            )
            row = cur.fetchone()
        assert row is not None
        assert row[0] in ("high", "critical")
        assert row[1] == "nc"
    finally:
        with pg_conn.cursor() as cur:
            cur.execute(
                "DELETE FROM node_alerts WHERE detail->>'raw' LIKE %s",
                (f"%{marker}%",),
            )
        pg_conn.commit()
        redis_client.delete(stream)
