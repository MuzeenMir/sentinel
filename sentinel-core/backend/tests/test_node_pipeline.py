"""Real node-path e2e: auditd event -> Redis stream -> ai-engine -> node_alerts.

Requires a live Redis and PostgreSQL (the local docker-compose stack). Skips
cleanly when they are unreachable, like test_e2e_pipeline.py.
"""
import json
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ai-engine"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data-collector"))

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel"
)


@pytest.fixture(scope="module")
def redis_client():
    redis = pytest.importorskip("redis")
    client = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        client.ping()
    except Exception:
        pytest.skip(f"Redis not reachable at {REDIS_URL}")
    return client


@pytest.fixture(scope="module")
def pg_conn():
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        conn = psycopg2.connect(DATABASE_URL)
    except Exception:
        pytest.skip(f"PostgreSQL not reachable at {DATABASE_URL}")
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
        f'type=SYSCALL msg=audit(1700000000.1:1): syscall=59 pid=4242 uid=0 '
        f'comm="nc" exe="/usr/bin/nc" key="exec-{marker}"',
        'type=EXECVE msg=audit(1700000000.1:1): argc=3 a0="nc" a1="-e" a2="/bin/sh"',
    ]
    assert collector.feed_lines(audit_lines) == 1

    consumer = NodeConsumer(redis_client, RuleScorer(), stream=stream,
                            group=group, consumer="test")
    consumer.ensure_group()
    written = consumer.process_once(pg_conn, block_ms=1000, count=10)
    assert written == 1

    with pg_conn.cursor() as cur:
        cur.execute(
            "SELECT severity, comm, summary FROM node_alerts "
            "WHERE source_event_id IS NOT NULL AND comm = 'nc' "
            "ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()
    assert row is not None
    assert row[0] in ("high", "critical")
    assert row[1] == "nc"

    # cleanup
    redis_client.delete(stream)
    pg_conn.rollback()
