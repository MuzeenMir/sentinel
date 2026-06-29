import json
import fakeredis
from node_consumer import NodeConsumer
from node_scoring import RuleScorer


class FakeCursor:
    def __init__(self, sink):
        self.sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.sink.append((sql, params))


class FakeConn:
    def __init__(self):
        self.calls = []
        self.commits = 0

    def cursor(self):
        return FakeCursor(self.calls)

    def commit(self):
        self.commits += 1


def _consumer():
    r = fakeredis.FakeStrictRedis(decode_responses=True)
    c = NodeConsumer(
        r, RuleScorer(), stream="node:events", group="node-detector", consumer="ai-1"
    )
    c.ensure_group()
    return r, c


_THREAT_PAYLOAD = {
    "event_type": "execve",
    "comm": "nc",
    "exe": "/usr/bin/nc",
    "args": ["nc", "-e", "/bin/sh"],
    "pid": 7,
    "uid": 0,
    "hostname": "h",
    "timestamp": "2026-06-27T00:00:00+00:00",
    "raw": "x",
}


def test_threat_event_inserts_alert_and_acks():
    r, c = _consumer()
    r.xadd("node:events", {"event": json.dumps(_THREAT_PAYLOAD)})
    conn = FakeConn()
    written = c.process_once(conn, block_ms=1, count=10)
    assert written == 1
    assert conn.commits == 1
    sql, params = conn.calls[0]
    assert "insert into node_alerts" in sql.lower()
    # comm is 6th param (index 5); status is 12th param (index 11)
    assert len(params) == 12
    assert params[5] == "nc"
    # acked -> no pending
    pending = r.xpending("node:events", "node-detector")
    assert pending["pending"] == 0


def test_benign_event_writes_no_alert_but_acks():
    r, c = _consumer()
    r.xadd(
        "node:events",
        {
            "event": json.dumps(
                {
                    "event_type": "execve",
                    "comm": "ls",
                    "exe": "/usr/bin/ls",
                    "args": ["ls"],
                    "pid": 9,
                    "uid": 0,
                    "hostname": "h",
                    "timestamp": "2026-06-27T00:00:00+00:00",
                    "raw": "x",
                }
            )
        },
    )
    conn = FakeConn()
    written = c.process_once(conn, block_ms=1, count=10)
    assert written == 0
    assert conn.calls == []
    pending = r.xpending("node:events", "node-detector")
    assert pending["pending"] == 0


def test_poison_pill_acked_and_skipped():
    """Malformed/missing event field must be acked and skipped; loop must not crash."""
    r, c = _consumer()
    # malformed JSON
    r.xadd("node:events", {"event": "{not json"})
    # missing event field entirely
    r.xadd("node:events", {"other": "x"})
    # valid benign event (must still be processed normally)
    r.xadd(
        "node:events",
        {
            "event": json.dumps(
                {
                    "event_type": "execve",
                    "comm": "ls",
                    "exe": "/usr/bin/ls",
                    "args": ["ls"],
                    "pid": 1,
                    "uid": 0,
                    "hostname": "h",
                    "timestamp": "2026-06-27T00:00:00+00:00",
                    "raw": "x",
                }
            )
        },
    )
    conn = FakeConn()
    written = c.process_once(conn, block_ms=1, count=10)
    assert written == 0  # benign → no alert
    # all 3 messages acked despite the two bad ones
    pending = r.xpending("node:events", "node-detector")
    assert pending["pending"] == 0


def test_db_failure_leaves_message_pending_and_raises():
    """DB failure on INSERT must propagate (not swallowed) and NOT ack the message."""
    r, c = _consumer()
    r.xadd(
        "node:events",
        {
            "event": json.dumps(
                {
                    "event_type": "execve",
                    "comm": "nc",
                    "exe": "/usr/bin/nc",
                    "args": ["nc", "-e", "/bin/sh"],
                    "pid": 7,
                    "uid": 0,
                    "hostname": "h",
                    "timestamp": "2026-06-27T00:00:00+00:00",
                    "raw": "x",
                }
            )
        },
    )
    conn = FakeConn()

    def boom():
        raise Exception("PG down")

    conn.commit = boom
    import pytest

    with pytest.raises(Exception, match="PG down"):
        c.process_once(conn, block_ms=1)
    pending = r.xpending("node:events", "node-detector")
    assert pending["pending"] == 1  # threat message must NOT be acked


def test_bytes_field_decode_writes_alert():
    """Bytes-mode redis (no decode_responses) must decode the event field correctly."""
    r = fakeredis.FakeStrictRedis()  # bytes responses, NOT decode_responses=True
    c = NodeConsumer(
        r, RuleScorer(), stream="node:events", group="node-detector", consumer="ai-1"
    )
    c.ensure_group()
    r.xadd("node:events", {"event": json.dumps(_THREAT_PAYLOAD)})
    conn = FakeConn()
    written = c.process_once(conn, block_ms=1, count=10)
    assert written == 1
    pending = r.xpending("node:events", "node-detector")
    assert pending["pending"] == 0
