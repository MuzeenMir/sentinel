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
    c = NodeConsumer(r, RuleScorer(), stream="node:events",
                     group="node-detector", consumer="ai-1")
    c.ensure_group()
    return r, c


def test_threat_event_inserts_alert_and_acks():
    r, c = _consumer()
    r.xadd("node:events", {"event": json.dumps(
        {"event_type": "execve", "comm": "nc", "exe": "/usr/bin/nc",
         "args": ["nc", "-e", "/bin/sh"], "pid": 7, "uid": 0,
         "hostname": "h", "timestamp": "2026-06-27T00:00:00+00:00", "raw": "x"})})
    conn = FakeConn()
    written = c.process_once(conn, block_ms=10, count=10)
    assert written == 1
    assert conn.commits == 1
    sql, params = conn.calls[0]
    assert "insert into node_alerts" in sql.lower()
    assert "nc" in params  # comm present in insert params
    # acked -> no pending
    pending = r.xpending("node:events", "node-detector")
    assert pending["pending"] == 0


def test_benign_event_writes_no_alert_but_acks():
    r, c = _consumer()
    r.xadd("node:events", {"event": json.dumps(
        {"event_type": "execve", "comm": "ls", "exe": "/usr/bin/ls",
         "args": ["ls"], "pid": 9, "uid": 0, "hostname": "h",
         "timestamp": "2026-06-27T00:00:00+00:00", "raw": "x"})})
    conn = FakeConn()
    written = c.process_once(conn, block_ms=10, count=10)
    assert written == 0
    assert conn.calls == []
    pending = r.xpending("node:events", "node-detector")
    assert pending["pending"] == 0
