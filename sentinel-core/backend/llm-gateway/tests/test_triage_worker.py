"""Tests for the auto-triage worker (deterministic: fake DB + fake copilot).

The worker is the Month-2 spine link: it polls ``node_alerts`` for rows that
have no triage yet, runs the grounded copilot on each, stores the cited triage
in ``node_alert_triage``, and (for high/critical alerts) drafts a signed
reversible proposal for a HUMAN to confirm. It never executes enforcement.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace


from copilot import CopilotResult
from proposals import ProposalError
from triage_worker import ALERT_COLS, TriageWorker

# --- fake DB ----------------------------------------------------------------


def _alert_row(
    id=2,
    severity="critical",
    comm="nc",
    exe="/usr/bin/nc",
    hostname="host-1",
    summary="offensive tool 'nc'",
):
    return (
        id,
        f"uuid-{id}",
        "execve",
        severity,
        Decimal("0.95"),
        4242,
        0,
        comm,
        exe,
        hostname,
        "1.0:1",
        summary,
        "new",
        datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
    )


class FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._conn.executed.append((" ".join(sql.split()), params))
        self._sql = sql

    def fetchall(self):
        return self._conn.select_rows


class FakeConn:
    def __init__(self, select_rows=None):
        self.select_rows = list(select_rows or [])
        self.executed = []
        self.commits = 0
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


# --- fake copilot stack -------------------------------------------------------


class FakeCopilot:
    def __init__(self, results):
        self._results = list(results)
        self.runs = []

    def run(self, system, user_message, prefetched=None):
        self.runs.append(
            {"system": system, "user_message": user_message, "prefetched": prefetched}
        )
        out = self._results.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


class FakeRegistry:
    def __init__(self, propose_error=None):
        self.executed = []
        self.propose_error = propose_error

    def execute(self, name, tool_input):
        self.executed.append((name, tool_input))
        if self.propose_error is not None:
            raise self.propose_error
        return {
            "tool": name,
            "ok": True,
            "result": {
                "proposal_id": "proposal:abc123",
                "executed": False,
                "reversible": True,
                "entity_id": tool_input["entity_id"],
                "action_type": tool_input["action_type"],
                "ttl_seconds": tool_input["ttl_seconds"],
                "rationale": tool_input["rationale"],
                "signature": "sig",
            },
            "record_ids": ["proposal:abc123"],
        }


def _grounded(alert_id=2):
    rid = f"node_alert:{alert_id}"
    return CopilotResult(
        text=f"Reverse shell tooling executed [{rid}]. Quarantine advised.",
        grounded=True,
        record_ids=[rid],
        citation_provenance={rid: "deadbeef"},
    )


def _worker(conn, copilot, registry=None, **kw):
    registry = registry if registry is not None else FakeRegistry()
    ctx = SimpleNamespace(copilot=copilot, registry=registry)
    kw.setdefault(
        "heartbeat_path", os.path.join(tempfile.gettempdir(), "test-triage-hb")
    )
    return TriageWorker(
        db_connect=lambda: conn,
        context_factory=lambda: ctx,
        **kw,
    ), registry


def _upserts(conn):
    return [
        (sql, p) for sql, p in conn.executed if "INSERT INTO node_alert_triage" in sql
    ]


# --- tests --------------------------------------------------------------------


def test_poll_once_stores_grounded_triage_with_citations_and_proposal():
    conn = FakeConn(select_rows=[_alert_row(id=2, severity="critical")])
    copilot = FakeCopilot([_grounded(2)])
    worker, registry = _worker(conn, copilot)

    n = worker.poll_once(conn)

    assert n == 1
    # The copilot was grounded deterministically on THIS alert.
    prefetched = copilot.runs[0]["prefetched"]
    assert prefetched[0]["record_ids"] == ["node_alert:2"]
    assert prefetched[0]["ok"] is True
    # The stored row carries the cited triage.
    (sql, params) = _upserts(conn)[0]
    row = dict(zip(worker.upsert_cols, params))
    assert row["alert_id"] == 2
    assert row["status"] == "triaged"
    assert row["grounded"] is True
    assert "node_alert:2" in json.loads(row["citations"])
    assert json.loads(row["citation_provenance"]) == {"node_alert:2": "deadbeef"}
    proposal = json.loads(row["proposal"])
    assert proposal["executed"] is False
    assert proposal["reversible"] is True
    assert conn.commits >= 1


def test_high_and_critical_get_proposals_medium_does_not():
    rows = [
        _alert_row(id=1, severity="critical"),
        _alert_row(id=2, severity="high"),
        _alert_row(id=3, severity="medium"),
    ]
    conn = FakeConn(select_rows=rows)
    copilot = FakeCopilot([_grounded(1), _grounded(2), _grounded(3)])
    worker, registry = _worker(conn, copilot)

    n = worker.poll_once(conn)

    assert n == 3
    proposed = [
        i for name, i in registry.executed if name == "propose_reversible_action"
    ]
    assert len(proposed) == 2
    stored = [dict(zip(worker.upsert_cols, p)) for _sql, p in _upserts(conn)]
    assert json.loads(stored[0]["proposal"]) is not None
    assert json.loads(stored[1]["proposal"]) is not None
    assert json.loads(stored[2]["proposal"]) is None


def test_ungrounded_triage_is_marked_failed_for_retry():
    conn = FakeConn(select_rows=[_alert_row(id=5)])
    copilot = FakeCopilot(
        [CopilotResult(text="fallback", grounded=False, reason="no citation")]
    )
    worker, registry = _worker(conn, copilot)

    n = worker.poll_once(conn)

    assert n == 0
    row = dict(zip(worker.upsert_cols, _upserts(conn)[0][1]))
    assert row["status"] == "failed"
    assert row["grounded"] is False
    assert "no citation" in (row["error"] or "")
    # A failed triage must never carry a proposal.
    assert json.loads(row["proposal"]) is None
    assert registry.executed == []


def test_copilot_exception_marks_transient_error_and_continues_batch():
    # Infrastructure exceptions (LLM down, network) are a different failure
    # class from ungrounded output: they get status 'error' and are retried
    # indefinitely with backoff, so an outage never permanently abandons
    # triage for the alerts raised during it.
    rows = [_alert_row(id=1), _alert_row(id=2)]
    conn = FakeConn(select_rows=rows)
    copilot = FakeCopilot([RuntimeError("ollama down"), _grounded(2)])
    worker, _ = _worker(conn, copilot)

    n = worker.poll_once(conn)

    assert n == 1
    stored = [dict(zip(worker.upsert_cols, p)) for _sql, p in _upserts(conn)]
    assert stored[0]["status"] == "error"
    assert "ollama down" in stored[0]["error"]
    assert stored[1]["status"] == "triaged"


def test_proposal_entity_id_is_sanitized_hostname():
    rows = [
        _alert_row(id=1, hostname="web-01.local"),
        _alert_row(id=2, hostname="bad host!"),
        _alert_row(id=3, hostname=None),
    ]
    conn = FakeConn(select_rows=rows)
    copilot = FakeCopilot([_grounded(1), _grounded(2), _grounded(3)])
    worker, registry = _worker(conn, copilot)

    worker.poll_once(conn)

    entities = [i["entity_id"] for _n, i in registry.executed]
    assert entities[0] == "web-01.local"
    assert entities[1] == "badhost"
    assert entities[2] == "node"


def test_signer_failure_keeps_triage_and_drops_proposal():
    conn = FakeConn(select_rows=[_alert_row(id=7)])
    copilot = FakeCopilot([_grounded(7)])
    registry = FakeRegistry(propose_error=ProposalError("no signing key configured"))
    worker, _ = _worker(conn, copilot, registry=registry)

    n = worker.poll_once(conn)

    assert n == 1
    row = dict(zip(worker.upsert_cols, _upserts(conn)[0][1]))
    assert row["status"] == "triaged"
    assert json.loads(row["proposal"]) is None
    assert "no signing key" in (row["error"] or "")


def test_fetch_untriaged_passes_attempts_and_batch_limits():
    conn = FakeConn(select_rows=[_alert_row(id=9)])
    copilot = FakeCopilot([_grounded(9)])
    worker, _ = _worker(
        conn, copilot, batch_size=7, max_attempts=4, retry_base=20, retry_cap=600
    )

    alerts = worker.fetch_untriaged(conn)

    assert [a["id"] for a in alerts] == [9]
    assert set(ALERT_COLS) <= set(alerts[0].keys())
    sql, params = conn.executed[0]
    assert "node_alert_triage" in sql
    assert params == (4, 600, 20, 7)


def test_fetch_retries_transient_errors_with_capped_backoff():
    # 'error' rows (infra failures) re-qualify only after an exponential
    # backoff window (base * 2^attempts, capped) — never permanently dropped.
    conn = FakeConn(select_rows=[])
    copilot = FakeCopilot([])
    worker, _ = _worker(conn, copilot)

    worker.fetch_untriaged(conn)

    sql, _params = conn.executed[0]
    assert "t.status = 'error'" in sql
    assert "POWER(2, t.attempts)" in sql
    assert "LEAST" in sql


def test_fetch_orders_fresh_alerts_before_retries():
    # A handful of perpetually erroring rows must not starve brand-new
    # alerts out of the batch: untriaged rows sort first.
    conn = FakeConn(select_rows=[])
    copilot = FakeCopilot([])
    worker, _ = _worker(conn, copilot)

    worker.fetch_untriaged(conn)

    sql, _params = conn.executed[0]
    assert "ORDER BY (t.id IS NOT NULL), a.id" in sql


def test_poll_once_heartbeats_after_each_alert(tmp_path):
    # A CPU-bound local model can take minutes per alert; the healthcheck
    # probes heartbeat freshness, so the worker must beat inside the batch,
    # not only at cycle end.
    heartbeat = tmp_path / "hb"
    conn = FakeConn(select_rows=[_alert_row(id=1), _alert_row(id=2)])
    copilot = FakeCopilot([_grounded(1), _grounded(2)])
    ctx = SimpleNamespace(copilot=copilot, registry=FakeRegistry())
    worker = TriageWorker(
        db_connect=lambda: conn,
        context_factory=lambda: ctx,
        heartbeat_path=str(heartbeat),
    )

    worker.poll_once(conn)

    assert heartbeat.exists()


def test_cycle_skips_polling_when_inference_disabled(tmp_path):
    heartbeat = tmp_path / "hb"
    connects = []

    def _connect():
        connects.append(1)
        return FakeConn()

    worker = TriageWorker(
        db_connect=_connect,
        context_factory=lambda: SimpleNamespace(
            copilot=FakeCopilot([]), registry=FakeRegistry()
        ),
        inference_gate=lambda: False,
        heartbeat_path=str(heartbeat),
    )

    n = worker.cycle()

    assert n == 0
    assert connects == []
    assert heartbeat.exists()


def test_cycle_polls_and_heartbeats_when_enabled(tmp_path):
    heartbeat = tmp_path / "hb"
    conn = FakeConn(select_rows=[_alert_row(id=2)])
    ctx = SimpleNamespace(copilot=FakeCopilot([_grounded(2)]), registry=FakeRegistry())
    worker = TriageWorker(
        db_connect=lambda: conn,
        context_factory=lambda: ctx,
        inference_gate=lambda: True,
        heartbeat_path=str(heartbeat),
    )

    n = worker.cycle()

    assert n == 1
    assert heartbeat.exists()
    assert conn.closed is True


def test_cycle_survives_db_connect_failure(tmp_path):
    heartbeat = tmp_path / "hb"

    def _connect():
        raise RuntimeError("pg down")

    worker = TriageWorker(
        db_connect=_connect,
        context_factory=lambda: SimpleNamespace(
            copilot=FakeCopilot([]), registry=FakeRegistry()
        ),
        inference_gate=lambda: True,
        heartbeat_path=str(heartbeat),
    )

    n = worker.cycle()

    assert n == 0
    assert heartbeat.exists()
