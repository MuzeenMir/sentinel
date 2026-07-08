"""Tests for the pending-proposal read model (approval queue backend)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from triage_store import PENDING_COLS, list_pending_proposals


def _row(
    alert_id=2,
    severity="critical",
    comm="nc",
    exe="/usr/bin/nc",
    hostname="host-1",
    summary="offensive tool 'nc'",
    triage_text="Reverse shell tooling [node_alert:2].",
    citations=None,
    proposal=None,
    created_at=None,
):
    return (
        alert_id,
        severity,
        comm,
        exe,
        hostname,
        summary,
        triage_text,
        json.dumps(citations if citations is not None else ["node_alert:2"]),
        json.dumps(
            proposal
            if proposal is not None
            else {
                "proposal_id": "proposal:abc",
                "action_type": "quarantine",
                "reversible": True,
                "executed": False,
                "signature": "sig",
            }
        ),
        created_at or datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
    )


class FakeCursor:
    def __init__(self, rows):
        self._rows = rows
        self.executed = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed = (sql, params)

    def fetchall(self):
        return self._rows


class FakeConn:
    def __init__(self, rows):
        self.cur = FakeCursor(rows)

    def cursor(self):
        return self.cur


def test_lists_pending_proposals_with_alert_context():
    conn = FakeConn([_row(alert_id=2)])

    out = list_pending_proposals(conn, limit=25)

    assert len(out) == 1
    item = out[0]
    assert item["alert_id"] == 2
    assert item["severity"] == "critical"
    assert item["comm"] == "nc"
    assert item["triage_text"] == "Reverse shell tooling [node_alert:2]."
    assert item["citations"] == ["node_alert:2"]
    # The signed proposal is returned as an object the UI can confirm as-is.
    assert item["proposal"]["proposal_id"] == "proposal:abc"
    assert item["proposal"]["executed"] is False
    assert item["proposal"]["reversible"] is True
    assert "created_at" in item


def test_created_at_is_serialized_to_iso_string():
    conn = FakeConn([_row()])
    out = list_pending_proposals(conn)
    assert out[0]["created_at"] == "2026-07-07T12:00:00+00:00"


def test_query_filters_to_triaged_rows_with_a_proposal():
    conn = FakeConn([])
    list_pending_proposals(conn, limit=10)
    sql, params = conn.cur.executed
    flat = " ".join(sql.split())
    assert "FROM node_alert_triage" in flat
    assert "proposal IS NOT NULL" in flat
    assert "status = 'triaged'" in flat
    # newest first, bounded
    assert "ORDER BY t.alert_id DESC" in flat
    assert params == (10,)


def test_limit_is_clamped_to_a_sane_maximum():
    conn = FakeConn([])
    list_pending_proposals(conn, limit=10_000)
    _sql, params = conn.cur.executed
    assert params == (200,)


def test_all_pending_cols_are_mapped():
    conn = FakeConn([_row()])
    out = list_pending_proposals(conn)
    assert set(PENDING_COLS) <= set(out[0].keys())
