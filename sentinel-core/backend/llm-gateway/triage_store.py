"""Read model for the approval queue.

Lists the reversible proposals the auto-triage worker drafted and stored in
``node_alert_triage`` (JSONB), joined with their originating ``node_alerts``
context, so the admin console can surface them for one-click human
confirmation. Read-only: nothing here mutates a proposal or executes anything.

Tenancy: ``node_alerts`` and ``node_alert_triage`` are single-host node-path
tables with **no ``tenant_id`` column** — the offline node is a single tenant
(``DEFAULT_TENANT_ID=1``). There is therefore no tenant dimension to scope this
read on, and no cross-tenant boundary to cross; this mirrors the already-shipped
``get_node_alerts`` grounding tool in ``tools.py``, which reads the same tables
the same way. The authenticated api-gateway proxy remains the access boundary.
"""

from __future__ import annotations

import json
from typing import Any

PENDING_COLS = (
    "alert_id",
    "severity",
    "comm",
    "exe",
    "hostname",
    "summary",
    "triage_text",
    "citations",
    "proposal",
    "created_at",
)

_PENDING_MAX = 200

_SELECT_SQL = (
    "SELECT t.alert_id, a.severity, a.comm, a.exe, a.hostname, a.summary, "
    "t.triage_text, t.citations, t.proposal, t.created_at "
    "FROM node_alert_triage t "
    "JOIN node_alerts a ON a.id = t.alert_id "
    "WHERE t.proposal IS NOT NULL AND t.status = 'triaged' "
    "ORDER BY t.alert_id DESC LIMIT %s"
)


def _coerce(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _load_json(value: Any) -> Any:
    """psycopg2 returns JSONB as a parsed object; tests inject JSON strings."""
    if isinstance(value, str):
        return json.loads(value)
    return value


def list_pending_proposals(conn, limit: int = 50) -> list[dict]:
    limit = max(1, min(int(limit), _PENDING_MAX))
    with conn.cursor() as cur:
        cur.execute(_SELECT_SQL, (limit,))
        rows = cur.fetchall()
    out: list[dict] = []
    for row in rows:
        item = dict(zip(PENDING_COLS, row))
        item["citations"] = _load_json(item["citations"])
        item["proposal"] = _load_json(item["proposal"])
        item["created_at"] = _coerce(item["created_at"])
        out.append(item)
    return out
