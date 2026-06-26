"""Real-Postgres checks for the D4 per-event audit chain. Marked `integration`;
skipped unless AUDIT_TEST_DATABASE_URL points at a migrated audit_log.

DB: sentinel_db  role: sentinel_app  (see docker-compose.ci.yml for the
host-published 5432 port used in the integration-compose CI job).
"""

import importlib.util
import os
from pathlib import Path

import pytest

DB_URL = os.environ.get("AUDIT_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DB_URL, reason="AUDIT_TEST_DATABASE_URL unset"),
]

REPO_CORE = Path(__file__).resolve().parents[2]


def _load(mod, rel):
    spec = importlib.util.spec_from_file_location(mod, REPO_CORE / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _conn():
    import psycopg2

    return psycopg2.connect(DB_URL)


def test_plpgsql_genesis_matches_python():
    """The plpgsql genesis digest (computed inline in SQL) must equal chain_genesis(5)."""
    am = _load("audit_merkle", "backend/audit_merkle.py")
    with _conn() as c, c.cursor() as cur:
        # Replicate: SHA-256(_CHAIN_GENESIS_DOMAIN || "5") in SQL.
        # _CHAIN_GENESIS_DOMAIN = b"sentinel.audit.chain.genesis.v1\x00"
        # hex: 73656e74696e656c2e61756469742e636861696e2e67656e657369732e763100
        cur.execute(
            "SELECT encode(digest(decode(%s,'hex') || convert_to(%s,'UTF8'),'sha256'),'hex')",
            (
                "73656e74696e656c2e61756469742e636861696e2e67656e657369732e763100",
                "5",
            ),
        )
        assert cur.fetchone()[0] == am.chain_genesis(5)


def test_trigger_chains_inserts_per_tenant():
    """The DB trigger sets prev_event_hash per-tenant; chain must be intact."""
    import audit_logger as al  # backend on sys.path under pytest rootdir

    am = _load("audit_merkle", "backend/audit_merkle.py")
    vac = _load("verify_audit_chain", "scripts/verify_audit_chain.py")

    # Point audit_logger at the same DB as this test.
    os.environ["DATABASE_URL"] = DB_URL

    # Write two events for tenant 4242 (high id — unlikely to collide with fixtures).
    al.audit_log(al.AuditCategory.SYSTEM, "d4_test_a", tenant_id=4242)
    al.audit_log(al.AuditCategory.SYSTEM, "d4_test_b", tenant_id=4242)

    with _conn() as c, c.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id','4242',true)")
        cur.execute(
            "SELECT id, tenant_id, category, action, resource_id, user_id, "
            "timestamp, details, event_hash, prev_event_hash "
            "FROM audit_log WHERE tenant_id=4242 ORDER BY id"
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]

    assert len(rows) >= 2, f"expected >=2 rows for tenant 4242, got {len(rows)}"
    assert rows[0]["prev_event_hash"] == am.chain_genesis(4242), (
        f"first row prev_event_hash {rows[0]['prev_event_hash']!r} "
        f"!= genesis {am.chain_genesis(4242)!r}"
    )
    assert rows[1]["prev_event_hash"] == rows[0]["event_hash"], (
        f"second row prev_event_hash {rows[1]['prev_event_hash']!r} "
        f"!= first event_hash {rows[0]['event_hash']!r}"
    )
    assert vac.find_chain_breaks(rows) == [], "chain breaks detected"
