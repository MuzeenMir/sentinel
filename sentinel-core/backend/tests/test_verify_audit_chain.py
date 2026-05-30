"""Tests for the audit-ledger verifier core (wedge #3, auditor tool).

Pure functions only — no DB. Rows are dicts shaped like the audit_log columns.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

from audit_merkle import canonical_event_digest  # noqa: E402
from verify_audit_chain import (  # noqa: E402
    recompute_row_digest,
    find_row_tampers,
    compute_daily_roots,
    chain_roots,
    diff_published,
)


def _row(rid, ts, action="login_success", tenant=7, details=None, event_hash=None):
    details = details if details is not None else {"actor": "user:1"}
    row = dict(
        id=rid,
        tenant_id=tenant,
        category="auth",
        action=action,
        resource_id="auth-service",
        user_id=1,
        timestamp=ts,
        details=details,
    )
    row["event_hash"] = event_hash or canonical_event_digest(
        tenant_id=tenant,
        category="auth",
        action=action,
        resource_id="auth-service",
        user_id=1,
        timestamp=ts,
        details=details,
    )
    return row


def test_recompute_row_digest_matches_canonical():
    r = _row(1, "2026-05-30T01:00:00Z")
    assert recompute_row_digest(r) == r["event_hash"]


def test_no_tampers_for_consistent_rows():
    rows = [_row(1, "2026-05-30T01:00:00Z"), _row(2, "2026-05-30T02:00:00Z")]
    assert find_row_tampers(rows) == []


def test_detects_content_tamper_with_stale_hash():
    r = _row(1, "2026-05-30T01:00:00Z")
    r["action"] = "logout"  # mutate content, leave stored event_hash stale
    tampers = find_row_tampers([r])
    assert len(tampers) == 1 and tampers[0]["id"] == 1


def test_compute_daily_roots_groups_by_utc_date():
    rows = [
        _row(1, "2026-05-30T01:00:00Z"),
        _row(2, "2026-05-30T23:00:00Z"),
        _row(3, "2026-05-31T00:30:00Z"),
    ]
    roots = compute_daily_roots(rows)
    assert [r["date"] for r in roots] == ["2026-05-30", "2026-05-31"]
    assert roots[0]["count"] == 2 and roots[1]["count"] == 1


def test_daily_root_changes_when_event_hash_changes():
    rows = [_row(1, "2026-05-30T01:00:00Z"), _row(2, "2026-05-30T02:00:00Z")]
    before = compute_daily_roots(rows)[0]["merkle_root"]
    rows[1]["event_hash"] = "0" * 64
    after = compute_daily_roots(rows)[0]["merkle_root"]
    assert before != after


def test_chain_roots_cascades_on_earlier_day_tamper():
    rows = [_row(1, "2026-05-30T01:00:00Z"), _row(2, "2026-05-31T01:00:00Z")]
    chained = chain_roots(compute_daily_roots(rows))
    day2_root_before = chained[1]["root"]

    rows[0]["event_hash"] = "f" * 64  # tamper day 1
    chained2 = chain_roots(compute_daily_roots(rows))
    assert chained2[1]["root"] != day2_root_before  # cascade through prev_root


def test_diff_published_detects_divergence():
    rows = [_row(1, "2026-05-30T01:00:00Z")]
    computed = chain_roots(compute_daily_roots(rows))
    published = [{"date": c["date"], "root": c["root"]} for c in computed]
    assert diff_published(computed, published) == []

    published[0]["root"] = "deadbeef"
    div = diff_published(computed, published)
    assert len(div) == 1 and div[0]["date"] == "2026-05-30"
