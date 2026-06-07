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
    signature_failures,
    trusted_published,
    verify_published_signatures,
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


# --------------------------------------------------------------------------- #
# Cosign signature gating (C7) — a published root is only trusted if its
# detached cosign signature + certificate verify. Unsigned/forged roots are
# never used as an anchor for the chain comparison.
# --------------------------------------------------------------------------- #


def test_signature_failures_flags_invalid_and_missing():
    sig_results = [
        {"date": "2026-05-30", "valid": True, "reason": None},
        {"date": "2026-05-31", "valid": False, "reason": "signature_invalid"},
        {"date": "2026-06-01", "valid": False, "reason": "signature_missing"},
    ]
    fails = signature_failures(sig_results)
    assert [f["date"] for f in fails] == ["2026-05-31", "2026-06-01"]
    assert fails[0]["reason"] == "signature_invalid"
    assert fails[1]["reason"] == "signature_missing"


def test_trusted_published_excludes_unsigned_roots():
    published = [
        {"date": "2026-05-30", "root": "aa"},
        {"date": "2026-05-31", "root": "bb"},
    ]
    sig_results = [
        {"date": "2026-05-30", "valid": True, "reason": None},
        {"date": "2026-05-31", "valid": False, "reason": "signature_invalid"},
    ]
    trusted = trusted_published(published, sig_results)
    assert [p["date"] for p in trusted] == ["2026-05-30"]


def test_forged_root_with_bad_signature_is_not_trusted_for_divergence():
    # An attacker rewrites history AND publishes a matching root, but cannot
    # forge the cosign signature. The matching (untrusted) root must not mask
    # the tamper: trusted set is empty, and the day is a signature failure.
    rows = [_row(1, "2026-05-30T01:00:00Z")]
    computed = chain_roots(compute_daily_roots(rows))
    forged = [{"date": c["date"], "root": c["root"]} for c in computed]
    sig_results = [
        {"date": "2026-05-30", "valid": False, "reason": "signature_invalid"}
    ]

    trusted = trusted_published(forged, sig_results)
    assert trusted == []  # forged root is never trusted as an anchor
    # main() guards divergence on a non-empty trusted set; the tamper surfaces
    # as a signature failure instead of being masked by the matching forgery.
    divergences = diff_published(computed, trusted) if trusted else []
    assert divergences == []
    assert signature_failures(sig_results)[0]["date"] == "2026-05-30"


def test_verify_published_signatures_pairs_blob_sig_cert(tmp_path):
    # date1: full triple, verifier returns True  -> valid
    # date2: json + sig + cert, verifier returns False -> signature_invalid
    # date3: json only (no .sig/.pem)             -> signature_missing
    for date in ("2026-05-30", "2026-05-31", "2026-06-01"):
        (tmp_path / f"{date}.json").write_text("{}")
    for date in ("2026-05-30", "2026-05-31"):
        (tmp_path / f"{date}.json.sig").write_text("sig")
        (tmp_path / f"{date}.json.pem").write_text("cert")

    seen = []

    def fake_verify(blob, sig, cert):
        seen.append(os.path.basename(blob))
        return blob.endswith("2026-05-30.json")

    results = verify_published_signatures(str(tmp_path), verify_fn=fake_verify)
    by_date = {r["date"]: r for r in results}
    assert by_date["2026-05-30"]["valid"] is True
    assert by_date["2026-05-31"] == {
        "date": "2026-05-31",
        "valid": False,
        "reason": "signature_invalid",
    }
    assert by_date["2026-06-01"] == {
        "date": "2026-06-01",
        "valid": False,
        "reason": "signature_missing",
    }
    # verifier is only invoked when both sig + cert are present
    assert sorted(seen) == ["2026-05-30.json", "2026-05-31.json"]
