"""C4 — citation content-integrity: reject citations whose source was mutated.

Time-freshness (issued_at age) already exists. This adds *content* integrity:
if a re-fetch of the cited record hashes differently than what was captured when
the answer was formed, the citation is no longer trustworthy and must be
rejected (the source changed under us — tamper or drift), independent of age.
"""

from provenance import provenance_from_results, source_hash, verify_citations


def _results():
    return [
        {
            "tool": "score",
            "ok": True,
            "result": {"score": 0.9},
            "record_ids": ["score:s1"],
        },
        {
            "tool": "audit",
            "ok": True,
            "result": {"events": ["e1"]},
            "record_ids": ["audit:e1"],
        },
    ]


def test_verify_accepts_unchanged_source_content():
    prov = provenance_from_results(_results(), now=1000)
    current = {"score:s1": source_hash({"score": 0.9})}
    res = verify_citations(["score:s1"], prov, now=1000, current_hashes=current)
    assert res.ok is True
    assert res.mutated_ids == []


def test_verify_rejects_mutated_source_content():
    prov = provenance_from_results(_results(), now=1000)
    # the cited record's content changed after capture (0.9 -> 0.1)
    current = {"score:s1": source_hash({"score": 0.1})}
    res = verify_citations(["score:s1"], prov, now=1000, current_hashes=current)
    assert res.ok is False
    assert res.mutated_ids == ["score:s1"]
    assert "mutat" in (res.reason or "").lower()


def test_mutation_check_is_opt_in():
    # without current_hashes, behavior is unchanged (no mutation checking)
    prov = provenance_from_results(_results(), now=1000)
    res = verify_citations(["score:s1"], prov, now=1000)
    assert res.ok is True
    assert res.mutated_ids == []
