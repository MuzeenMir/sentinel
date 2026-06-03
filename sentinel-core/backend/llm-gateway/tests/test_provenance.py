"""Tests for citation provenance (hash binding + freshness)."""

from provenance import (
    citation_hashes,
    provenance_from_results,
    source_hash,
    verify_citations,
)


def _results():
    return [
        {
            "tool": "get_threat_score",
            "ok": True,
            "result": {"score": 0.9},
            "record_ids": ["score:s1"],
        },
        {
            "tool": "get_audit_events",
            "ok": True,
            "result": {"events": [{"id": "e1"}]},
            "record_ids": ["audit:e1"],
        },
        {
            "tool": "get_enforcement_state",
            "ok": False,  # failed fetch -> no provenance
            "result": None,
            "record_ids": ["enforce:h1"],
        },
    ]


def test_source_hash_is_stable_and_content_sensitive():
    assert source_hash({"a": 1, "b": 2}) == source_hash({"b": 2, "a": 1})
    assert source_hash({"a": 1}) != source_hash({"a": 2})


def test_provenance_skips_failed_results_and_binds_hashes():
    prov = provenance_from_results(_results(), now=1000)
    assert set(prov) == {"score:s1", "audit:e1"}  # failed enforce skipped
    assert prov["score:s1"].hash == source_hash({"score": 0.9})
    assert prov["score:s1"].issued_at == 1000


def test_verify_accepts_known_fresh_citations():
    prov = provenance_from_results(_results(), now=1000)
    res = verify_citations(["score:s1", "audit:e1"], prov, now=1000)
    assert res.ok is True


def test_verify_rejects_unverifiable_citation():
    prov = provenance_from_results(_results(), now=1000)
    res = verify_citations(["score:s1", "audit:FORGED"], prov, now=1000)
    assert res.ok is False
    assert res.unverifiable_ids == ["audit:FORGED"]


def test_verify_rejects_stale_citation():
    prov = provenance_from_results(_results(), now=1000)
    res = verify_citations(
        ["score:s1"], prov, now=1000 + 86_401, freshness_seconds=86_400
    )
    assert res.ok is False
    assert res.stale_ids == ["score:s1"]


def test_citation_hashes_returns_id_to_hash_for_cited_only():
    prov = provenance_from_results(_results(), now=1000)
    hashes = citation_hashes(["score:s1"], prov)
    assert hashes == {"score:s1": source_hash({"score": 0.9})}
