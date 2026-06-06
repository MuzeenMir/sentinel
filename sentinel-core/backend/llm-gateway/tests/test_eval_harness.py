"""Tests for the copilot eval harness."""

from types import SimpleNamespace

from evals.harness import evaluate, load_golden


def _result(text, grounded=True, record_ids=None, proposals=None):
    return SimpleNamespace(
        text=text,
        grounded=grounded,
        record_ids=record_ids or [],
        proposals=proposals or [],
    )


GOLDENS = [
    {"incident_id": "i1", "entity_id": "h1", "valid_record_ids": ["score:s1"]},
    {"incident_id": "i2", "entity_id": "h2", "valid_record_ids": ["audit:e2"]},
]


def test_load_golden_reads_bundled_dataset():
    goldens = load_golden()
    assert len(goldens) >= 1
    assert "valid_record_ids" in goldens[0]


def test_all_grounded_passes_with_zero_hallucination():
    def runner(g):
        rid = g["valid_record_ids"][0]
        return _result(f"finding [{rid}]", record_ids=[rid])

    report = evaluate(runner, GOLDENS)
    assert report.total == 2
    assert report.hallucinations == 0
    assert report.residual_hallucination_rate == 0.0
    assert report.passed is True


def test_hallucinated_citation_is_counted_and_fails():
    def runner(g):
        return _result("finding [score:GHOST]", record_ids=[])

    report = evaluate(runner, GOLDENS)
    assert report.hallucinations == 2
    assert report.residual_hallucination_rate == 1.0
    assert report.passed is False


def test_execution_violation_fails_even_if_grounded():
    def runner(g):
        rid = g["valid_record_ids"][0]
        return _result(
            f"did it [{rid}]",
            record_ids=[rid],
            proposals=[{"proposal_id": "p", "executed": True}],
        )

    report = evaluate(runner, GOLDENS)
    assert report.exec_violations == 2
    assert report.passed is False


def test_residual_rate_partial():
    calls = {"n": 0}

    def runner(g):
        calls["n"] += 1
        if calls["n"] == 1:
            return _result("bad [x:GHOST]", record_ids=[])
        rid = g["valid_record_ids"][0]
        return _result(f"ok [{rid}]", record_ids=[rid])

    report = evaluate(runner, GOLDENS)
    assert report.residual_hallucination_rate == 0.5
