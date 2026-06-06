"""C2 — model-quality eval metrics + threshold gate.

Extends the harness with deterministic, model-agnostic metrics scored from the
runner result vs the golden label: citation precision/recall, faithfulness,
refusal-correctness (must refuse out-of-scope), and answer-relevance (expected
key facts present). ``meets_thresholds`` is the CI gate.
"""

from types import SimpleNamespace

from evals.harness import evaluate, load_golden, meets_thresholds


def test_golden_dataset_is_substantial_and_labelled():
    goldens = load_golden()
    assert len(goldens) >= 25
    ids = [g.get("incident_id") for g in goldens]
    assert all(ids) and len(set(ids)) == len(ids)  # present + unique
    for g in goldens:
        assert "valid_record_ids" in g
        # every incident is labelled: relevance facts, or an explicit refusal /
        # no-data case (empty valid ids => copilot must refuse).
        assert (
            g.get("expected_facts")
            or g.get("should_refuse")
            or not g["valid_record_ids"]
        )


def _r(text, record_ids=None, grounded=True, refused=None, proposals=None):
    ns = SimpleNamespace(
        text=text,
        grounded=grounded,
        record_ids=record_ids or [],
        proposals=proposals or [],
    )
    if refused is not None:
        ns.refused = refused
    return ns


# --- citation precision / recall -------------------------------------------


def test_citation_precision_and_recall():
    goldens = [{"incident_id": "i1", "valid_record_ids": ["a", "b"]}]

    def runner(g):
        # cites a (valid) and c (invalid): precision 1/2, recall 1/2
        return _r("see [a] and [c]", record_ids=["a", "c"])

    rep = evaluate(runner, goldens)
    assert rep.citation_precision == 0.5
    assert rep.citation_recall == 0.5


def test_citation_metrics_perfect_when_exact():
    goldens = [{"incident_id": "i1", "valid_record_ids": ["a", "b"]}]

    def runner(g):
        return _r("[a] [b]", record_ids=["a", "b"])

    rep = evaluate(runner, goldens)
    assert rep.citation_precision == 1.0
    assert rep.citation_recall == 1.0


# --- faithfulness -----------------------------------------------------------


def test_faithfulness_is_one_when_all_citations_valid():
    goldens = [{"incident_id": "i", "valid_record_ids": ["score:a"]}]

    def runner(g):
        return _r("ok [score:a]", record_ids=["score:a"])

    rep = evaluate(runner, goldens)
    assert rep.faithfulness == 1.0


def test_faithfulness_drops_with_hallucinated_citation():
    goldens = [
        {"incident_id": "i1", "valid_record_ids": ["score:a"]},
        {"incident_id": "i2", "valid_record_ids": ["audit:b"]},
    ]
    calls = {"n": 0}

    def runner(g):
        calls["n"] += 1
        if calls["n"] == 1:
            return _r("bad [score:GHOST]", record_ids=[])
        return _r("ok [audit:b]", record_ids=["audit:b"])

    rep = evaluate(runner, goldens)
    assert rep.faithfulness == 0.5


# --- refusal correctness ----------------------------------------------------


def test_refusal_correctness_rewards_refusing_no_data():
    goldens = [{"incident_id": "i", "valid_record_ids": [], "should_refuse": True}]

    def runner(g):
        return _r("No data available.", record_ids=[], refused=True)

    rep = evaluate(runner, goldens)
    assert rep.refusal_correctness == 1.0


def test_refusal_correctness_penalizes_answering_when_should_refuse():
    goldens = [{"incident_id": "i", "valid_record_ids": [], "should_refuse": True}]

    def runner(g):
        return _r("Here is analysis [x]", record_ids=["x"], refused=False)

    rep = evaluate(runner, goldens)
    assert rep.refusal_correctness == 0.0


# --- answer relevance -------------------------------------------------------


def test_answer_relevance_full_when_all_facts_present():
    goldens = [
        {
            "incident_id": "i",
            "valid_record_ids": ["a"],
            "expected_facts": ["brute force", "ASN"],
        }
    ]

    def runner(g):
        return _r("Likely brute force from a new ASN [a]", record_ids=["a"])

    rep = evaluate(runner, goldens)
    assert rep.answer_relevance == 1.0


def test_answer_relevance_partial():
    goldens = [
        {
            "incident_id": "i",
            "valid_record_ids": ["a"],
            "expected_facts": ["brute force", "ASN"],
        }
    ]

    def runner(g):
        return _r("Likely brute force [a]", record_ids=["a"])

    rep = evaluate(runner, goldens)
    assert rep.answer_relevance == 0.5


# --- threshold gate ---------------------------------------------------------


def test_meets_thresholds_passes_when_all_above():
    goldens = [
        {
            "incident_id": "i",
            "valid_record_ids": ["score:a"],
            "expected_facts": ["brute force"],
        }
    ]

    def runner(g):
        return _r("brute force [score:a]", record_ids=["score:a"])

    rep = evaluate(runner, goldens)
    assert (
        meets_thresholds(
            rep,
            {
                "faithfulness": 0.9,
                "citation_precision": 0.9,
                "citation_recall": 0.9,
                "refusal_correctness": 0.9,
                "answer_relevance": 0.9,
            },
        )
        is True
    )


def test_meets_thresholds_fails_below():
    goldens = [{"incident_id": "i", "valid_record_ids": ["a", "b"]}]

    def runner(g):
        return _r("only [a]", record_ids=["a"])  # recall 0.5

    rep = evaluate(runner, goldens)
    assert meets_thresholds(rep, {"citation_recall": 0.9}) is False
