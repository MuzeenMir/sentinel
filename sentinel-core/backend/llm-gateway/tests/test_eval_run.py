"""C2.3 — the eval CI gate: published thresholds + non-zero exit below them."""

from evals import run
from evals.harness import EvalReport


def _report(**kw):
    base = dict(
        total=10,
        grounded=10,
        hallucinations=0,
        exec_violations=0,
        residual_hallucination_rate=0.0,
        passed=True,
        citation_precision=1.0,
        citation_recall=1.0,
        faithfulness=1.0,
        refusal_correctness=1.0,
        answer_relevance=1.0,
    )
    base.update(kw)
    return EvalReport(**base)


def test_published_thresholds_exist():
    assert run.PUBLISHED_THRESHOLDS
    assert set(run.PUBLISHED_THRESHOLDS) <= {
        "faithfulness",
        "citation_precision",
        "citation_recall",
        "refusal_correctness",
        "answer_relevance",
    }


def test_gate_passes_on_clean_report():
    assert run.gate(_report()) == 0


def test_gate_fails_when_metric_below_threshold():
    assert run.gate(_report(citation_recall=0.10)) == 1


def test_gate_fails_on_exec_violation_even_if_metrics_high():
    assert run.gate(_report(exec_violations=1, passed=False)) == 1
