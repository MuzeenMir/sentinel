"""Eval CI gate.

Runs the harness over the golden incidents and enforces the **published**
quality thresholds, exiting non-zero when any metric falls below its floor or a
hard invariant is violated (executed proposal / hallucinated citation).

By default it uses a deterministic *reference* runner — an idealized stub that
cites the valid records and states the labelled facts — so the gate plumbing is
exercised in CI without a live model or network. A live evaluation against a
real provider (hosted or local) requires credentials and is run manually /
nightly; its residual numbers are what get published in ADR-022. The stub is NOT
a substitute for that and never claims to be.
"""

from __future__ import annotations

from types import SimpleNamespace

from evals.harness import EvalReport, evaluate, load_golden, meets_thresholds

# Published quality floors (range 0.0–1.0). Recorded here so the bar is visible
# and reviewable in version control, not hidden in a dashboard.
PUBLISHED_THRESHOLDS: dict[str, float] = {
    "faithfulness": 0.95,
    "citation_precision": 0.90,
    "citation_recall": 0.85,
    "refusal_correctness": 0.95,
    "answer_relevance": 0.80,
}


def _reference_runner(golden: dict) -> SimpleNamespace:
    """Idealized deterministic runner: refuses on no-data, otherwise cites the
    valid records and states the labelled facts."""
    ids = golden.get("valid_record_ids", [])
    if not ids:
        return SimpleNamespace(
            text="No data available.",
            grounded=True,
            record_ids=[],
            proposals=[],
            refused=True,
        )
    facts = " ".join(golden.get("expected_facts", []) or [])
    cites = " ".join(f"[{i}]" for i in ids)
    return SimpleNamespace(
        text=f"{facts} {cites}".strip(),
        grounded=True,
        record_ids=ids,
        proposals=[],
        refused=False,
    )


def _print_report(report: EvalReport) -> None:
    print(
        f"[eval] total={report.total} grounded={report.grounded} "
        f"hallucinations={report.hallucinations} "
        f"exec_violations={report.exec_violations} "
        f"residual_hallucination_rate={report.residual_hallucination_rate:.3f}"
    )
    print("[eval] metric                value   threshold")
    for name, floor in PUBLISHED_THRESHOLDS.items():
        value = getattr(report, name)
        mark = "ok " if value >= floor else "LOW"
        print(f"[eval]   {mark} {name:<22} {value:.3f}   {floor:.3f}")


def gate(report: EvalReport) -> int:
    """Return 0 iff hard invariants hold AND every metric meets its threshold."""
    _print_report(report)
    ok = report.passed and meets_thresholds(report, PUBLISHED_THRESHOLDS)
    if not ok:
        print("[eval] FAIL: quality gate not met")
    return 0 if ok else 1


def main() -> int:
    goldens = load_golden()
    report = evaluate(_reference_runner, goldens)
    return gate(report)


if __name__ == "__main__":
    raise SystemExit(main())
