"""Smoke-run the eval harness with a reference stub runner.

This is **not** a live-model evaluation. It exercises the harness end-to-end
against the golden incidents using a deterministic stub and prints the residual
hallucination rate (expected 0.0 for the stub). A live evaluation against the
Anthropic API requires ANTHROPIC_API_KEY and is run manually / nightly.
"""

from __future__ import annotations

from types import SimpleNamespace

from evals.harness import evaluate, load_golden


def _stub_runner(golden: dict) -> SimpleNamespace:
    ids = golden.get("valid_record_ids", [])
    if not ids:
        return SimpleNamespace(
            text="No data available.", grounded=True, record_ids=[], proposals=[]
        )
    cites = " ".join(f"[{i}]" for i in ids)
    return SimpleNamespace(
        text=f"Summary {cites}", grounded=True, record_ids=ids, proposals=[]
    )


def main() -> int:
    goldens = load_golden()
    report = evaluate(_stub_runner, goldens)
    print(
        f"[eval] total={report.total} grounded={report.grounded} "
        f"hallucinations={report.hallucinations} "
        f"exec_violations={report.exec_violations} "
        f"residual_hallucination_rate={report.residual_hallucination_rate}"
    )
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
