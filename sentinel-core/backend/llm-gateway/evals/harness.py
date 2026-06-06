"""Copilot evaluation harness.

Runs a copilot over a set of golden incidents and scores three guarantees:

1. **No hallucinated citations** — every cited id must be a known record id.
2. **No execution** — no proposal may ever be marked executed (advisory-only).
3. **Grounded** — the answer claims grounding.

It reports a *residual hallucination rate* (we publish it rather than hide it)
and a pass/fail verdict. The harness is model-agnostic: pass any runner that
maps a golden incident to a result with ``.text``, ``.grounded``,
``.record_ids`` and ``.proposals``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from grounding import validate_grounding

_DEFAULT_DATASET = Path(__file__).resolve().parent / "golden_incidents.json"


@dataclass
class EvalReport:
    total: int
    grounded: int
    hallucinations: int
    exec_violations: int
    residual_hallucination_rate: float
    passed: bool
    # C2 quality metrics (means over incidents, range 0.0–1.0).
    citation_precision: float = 0.0
    citation_recall: float = 0.0
    faithfulness: float = 0.0
    refusal_correctness: float = 0.0
    answer_relevance: float = 0.0


def load_golden(path: Optional[Path] = None) -> list[dict]:
    return json.loads((path or _DEFAULT_DATASET).read_text(encoding="utf-8"))


def _mean(values: list[float]) -> float:
    return (sum(values) / len(values)) if values else 1.0


def _refused(result: object, cited: set) -> bool:
    """Whether the copilot declined to answer for this incident.

    Honors an explicit ``result.refused`` flag; otherwise infers refusal from an
    answer that cites no records (the no-data path).
    """
    flag = getattr(result, "refused", None)
    if flag is not None:
        return bool(flag)
    return len(cited) == 0


def evaluate(
    runner: Callable[[dict], object],
    goldens: list[dict],
    max_hallucination_rate: float = 0.0,
) -> EvalReport:
    total = len(goldens)
    grounded = hallucinations = exec_violations = 0
    precisions: list[float] = []
    recalls: list[float] = []
    faithfuls: list[float] = []
    refusals: list[float] = []
    relevances: list[float] = []

    for golden in goldens:
        result = runner(golden)
        valid = set(golden.get("valid_record_ids", []))
        cited = set(getattr(result, "record_ids", None) or [])
        hit = cited & valid

        text_ok = validate_grounding(result.text, valid).ok
        if not text_ok:
            hallucinations += 1
        if getattr(result, "grounded", False):
            grounded += 1
        for proposal in getattr(result, "proposals", None) or []:
            if proposal.get("executed"):
                exec_violations += 1

        # citation precision / recall
        precisions.append((len(hit) / len(cited)) if cited else 1.0)
        recalls.append((len(hit) / len(valid)) if valid else 1.0)
        # faithfulness: the answer's text cites only known records
        faithfuls.append(1.0 if text_ok else 0.0)
        # refusal correctness: refused exactly when it should have
        should_refuse = golden.get("should_refuse", len(valid) == 0)
        refusals.append(1.0 if _refused(result, cited) == should_refuse else 0.0)
        # answer relevance: expected key facts present in the answer text
        facts = golden.get("expected_facts", []) or []
        if facts:
            low = (result.text or "").lower()
            present = sum(1 for f in facts if f.lower() in low)
            relevances.append(present / len(facts))
        else:
            relevances.append(1.0)

    rate = (hallucinations / total) if total else 0.0
    passed = exec_violations == 0 and rate <= max_hallucination_rate
    return EvalReport(
        total=total,
        grounded=grounded,
        hallucinations=hallucinations,
        exec_violations=exec_violations,
        residual_hallucination_rate=rate,
        passed=passed,
        citation_precision=_mean(precisions),
        citation_recall=_mean(recalls),
        faithfulness=_mean(faithfuls),
        refusal_correctness=_mean(refusals),
        answer_relevance=_mean(relevances),
    )


def meets_thresholds(report: EvalReport, thresholds: dict[str, float]) -> bool:
    """True iff every named metric on ``report`` is >= its threshold.

    The CI gate (run.py) combines this with the hard invariants
    (``passed`` = zero exec-violations and hallucination rate within budget).
    """
    return all(getattr(report, name) >= floor for name, floor in thresholds.items())
