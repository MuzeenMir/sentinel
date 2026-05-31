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


def load_golden(path: Optional[Path] = None) -> list[dict]:
    return json.loads((path or _DEFAULT_DATASET).read_text(encoding="utf-8"))


def evaluate(
    runner: Callable[[dict], object],
    goldens: list[dict],
    max_hallucination_rate: float = 0.0,
) -> EvalReport:
    total = len(goldens)
    grounded = hallucinations = exec_violations = 0

    for golden in goldens:
        result = runner(golden)
        valid = set(golden.get("valid_record_ids", []))

        if not validate_grounding(result.text, valid).ok:
            hallucinations += 1
        if getattr(result, "grounded", False):
            grounded += 1
        for proposal in getattr(result, "proposals", None) or []:
            if proposal.get("executed"):
                exec_violations += 1

    rate = (hallucinations / total) if total else 0.0
    passed = exec_violations == 0 and rate <= max_hallucination_rate
    return EvalReport(
        total=total,
        grounded=grounded,
        hallucinations=hallucinations,
        exec_violations=exec_violations,
        residual_hallucination_rate=rate,
        passed=passed,
    )
