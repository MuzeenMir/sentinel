"""Adversarial red-team gate for the copilot defenses (C1).

Deterministic — no live model. Each corpus case is fed through the *exact*
defense that must neutralize it, and we assert the attack does not succeed:

* prompt injection (user input or poisoned tool output) -> `safety.detect_injection`
  / `safety.check_request`,
* citation forgery / ungrounded narration -> `grounding.validate_grounding`,
* SSRF / path-injection via tool args -> `tools.validate_entity_id`.

`run_redteam()` returns a report with a **residual** = attacks that slipped
through / total. The CI gate (`tests/test_redteam.py` + `llm-gateway-redteam.yml`)
fails if residual > 0. The number is published, not hidden.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from grounding import validate_grounding
from safety import check_request, detect_injection
from tools import InvalidEntityIdError, validate_entity_id

CORPUS_DIR = Path(__file__).resolve().parent / "evals" / "redteam"


@dataclass
class RedTeamReport:
    total: int = 0
    caught: int = 0
    slipped: list[str] = field(default_factory=list)

    @property
    def residual(self) -> float:
        return 0.0 if self.total == 0 else len(self.slipped) / self.total


def _load(name: str) -> list[dict]:
    path = CORPUS_DIR / name
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _injection_caught(case: dict) -> bool:
    payload = case["payload"]
    # Tool output and user input are both untrusted: a known-injection string
    # must be flagged by the detector or rejected by the request guard.
    return detect_injection(payload) or not check_request(payload)[0]


def _forgery_caught(case: dict) -> bool:
    result = validate_grounding(case["answer"], set(case["valid_ids"]))
    return not result.ok


def _ssrf_caught(case: dict) -> bool:
    try:
        validate_entity_id(case["entity_id"])
    except InvalidEntityIdError:
        return True
    return False


_CHECKS = (
    ("prompt_injection.jsonl", _injection_caught),
    ("citation_forgery.jsonl", _forgery_caught),
    ("ssrf_args.jsonl", _ssrf_caught),
)


def run_redteam() -> RedTeamReport:
    report = RedTeamReport()
    for name, caught_fn in _CHECKS:
        for case in _load(name):
            report.total += 1
            if caught_fn(case):
                report.caught += 1
            else:
                report.slipped.append(case["id"])
    return report


if __name__ == "__main__":  # pragma: no cover - CLI entry for the CI gate
    rep = run_redteam()
    print(
        f"red-team: {rep.caught}/{rep.total} neutralized, "
        f"residual={rep.residual:.3f}, slipped={rep.slipped}"
    )
    raise SystemExit(0 if not rep.slipped else 1)
