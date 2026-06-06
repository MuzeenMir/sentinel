"""C3 — broaden the adversarial corpus: jailbreak + tool-output poisoning.

Both are injection-class attacks via different vectors (direct user jailbreak vs
malicious instructions smuggled inside *tool output*). Tool output is untrusted,
so the same detector must neutralize them. The gate requires 0 escapes.
"""

from redteam import _CHECKS, _injection_caught, _load, run_redteam

_CATEGORIES = {name for name, _ in _CHECKS}


def test_new_attack_categories_are_wired_into_the_gate():
    assert "jailbreak.jsonl" in _CATEGORIES
    assert "tool_output_poisoning.jsonl" in _CATEGORIES


def test_jailbreak_corpus_fully_neutralized():
    cases = _load("jailbreak.jsonl")
    assert len(cases) >= 3
    assert all(_injection_caught(c) for c in cases)


def test_tool_output_poisoning_fully_neutralized():
    cases = _load("tool_output_poisoning.jsonl")
    assert len(cases) >= 3
    assert all(_injection_caught(c) for c in cases)


def test_full_redteam_zero_residual_with_new_categories():
    report = run_redteam()
    # the new categories must be part of the run and nothing may slip
    assert report.total >= 12
    assert report.slipped == []
    assert report.residual == 0.0
