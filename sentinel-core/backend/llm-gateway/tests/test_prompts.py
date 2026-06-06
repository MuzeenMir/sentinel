"""Tests for prompt templates and the strict renderer."""

import pytest

from prompts import PromptRenderError, render


def test_system_prompt_states_grounding_and_advisory_contract():
    text = render("system")
    lowered = text.lower()
    # Citation contract + advisory-only invariant must be explicit.
    assert "cite" in lowered or "citation" in lowered
    assert "advisory" in lowered
    assert "propose" in lowered
    # Hard invariant: copilot must never execute enforcement itself.
    assert "must not" in lowered and "execute" in lowered


def test_incident_summary_fills_variables():
    text = render(
        "incident_summary",
        entity_id="host-42",
        threat_score="0.91",
        audit_excerpt="login from new ASN",
        enforcement_state="none",
    )
    assert "host-42" in text
    assert "0.91" in text
    assert "login from new ASN" in text
    assert "{{" not in text  # no unrendered placeholders


def test_missing_variable_raises():
    with pytest.raises(PromptRenderError):
        render("incident_summary", entity_id="only-one")


def test_unknown_template_raises():
    with pytest.raises(PromptRenderError):
        render("does_not_exist")
