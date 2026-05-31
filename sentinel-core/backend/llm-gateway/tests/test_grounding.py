"""Tests for citation/grounding enforcement."""

import pytest

from grounding import (
    GroundingError,
    enforce_grounding,
    extract_citations,
    repair_instruction,
    validate_grounding,
)


def test_extract_citations_finds_bracketed_record_ids():
    text = "Host failed logins [audit:evt-1] and score rose [score:s9]."
    assert extract_citations(text) == ["audit:evt-1", "score:s9"]


def test_validate_passes_when_all_citations_known():
    text = "Activity spiked [audit:evt-1]."
    result = validate_grounding(text, valid_ids={"audit:evt-1", "score:s9"})
    assert result.ok is True
    assert result.hallucinated_ids == []


def test_validate_flags_hallucinated_id():
    text = "Suspicious [audit:evt-1] and [audit:evt-FAKE]."
    result = validate_grounding(text, valid_ids={"audit:evt-1"})
    assert result.ok is False
    assert result.hallucinated_ids == ["audit:evt-FAKE"]


def test_response_without_any_citation_is_flagged_when_data_available():
    text = "This host is definitely compromised and should be blocked."
    result = validate_grounding(text, valid_ids={"audit:evt-1"})
    assert result.ok is False
    assert "citation" in (result.reason or "").lower()


def test_no_citation_required_when_no_data_available():
    text = "No data available for this entity."
    result = validate_grounding(text, valid_ids=set())
    assert result.ok is True


def test_citation_with_no_data_available_is_hallucination():
    text = "It happened [audit:evt-1]."
    result = validate_grounding(text, valid_ids=set())
    assert result.ok is False
    assert result.hallucinated_ids == ["audit:evt-1"]


def test_enforce_raises_on_ungrounded():
    with pytest.raises(GroundingError):
        enforce_grounding("Bad [audit:nope].", valid_ids={"audit:evt-1"})


def test_repair_instruction_names_offending_ids():
    result = validate_grounding("Bad [audit:nope].", valid_ids={"audit:evt-1"})
    msg = repair_instruction(result)
    assert "audit:nope" in msg
