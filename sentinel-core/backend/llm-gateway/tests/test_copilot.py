"""Tests for the copilot orchestration loop (deterministic with a fake model)."""

from anthropic_client import LLMResponse
from copilot import Copilot, SAFE_FALLBACK


class FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def complete(self, system, messages, tools=None, model=None, max_tokens=None):
        self.calls.append({"messages": [dict(m) for m in messages]})
        return self._responses.pop(0)


class FakeRegistry:
    def __init__(self, results):
        self.results = results
        self.executed = []

    def definitions(self):
        return [{"name": n, "description": "d", "input_schema": {"type": "object"}}
                for n in self.results]

    def execute(self, name, tool_input):
        self.executed.append((name, tool_input))
        return self.results[name]


def _resp(text="", tool_calls=None, stop_reason="end_turn", out=5):
    return LLMResponse(
        text=text,
        stop_reason=stop_reason,
        tool_calls=tool_calls or [],
        usage={"input_tokens": 10, "output_tokens": out, "cache_read_input_tokens": 0},
    )


def test_single_turn_without_tools_is_grounded():
    client = FakeClient([_resp(text="How can I help with this incident?")])
    cop = Copilot(client=client, registry=FakeRegistry({}))

    result = cop.run(system="s", user_message="hi")

    assert result.grounded is True
    assert result.text == "How can I help with this incident?"
    assert result.iterations == 1


def test_tool_use_then_grounded_answer():
    client = FakeClient([
        _resp(stop_reason="tool_use", tool_calls=[
            {"id": "tc1", "name": "get_threat_score", "input": {"entity_id": "h1"}}]),
        _resp(text="Score is elevated [score:s1]."),
    ])
    registry = FakeRegistry({
        "get_threat_score": {"ok": True, "result": {"score": 0.9}, "record_ids": ["score:s1"]},
    })
    cop = Copilot(client=client, registry=registry)

    result = cop.run(system="s", user_message="assess h1")

    assert result.grounded is True
    assert "score:s1" in result.record_ids
    assert registry.executed == [("get_threat_score", {"entity_id": "h1"})]
    assert "[score:s1]" in result.text


def test_ungrounded_answer_triggers_repair_then_succeeds():
    client = FakeClient([
        _resp(stop_reason="tool_use", tool_calls=[
            {"id": "tc1", "name": "get_threat_score", "input": {"entity_id": "h1"}}]),
        _resp(text="Compromised [score:HALLUCINATED]."),   # ungrounded
        _resp(text="Score is elevated [score:s1]."),        # repaired
    ])
    registry = FakeRegistry({
        "get_threat_score": {"ok": True, "result": {"score": 0.9}, "record_ids": ["score:s1"]},
    })
    cop = Copilot(client=client, registry=registry, max_repairs=1)

    result = cop.run(system="s", user_message="assess h1")

    assert result.grounded is True
    assert result.text == "Score is elevated [score:s1]."
    assert result.repairs == 1


def test_persistent_hallucination_is_flagged_and_text_is_safe():
    client = FakeClient([
        _resp(stop_reason="tool_use", tool_calls=[
            {"id": "tc1", "name": "get_threat_score", "input": {"entity_id": "h1"}}]),
        _resp(text="Bad [score:FAKE]."),
        _resp(text="Still bad [score:FAKE]."),
    ])
    registry = FakeRegistry({
        "get_threat_score": {"ok": True, "result": {"score": 0.9}, "record_ids": ["score:s1"]},
    })
    cop = Copilot(client=client, registry=registry, max_repairs=1)

    result = cop.run(system="s", user_message="assess h1")

    assert result.grounded is False
    assert result.text == SAFE_FALLBACK
    assert result.stop_reason == "ungrounded"


def test_proposals_are_captured_and_not_executed():
    client = FakeClient([
        _resp(stop_reason="tool_use", tool_calls=[
            {"id": "tc1", "name": "propose_reversible_action",
             "input": {"entity_id": "h1", "action_type": "block", "rationale": "x"}}]),
        _resp(text="I recommend a 15-minute block [proposal:p1]."),
    ])
    registry = FakeRegistry({
        "propose_reversible_action": {
            "ok": True,
            "result": {"proposal_id": "proposal:p1", "executed": False,
                       "reversible": True, "ttl_seconds": 900},
            "record_ids": ["proposal:p1"],
        },
    })
    cop = Copilot(client=client, registry=registry)

    result = cop.run(system="s", user_message="should I block h1?")

    assert len(result.proposals) == 1
    assert result.proposals[0]["executed"] is False
    assert result.grounded is True


def test_max_iters_guard_prevents_infinite_tool_loop():
    looping = [_resp(stop_reason="tool_use", tool_calls=[
        {"id": "tc", "name": "get_threat_score", "input": {"entity_id": "h1"}}])
        for _ in range(10)]
    client = FakeClient(looping)
    registry = FakeRegistry({
        "get_threat_score": {"ok": True, "result": {}, "record_ids": ["score:s1"]}})
    cop = Copilot(client=client, registry=registry, max_iters=3)

    result = cop.run(system="s", user_message="loop")

    assert result.stop_reason == "max_iters"
    assert result.iterations == 3


def test_token_budget_stops_loop():
    client = FakeClient([
        _resp(stop_reason="tool_use", tool_calls=[
            {"id": "tc", "name": "get_threat_score", "input": {"entity_id": "h1"}}], out=100),
        _resp(text="done [score:s1]"),
    ])
    registry = FakeRegistry({
        "get_threat_score": {"ok": True, "result": {}, "record_ids": ["score:s1"]}})
    cop = Copilot(client=client, registry=registry, max_total_tokens=50)

    result = cop.run(system="s", user_message="x")

    assert result.stop_reason == "token_budget"
