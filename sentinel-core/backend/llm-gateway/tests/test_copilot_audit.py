"""Tests for copilot audit integration.

The auditor wraps the shared audit_logger (imported, never edited). It is
injectable so tests need no Postgres, and the default sink is resolved lazily
so constructing it never imports psycopg2.
"""

from anthropic_client import LLMResponse
from audit import CopilotAuditor
from copilot import Copilot


class FakeSink:
    def __init__(self):
        self.events = []

    def __call__(self, **kwargs):
        self.events.append(kwargs)


def test_construction_without_sink_does_not_require_pg():
    # Must not raise even though psycopg2 is unavailable (lazy default sink).
    CopilotAuditor(actor="analyst@x")


def test_hook_emits_prefixed_events_with_actor():
    sink = FakeSink()
    auditor = CopilotAuditor(actor="analyst@x", tenant_id="t1", sink=sink)
    hook = auditor.hook()

    hook("tool_call", {"name": "get_threat_score"})

    assert len(sink.events) == 1
    evt = sink.events[0]
    assert evt["event_type"] == "copilot_tool_call"
    assert evt["actor"] == "analyst@x"
    assert evt["tenant_id"] == "t1"
    assert evt["metadata"]["name"] == "get_threat_score"


def test_proposal_audit_records_not_executed():
    sink = FakeSink()
    auditor = CopilotAuditor(actor="a", sink=sink)
    auditor.log_proposal({"proposal_id": "proposal:p1", "executed": False})
    evt = sink.events[-1]
    assert evt["event_type"] == "copilot_proposal"
    assert evt["metadata"]["executed"] is False


def test_copilot_run_emits_audit_trail():
    class FakeClient:
        def __init__(self, responses):
            self._r = list(responses)

        def complete(self, **kw):
            return self._r.pop(0)

    class FakeRegistry:
        def definitions(self):
            return [
                {
                    "name": "get_threat_score",
                    "description": "d",
                    "input_schema": {"type": "object"},
                }
            ]

        def execute(self, name, tool_input):
            return {"ok": True, "result": {}, "record_ids": ["score:s1"]}

    sink = FakeSink()
    auditor = CopilotAuditor(actor="analyst@x", sink=sink)
    client = FakeClient(
        [
            LLMResponse(
                text="",
                stop_reason="tool_use",
                tool_calls=[
                    {
                        "id": "tc",
                        "name": "get_threat_score",
                        "input": {"entity_id": "h1"},
                    }
                ],
                usage={"input_tokens": 1, "output_tokens": 1},
            ),
            LLMResponse(
                text="elevated [score:s1]",
                stop_reason="end_turn",
                usage={"input_tokens": 1, "output_tokens": 1},
            ),
        ]
    )
    cop = Copilot(client=client, registry=FakeRegistry(), audit_hook=auditor.hook())

    cop.run(system="s", user_message="assess h1")

    types = [e["event_type"] for e in sink.events]
    assert "copilot_tool_call" in types
    assert "copilot_answer" in types


def test_copilot_run_audits_every_turn_in_the_ledger():
    """C6: prompt, completion, tool-call, and answer must all be audited so the
    copilot is provably inside the ledger; the answer event carries cost."""

    class FakeClient:
        def __init__(self, responses):
            self._r = list(responses)

        def complete(self, **kw):
            return self._r.pop(0)

    class FakeRegistry:
        def definitions(self):
            return [
                {
                    "name": "get_threat_score",
                    "description": "d",
                    "input_schema": {"type": "object"},
                }
            ]

        def execute(self, name, tool_input):
            return {"ok": True, "result": {"score": 0.9}, "record_ids": ["score:s1"]}

    sink = FakeSink()
    auditor = CopilotAuditor(actor="analyst@x", sink=sink)
    client = FakeClient(
        [
            LLMResponse(
                text="",
                stop_reason="tool_use",
                tool_calls=[
                    {
                        "id": "tc",
                        "name": "get_threat_score",
                        "input": {"entity_id": "h1"},
                    }
                ],
                usage={"input_tokens": 10, "output_tokens": 5},
            ),
            LLMResponse(
                text="elevated [score:s1]",
                stop_reason="end_turn",
                usage={"input_tokens": 8, "output_tokens": 12},
            ),
        ]
    )
    cop = Copilot(client=client, registry=FakeRegistry(), audit_hook=auditor.hook())

    result = cop.run(system="s", user_message="assess h1")

    types = [e["event_type"] for e in sink.events]
    for required in (
        "copilot_prompt",
        "copilot_llm_completion",
        "copilot_tool_call",
        "copilot_answer",
    ):
        assert required in types, f"missing audit event: {required}"

    answer = next(e for e in sink.events if e["event_type"] == "copilot_answer")
    assert "cost_usd" in answer["metadata"]
    assert answer["metadata"]["cost_usd"] > 0
    assert result.cost_usd > 0
    # prompt event records metadata only — never raw content (no PII)
    prompt = next(e for e in sink.events if e["event_type"] == "copilot_prompt")
    assert "content" not in prompt["metadata"]
    assert prompt["metadata"]["chars"] > 0
