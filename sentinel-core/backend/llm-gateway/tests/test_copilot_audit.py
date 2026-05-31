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
