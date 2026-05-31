"""Integration tests for the copilot HTTP endpoints.

The copilot stack is overridden with a fake client + registry so no network or
inference happens; Redis is the in-memory fake from conftest.
"""

from types import SimpleNamespace

import pytest

from anthropic_client import LLMResponse
from copilot import Copilot
from persistence import SessionStore


def _resp(text="", tool_calls=None, stop_reason="end_turn"):
    return LLMResponse(
        text=text, stop_reason=stop_reason, tool_calls=tool_calls or [],
        usage={"input_tokens": 1, "output_tokens": 1, "cache_read_input_tokens": 0},
    )


class FakeClient:
    def __init__(self, responses):
        self._r = list(responses)

    def complete(self, **kw):
        return self._r.pop(0)


class FakeRegistry:
    def __init__(self, results):
        self.results = results

    def definitions(self):
        return [{"name": n, "description": "d", "input_schema": {"type": "object"}}
                for n in self.results]

    def execute(self, name, tool_input):
        return self.results[name]


def _install(app_module, monkeypatch, client, registry):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    monkeypatch.setattr(app_module, "make_registry", lambda: registry)
    monkeypatch.setattr(
        app_module,
        "make_copilot_context",
        lambda actor, tenant_id=None: SimpleNamespace(
            copilot=Copilot(client=client, registry=registry),
            registry=registry,
            auditor=None,
        ),
    )


def test_summarize_returns_grounded_summary(app_module, monkeypatch):
    registry = FakeRegistry({
        "get_threat_score": {"tool": "get_threat_score", "ok": True,
                             "result": {"score": 0.9}, "record_ids": ["score:s1"]},
        "get_audit_events": {"tool": "get_audit_events", "ok": True,
                             "result": {"events": [{"id": "e1"}]}, "record_ids": ["audit:e1"]},
        "get_enforcement_state": {"tool": "get_enforcement_state", "ok": True,
                                  "result": {"state": "none"}, "record_ids": ["enforce:h1"]},
    })
    client = FakeClient([_resp(text="Elevated risk [score:s1] [audit:e1], no enforcement [enforce:h1].")])
    _install(app_module, monkeypatch, client, registry)

    rv = app_module.app.test_client().post("/copilot/summarize", json={"entity_id": "h1"})

    assert rv.status_code == 200
    body = rv.get_json()
    assert body["grounded"] is True
    assert body["entity_id"] == "h1"
    assert "score:s1" in body["citations"]
    assert body["session_id"]


def test_summarize_requires_entity_id(app_module, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    rv = app_module.app.test_client().post("/copilot/summarize", json={})
    assert rv.status_code == 400


def test_summarize_503_when_inference_disabled(app_module, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rv = app_module.app.test_client().post("/copilot/summarize", json={"entity_id": "h1"})
    assert rv.status_code == 503


def test_summarize_rate_limited(app_module, monkeypatch):
    registry = FakeRegistry({
        "get_threat_score": {"ok": True, "result": {}, "record_ids": []},
        "get_audit_events": {"ok": True, "result": {}, "record_ids": []},
        "get_enforcement_state": {"ok": True, "result": {}, "record_ids": []},
    })
    # fresh client per call; rate limit is what we assert
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("COPILOT_RATE_LIMIT", "1")
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    monkeypatch.setattr(app_module, "make_registry", lambda: registry)
    monkeypatch.setattr(
        app_module, "make_copilot_context",
        lambda actor, tenant_id=None: SimpleNamespace(
            copilot=Copilot(client=FakeClient([_resp(text="ok")]), registry=registry),
            registry=registry, auditor=None),
    )
    c = app_module.app.test_client()
    first = c.post("/copilot/summarize", json={"entity_id": "h1", "actor": "a@x"})
    second = c.post("/copilot/summarize", json={"entity_id": "h1", "actor": "a@x"})
    assert first.status_code == 200
    assert second.status_code == 429


def test_ask_uses_session_and_tools(app_module, monkeypatch, fake_redis):
    registry = FakeRegistry({
        "get_audit_events": {"tool": "get_audit_events", "ok": True,
                             "result": {"events": [{"id": "e9"}]}, "record_ids": ["audit:e9"]},
    })
    client = FakeClient([
        _resp(stop_reason="tool_use", tool_calls=[
            {"id": "tc", "name": "get_audit_events", "input": {"entity_id": "h1"}}]),
        _resp(text="Recent failed logins [audit:e9]."),
    ])
    _install(app_module, monkeypatch, client, registry)
    sid = SessionStore(fake_redis).create_session("h1")

    rv = app_module.app.test_client().post(
        "/copilot/ask", json={"session_id": sid, "question": "what happened?"})

    assert rv.status_code == 200
    body = rv.get_json()
    assert body["grounded"] is True
    assert "audit:e9" in body["citations"]


def test_ask_unknown_session_404(app_module, monkeypatch):
    registry = FakeRegistry({})
    client = FakeClient([_resp(text="x")])
    _install(app_module, monkeypatch, client, registry)
    rv = app_module.app.test_client().post(
        "/copilot/ask", json={"session_id": "copilot:session:nope", "question": "hi"})
    assert rv.status_code == 404


def test_propose_returns_unexecuted_reversible_draft(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    rv = app_module.app.test_client().post(
        "/copilot/propose",
        json={"entity_id": "h1", "action_type": "block", "rationale": "brute force"},
    )
    assert rv.status_code == 200
    proposal = rv.get_json()["proposal"]
    assert proposal["executed"] is False
    assert proposal["reversible"] is True
    assert proposal["ttl_seconds"] == 900


def test_propose_requires_fields(app_module, monkeypatch):
    rv = app_module.app.test_client().post(
        "/copilot/propose", json={"entity_id": "h1"})
    assert rv.status_code == 400
