"""Tests for the grounded tool registry.

Upstream services are faked; no real HTTP. The propose tool must make NO
network call (advisory-only invariant).
"""

import pytest

from tools import ToolRegistry, UnknownToolError


class FakeResp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, get_data=None, fail=False):
        self.calls = []
        self._get_data = get_data or {}
        self.fail = fail

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append(("GET", url, headers or {}, params or {}))
        if self.fail:
            raise ConnectionError("upstream down")
        return FakeResp(self._get_data)

    def post(self, *a, **k):  # pragma: no cover - should never be called by reads
        self.calls.append(("POST", a, k))
        raise AssertionError("propose tool must not make HTTP calls")


def _registry(session, **cfg):
    config = {
        "ai_engine_url": "http://ai-engine:5003",
        "api_gateway_url": "http://api-gateway:8080",
        "policy_url": "http://policy-orchestrator:5004",
    }
    config.update(cfg)
    return ToolRegistry(config=config, session=session, service_token="tok-123")


def test_definitions_expose_four_tools_with_schemas():
    reg = _registry(FakeSession())
    defs = reg.definitions()
    names = {d["name"] for d in defs}
    assert names == {
        "get_threat_score",
        "get_audit_events",
        "get_enforcement_state",
        "propose_reversible_action",
    }
    for d in defs:
        assert d["input_schema"]["type"] == "object"
        assert d["description"]


def test_get_threat_score_calls_ai_engine_and_returns_record_ids():
    session = FakeSession(get_data={"id": "score-1", "entity_id": "h1", "score": 0.9})
    reg = _registry(session)

    out = reg.execute("get_threat_score", {"entity_id": "h1"})

    assert out["ok"] is True
    assert out["result"]["score"] == 0.9
    assert "score:score-1" in out["record_ids"]
    method, url, headers, _ = session.calls[0]
    assert method == "GET"
    assert "ai-engine:5003" in url and "h1" in url
    assert headers.get("X-Internal-Service-Token") == "tok-123"


def test_get_audit_events_returns_event_ids():
    session = FakeSession(get_data={"events": [{"id": "evt-1"}, {"id": "evt-2"}]})
    reg = _registry(session)

    out = reg.execute("get_audit_events", {"entity_id": "h1", "window": "24h"})

    assert out["ok"] is True
    assert out["record_ids"] == ["audit:evt-1", "audit:evt-2"]


def test_get_enforcement_state_calls_policy_orchestrator():
    session = FakeSession(get_data={"entity_id": "h1", "state": "blocked"})
    reg = _registry(session)

    out = reg.execute("get_enforcement_state", {"entity_id": "h1"})

    assert out["ok"] is True
    assert "policy-orchestrator:5004" in session.calls[0][1]
    assert out["result"]["state"] == "blocked"


def test_propose_action_makes_no_http_call_and_is_not_executed():
    session = FakeSession()  # .post raises if called
    reg = _registry(session)

    out = reg.execute(
        "propose_reversible_action",
        {
            "entity_id": "h1",
            "action_type": "block",
            "ttl_seconds": 900,
            "rationale": "repeated failed logins",
        },
    )

    assert session.calls == []  # zero network calls
    assert out["ok"] is True
    assert out["result"]["executed"] is False
    assert out["result"]["reversible"] is True
    assert out["result"]["ttl_seconds"] == 900
    assert out["result"]["proposal_id"]


def test_http_failure_is_fail_soft():
    reg = _registry(FakeSession(fail=True))
    out = reg.execute("get_threat_score", {"entity_id": "h1"})
    assert out["ok"] is False
    assert out["record_ids"] == []
    assert "error" in out


def test_unknown_tool_raises():
    reg = _registry(FakeSession())
    with pytest.raises(UnknownToolError):
        reg.execute("delete_everything", {})


# --- anti-SSRF / path-injection: entity_id is attacker/LLM-controlled --------


def test_threat_score_rejects_path_injection_without_network():
    session = FakeSession(get_data={"id": "x"})
    reg = _registry(session)
    out = reg.execute("get_threat_score", {"entity_id": "../../admin/keys"})
    assert out["ok"] is False  # fail-soft, model gets an error
    assert session.calls == []  # crucially: NEVER reached the network
    assert "entity_id" in out["error"]


def test_enforcement_state_rejects_path_injection_without_network():
    session = FakeSession(get_data={})
    reg = _registry(session)
    out = reg.execute("get_enforcement_state", {"entity_id": "h1/../../secret"})
    assert out["ok"] is False
    assert session.calls == []


def test_audit_events_rejects_injection_without_network():
    session = FakeSession(get_data={"events": []})
    reg = _registry(session)
    out = reg.execute("get_audit_events", {"entity_id": "h1 OR 1=1", "window": "24h"})
    assert out["ok"] is False
    assert session.calls == []


def test_valid_entity_id_with_safe_punctuation_allowed():
    session = FakeSession(get_data={"id": "s1", "score": 0.5})
    reg = _registry(session)
    out = reg.execute("get_threat_score", {"entity_id": "host-1.local_2"})
    assert out["ok"] is True
    assert session.calls and "host-1.local_2" in session.calls[0][1]
