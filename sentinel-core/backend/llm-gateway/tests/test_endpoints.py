"""Integration tests for the copilot HTTP endpoints.

The copilot stack is overridden with a fake client + registry so no network or
inference happens; Redis is the in-memory fake from conftest.
"""

from types import SimpleNamespace


from anthropic_client import LLMResponse
from copilot import Copilot
from persistence import SessionStore


def _resp(text="", tool_calls=None, stop_reason="end_turn"):
    return LLMResponse(
        text=text,
        stop_reason=stop_reason,
        tool_calls=tool_calls or [],
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
        return [
            {"name": n, "description": "d", "input_schema": {"type": "object"}}
            for n in self.results
        ]

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
    registry = FakeRegistry(
        {
            "get_threat_score": {
                "tool": "get_threat_score",
                "ok": True,
                "result": {"score": 0.9},
                "record_ids": ["score:s1"],
            },
            "get_audit_events": {
                "tool": "get_audit_events",
                "ok": True,
                "result": {"events": [{"id": "e1"}]},
                "record_ids": ["audit:e1"],
            },
            "get_enforcement_state": {
                "tool": "get_enforcement_state",
                "ok": True,
                "result": {"state": "none"},
                "record_ids": ["enforce:h1"],
            },
        }
    )
    client = FakeClient(
        [
            _resp(
                text="Elevated risk [score:s1] [audit:e1], no enforcement [enforce:h1]."
            )
        ]
    )
    _install(app_module, monkeypatch, client, registry)

    rv = app_module.app.test_client().post(
        "/copilot/summarize", json={"entity_id": "h1"}
    )

    assert rv.status_code == 200
    body = rv.get_json()
    assert body["grounded"] is True
    assert body["entity_id"] == "h1"
    assert "score:s1" in body["citations"]
    assert body["session_id"]
    # C2: cited ids carry a verifiable source-hash fingerprint.
    assert body["citation_provenance"]["score:s1"]


def test_summarize_requires_entity_id(app_module, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    rv = app_module.app.test_client().post("/copilot/summarize", json={})
    assert rv.status_code == 400


def test_summarize_503_when_inference_disabled(app_module, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rv = app_module.app.test_client().post(
        "/copilot/summarize", json={"entity_id": "h1"}
    )
    assert rv.status_code == 503


def test_summarize_rate_limited(app_module, monkeypatch):
    registry = FakeRegistry(
        {
            "get_threat_score": {"ok": True, "result": {}, "record_ids": []},
            "get_audit_events": {"ok": True, "result": {}, "record_ids": []},
            "get_enforcement_state": {"ok": True, "result": {}, "record_ids": []},
        }
    )
    # fresh client per call; rate limit is what we assert
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("COPILOT_RATE_LIMIT", "1")
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    monkeypatch.setattr(app_module, "make_registry", lambda: registry)
    monkeypatch.setattr(
        app_module,
        "make_copilot_context",
        lambda actor, tenant_id=None: SimpleNamespace(
            copilot=Copilot(client=FakeClient([_resp(text="ok")]), registry=registry),
            registry=registry,
            auditor=None,
        ),
    )
    c = app_module.app.test_client()
    first = c.post("/copilot/summarize", json={"entity_id": "h1", "actor": "a@x"})
    second = c.post("/copilot/summarize", json={"entity_id": "h1", "actor": "a@x"})
    assert first.status_code == 200
    assert second.status_code == 429


def test_ask_uses_session_and_tools(app_module, monkeypatch, fake_redis):
    registry = FakeRegistry(
        {
            "get_audit_events": {
                "tool": "get_audit_events",
                "ok": True,
                "result": {"events": [{"id": "e9"}]},
                "record_ids": ["audit:e9"],
            },
        }
    )
    client = FakeClient(
        [
            _resp(
                stop_reason="tool_use",
                tool_calls=[
                    {
                        "id": "tc",
                        "name": "get_audit_events",
                        "input": {"entity_id": "h1"},
                    }
                ],
            ),
            _resp(text="Recent failed logins [audit:e9]."),
        ]
    )
    _install(app_module, monkeypatch, client, registry)
    sid = SessionStore(fake_redis).create_session("h1")

    rv = app_module.app.test_client().post(
        "/copilot/ask", json={"session_id": sid, "question": "what happened?"}
    )

    assert rv.status_code == 200
    body = rv.get_json()
    assert body["grounded"] is True
    assert "audit:e9" in body["citations"]


def test_ask_is_tenant_isolated(app_module, monkeypatch, fake_redis):
    # C3: a session created under tenant-a cannot be reached by tenant-b through
    # the gateway, even with the real session id.
    registry = FakeRegistry({})
    client = FakeClient([_resp(text="answer")])
    monkeypatch.setenv("INTERNAL_SERVICE_TOKEN", "svc-tok")
    _install(app_module, monkeypatch, client, registry)
    sid = SessionStore(fake_redis, tenant_id="tenant-a").create_session("h1")

    def hdr(tenant):
        return {"X-Internal-Service-Token": "svc-tok", "X-Tenant-Id": tenant}

    c = app_module.app.test_client()
    other = c.post(
        "/copilot/ask",
        json={"session_id": sid, "question": "what happened?"},
        headers=hdr("tenant-b"),
    )
    assert other.status_code == 404  # foreign tenant — session not visible

    owner = c.post(
        "/copilot/ask",
        json={"session_id": sid, "question": "what happened?"},
        headers=hdr("tenant-a"),
    )
    assert owner.status_code == 200  # owning tenant resolves its own session


def test_ask_unknown_session_404(app_module, monkeypatch):
    registry = FakeRegistry({})
    client = FakeClient([_resp(text="x")])
    _install(app_module, monkeypatch, client, registry)
    rv = app_module.app.test_client().post(
        "/copilot/ask", json={"session_id": "copilot:session:nope", "question": "hi"}
    )
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
    rv = app_module.app.test_client().post("/copilot/propose", json={"entity_id": "h1"})
    assert rv.status_code == 400


def test_propose_rejects_entity_id_path_injection(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    rv = app_module.app.test_client().post(
        "/copilot/propose",
        json={"entity_id": "../../x", "action_type": "block", "rationale": "r"},
    )
    assert rv.status_code == 400


def test_confirm_is_verify_only_and_does_not_consume_the_nonce(app_module, monkeypatch):
    monkeypatch.setenv("COPILOT_PROPOSAL_SIGNING_KEY", "k")
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    c = app_module.app.test_client()
    pr = c.post(
        "/copilot/propose",
        json={"entity_id": "h1", "action_type": "block", "rationale": "r"},
    )
    proposal = pr.get_json()["proposal"]
    assert proposal["signature"] and proposal["nonce"]

    ok = c.post("/copilot/confirm", json={"proposal": proposal})
    assert ok.status_code == 200
    assert ok.get_json()["confirmed"] is True

    # confirm is advisory validation only and must NOT consume the single-use
    # nonce -- the enforcement boundary (policy-orchestrator POST /enforcement)
    # owns single-use. Consuming here too would double-spend it and make every
    # real confirm->enforce call fail as a replay. So a repeat still validates.
    again = c.post("/copilot/confirm", json={"proposal": proposal})
    assert again.status_code == 200
    assert again.get_json()["confirmed"] is True


def test_confirm_rejects_tampered_proposal(app_module, monkeypatch):
    monkeypatch.setenv("COPILOT_PROPOSAL_SIGNING_KEY", "k")
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    c = app_module.app.test_client()
    pr = c.post(
        "/copilot/propose",
        json={"entity_id": "h1", "action_type": "block", "rationale": "r"},
    )
    proposal = pr.get_json()["proposal"]
    proposal["action_type"] = "quarantine"  # escalate after signing

    bad = c.post("/copilot/confirm", json={"proposal": proposal})
    assert bad.status_code == 400  # signature mismatch, never executes


def test_rate_limit_key_ignores_spoofed_actor(app_module, monkeypatch):
    # Rotating the client-supplied 'actor' must NOT mint a fresh rate-limit
    # bucket, otherwise the limit is trivially bypassed.
    registry = FakeRegistry(
        {
            "get_threat_score": {"ok": True, "result": {}, "record_ids": []},
            "get_audit_events": {"ok": True, "result": {}, "record_ids": []},
            "get_enforcement_state": {"ok": True, "result": {}, "record_ids": []},
        }
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("COPILOT_RATE_LIMIT", "1")
    monkeypatch.delenv("INTERNAL_SERVICE_TOKEN", raising=False)
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    monkeypatch.setattr(app_module, "make_registry", lambda: registry)
    monkeypatch.setattr(
        app_module,
        "make_copilot_context",
        lambda actor, tenant_id=None: SimpleNamespace(
            copilot=Copilot(
                client=FakeClient([_resp(text="ok"), _resp(text="ok")]),
                registry=registry,
            ),
            registry=registry,
            auditor=None,
        ),
    )
    c = app_module.app.test_client()
    first = c.post("/copilot/summarize", json={"entity_id": "h1", "actor": "a@x"})
    second = c.post(
        "/copilot/summarize", json={"entity_id": "h1", "actor": "rotated@y"}
    )
    assert first.status_code == 200
    assert second.status_code == 429  # different body actor, same real key


def test_xactor_honored_only_when_service_token_valid(app_module, monkeypatch):
    # With a valid internal service token the gateway-forwarded X-Actor keys the
    # limiter, so two DIFFERENT authenticated actors get independent buckets.
    registry = FakeRegistry(
        {
            "get_threat_score": {"ok": True, "result": {}, "record_ids": []},
            "get_audit_events": {"ok": True, "result": {}, "record_ids": []},
            "get_enforcement_state": {"ok": True, "result": {}, "record_ids": []},
        }
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("COPILOT_RATE_LIMIT", "1")
    monkeypatch.setenv("INTERNAL_SERVICE_TOKEN", "svc-tok")
    monkeypatch.setattr(app_module, "audit_sink", lambda **k: None)
    monkeypatch.setattr(app_module, "make_registry", lambda: registry)
    monkeypatch.setattr(
        app_module,
        "make_copilot_context",
        lambda actor, tenant_id=None: SimpleNamespace(
            copilot=Copilot(
                client=FakeClient([_resp(text="ok"), _resp(text="ok")]),
                registry=registry,
            ),
            registry=registry,
            auditor=None,
        ),
    )
    c = app_module.app.test_client()
    hdr_a = {"X-Internal-Service-Token": "svc-tok", "X-Actor": "alice"}
    hdr_b = {"X-Internal-Service-Token": "svc-tok", "X-Actor": "bob"}
    first = c.post("/copilot/summarize", json={"entity_id": "h1"}, headers=hdr_a)
    second = c.post("/copilot/summarize", json={"entity_id": "h1"}, headers=hdr_b)
    assert first.status_code == 200
    assert second.status_code == 200  # distinct authenticated actors = distinct buckets
