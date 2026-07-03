"""Offline triage integration test — the cable-pulled proof.

Drives the WHOLE analyst loop with the network cable pulled:
``INFERENCE_PROVIDER=local`` routes inference to the self-hosted adapter, which
talks only to a mock OpenAI-compatible endpoint (stand-in for Ollama/Qwen). The
copilot reads a real host-detector alert via ``get_node_alerts``, proposes a
reversible action, and returns a grounded, cited triage answer.

What this guarantees end to end, with no cloud and no GPU:
  node_alerts (detector output) -> analyst reads it -> grounded triage + a
  reversible, advisory-only proposal -> zero Anthropic / sibling-HTTP egress.

The mock LLM is scripted by call index; the DB and HTTP session are injected, so
nothing here needs psycopg2, a live PG, a model, or a key.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal

from copilot import Copilot
from provider import ProviderRouter
from tools import ToolRegistry

CHAT_PATH = "http://mock-ollama:11434/v1/chat/completions"

_NODE_COLS = (
    "id",
    "alert_id",
    "event_type",
    "severity",
    "score",
    "pid",
    "uid",
    "comm",
    "exe",
    "hostname",
    "source_event_id",
    "summary",
    "status",
    "created_at",
)
_ALERT_ROW = (
    2,
    "uuid-2",
    "execve",
    "critical",
    Decimal("0.95"),
    4242,
    0,
    "nc",
    "/usr/bin/nc",
    "host-1",
    "1.0:1",
    "offensive tool 'nc'",
    "new",
    datetime(2026, 6, 29, 12, 0, tzinfo=timezone.utc),
)


# --- injected DB (one critical detector alert, offline) ----------------------


class _FakeCursor:
    description = [(c,) for c in _NODE_COLS]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._sql = sql

    def fetchall(self):
        return [_ALERT_ROW]


class _FakeConn:
    def cursor(self):
        return _FakeCursor()

    def close(self):
        pass


def _db():
    return _FakeConn()


# --- guard: the registry must make NO sibling HTTP call this run -------------


class _NoSiblingHTTP:
    def get(self, *a, **k):
        raise AssertionError("offline triage must not call sibling services over HTTP")

    def post(self, *a, **k):
        raise AssertionError("offline triage must not call sibling services over HTTP")


# --- mock OpenAI-compatible LLM endpoint (Ollama/Qwen stand-in) --------------


def _openai(message: dict, finish: str) -> dict:
    return {
        "choices": [{"message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 8},
    }


def _tool_call(call_id: str, name: str, args: dict) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)},
            }
        ],
    }


class MockOllama:
    """A scripted, OpenAI-compatible chat endpoint. Records every URL it serves
    so the test can prove inference went only to the local box."""

    def __init__(self):
        self.urls: list[str] = []
        self.calls = 0
        # Turn 1: read the detector's alerts. Turn 2: propose a reversible block.
        # Turn 3: final grounded triage answer citing the alert.
        self._script = [
            _openai(
                _tool_call("c1", "get_node_alerts", {"severity": "critical"}),
                "tool_calls",
            ),
            _openai(
                _tool_call(
                    "c2",
                    "propose_reversible_action",
                    {
                        "entity_id": "host-1",
                        "action_type": "block",
                        "ttl_seconds": 900,
                        "rationale": "reverse-shell tool nc -e executed",
                    },
                ),
                "tool_calls",
            ),
            _openai(
                {
                    "role": "assistant",
                    "content": (
                        "Critical: offensive tool nc executed (nc -e /bin/sh) "
                        "[node_alert:2]. Proposed a reversible host block for "
                        "human approval."
                    ),
                },
                "stop",
            ),
        ]

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

        def raise_for_status(self):
            return None

    def post(self, url, json=None, timeout=None, headers=None):
        self.urls.append(url)
        payload = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        return self._Resp(payload)


# --- the test ----------------------------------------------------------------


def test_offline_triage_of_node_alert(monkeypatch):
    monkeypatch.setenv("COPILOT_PROPOSAL_SIGNING_KEY", "k")
    monkeypatch.setenv("INFERENCE_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://mock-ollama:11434")
    monkeypatch.delenv("LOCAL_LLM_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    mock = MockOllama()
    client = ProviderRouter.from_env().build(session=mock)
    # Inference is local, and on the node's spec-locked model.
    assert type(client).__name__ == "LocalLLMClient"
    assert client.default_model == "qwen2.5:14b-instruct"

    registry = ToolRegistry(
        config={"ai_engine_url": "x", "api_gateway_url": "x", "policy_url": "x"},
        session=_NoSiblingHTTP(),
        service_token="t",
        db_connect=_db,
    )

    copilot = Copilot(client, registry)
    result = copilot.run(
        system="You are an offline host-security analyst. Triage detector alerts; "
        "cite [node_alert:id]; propose only reversible actions for human approval.",
        user_message="Triage the latest critical host alert.",
    )

    # Grounded, cited triage answer bound to the real detector record.
    assert result.grounded is True
    assert "node_alert:2" in result.record_ids
    assert result.citation_provenance.get("node_alert:2")  # source hash recorded

    # The analyst actually read the detector's output.
    tools_called = [t["tool"] for t in result.tool_results]
    assert "get_node_alerts" in tools_called

    # A reversible action was proposed — advisory only, never executed.
    assert len(result.proposals) == 1
    proposal = result.proposals[0]
    assert proposal["executed"] is False
    assert proposal["reversible"] is True
    assert proposal["ttl_seconds"] == 900

    # Cable pulled: inference hit ONLY the local endpoint; no cloud, no siblings.
    assert mock.urls and all(u == CHAT_PATH for u in mock.urls)
    assert mock.calls == 3
