"""C1 — inference provider abstraction.

The router selects the hosted (Anthropic) adapter by default and the local
(llama.cpp / self-host) adapter when ``INFERENCE_PROVIDER=local``. Both adapters
expose the same ``complete(...) -> LLMResponse`` contract so ``copilot.py`` can
swap inference with a config change, not a code change (inference sovereignty).
"""

from __future__ import annotations

from types import SimpleNamespace


from anthropic_client import LLMResponse
from local_client import LocalLLMClient
from provider import ProviderRouter


# --- fakes (no network) -----------------------------------------------------


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class _FakeHTTP:
    """Stand-in for a requests.Session returning an OpenAI-style payload."""

    def __init__(self, payload):
        self._payload = payload
        self.calls: list[tuple] = []

    def post(self, url, json=None, timeout=None, headers=None):
        self.calls.append((url, json))
        return _FakeResp(self._payload)


def _openai_payload(content="hello", finish="stop", tool_calls=None, usage=None):
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"message": message, "finish_reason": finish}],
        "usage": usage
        if usage is not None
        else {"prompt_tokens": 10, "completion_tokens": 5},
    }


class _FakeSDK:
    """Minimal Anthropic SDK double exposing messages.create."""

    class _Messages:
        def create(self, **kwargs):
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text="hi")],
                stop_reason="end_turn",
                usage=SimpleNamespace(
                    input_tokens=1, output_tokens=1, cache_read_input_tokens=0
                ),
            )

    def __init__(self):
        self.messages = self._Messages()


# --- router selection -------------------------------------------------------


def test_router_defaults_to_anthropic(monkeypatch):
    monkeypatch.delenv("INFERENCE_PROVIDER", raising=False)
    assert ProviderRouter.from_env().name == "anthropic"


def test_router_selects_local(monkeypatch):
    monkeypatch.setenv("INFERENCE_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://llamacpp:8080")
    assert ProviderRouter.from_env().name == "local"


# --- local adapter maps OpenAI-compatible llama.cpp responses ---------------


def test_local_client_maps_text_completion():
    http = _FakeHTTP(_openai_payload(content="hello", finish="stop"))
    client = LocalLLMClient(base_url="http://llamacpp:8080", session=http)
    resp = client.complete(system="sys", messages=[{"role": "user", "content": "hi"}])
    assert isinstance(resp, LLMResponse)
    assert resp.text == "hello"
    assert resp.stop_reason == "end_turn"  # normalized to Anthropic-style
    assert resp.usage["input_tokens"] == 10
    assert resp.usage["output_tokens"] == 5
    # posts to the OpenAI-compatible chat-completions path on the configured host
    assert http.calls[0][0] == "http://llamacpp:8080/v1/chat/completions"


def test_local_client_maps_tool_calls():
    tool_calls = [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "get_threat", "arguments": '{"id": "t1"}'},
        }
    ]
    http = _FakeHTTP(
        _openai_payload(content=None, finish="tool_calls", tool_calls=tool_calls)
    )
    client = LocalLLMClient(base_url="http://x", session=http)
    resp = client.complete(system="s", messages=[], tools=[{"name": "get_threat"}])
    assert resp.stop_reason == "tool_use"  # normalized to Anthropic-style
    assert resp.tool_calls[0]["id"] == "call_1"
    assert resp.tool_calls[0]["name"] == "get_threat"
    assert resp.tool_calls[0]["input"] == {"id": "t1"}


# --- contract: both adapters return the same LLMResponse shape --------------


def test_router_build_returns_complete_capable_clients():
    local = ProviderRouter(name="local").build(
        base_url="http://x", session=_FakeHTTP(_openai_payload())
    )
    hosted = ProviderRouter(name="anthropic").build(sdk_client=_FakeSDK())
    assert hasattr(local, "complete") and hasattr(hosted, "complete")


def test_both_adapters_return_identical_response_fields():
    local = ProviderRouter(name="local").build(
        base_url="http://x", session=_FakeHTTP(_openai_payload())
    )
    hosted = ProviderRouter(name="anthropic").build(sdk_client=_FakeSDK())
    local_resp = local.complete(system="s", messages=[{"role": "user", "content": "x"}])
    hosted_resp = hosted.complete(
        system="s", messages=[{"role": "user", "content": "x"}]
    )
    assert isinstance(local_resp, LLMResponse) and isinstance(hosted_resp, LLMResponse)
    assert set(vars(local_resp)) == set(vars(hosted_resp))


# --- app wiring: the build site routes through ProviderRouter ----------------


def test_app_make_inference_client_selects_local(monkeypatch):
    monkeypatch.setenv("INFERENCE_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://llamacpp:8080")
    import app

    client = app.make_inference_client()
    assert type(client).__name__ == "LocalLLMClient"
    assert client.base_url == "http://llamacpp:8080"


# --- credential scoping: hosted key never reaches the local endpoint ---------


def test_local_provider_does_not_inherit_anthropic_key(monkeypatch):
    monkeypatch.setenv("INFERENCE_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://llamacpp:8080")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-hosted-secret")
    monkeypatch.delenv("LOCAL_LLM_API_KEY", raising=False)
    client = ProviderRouter.from_env().build()
    assert client.api_key is None  # hosted credential not forwarded


def test_local_provider_uses_its_own_key(monkeypatch):
    monkeypatch.setenv("INFERENCE_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://llamacpp:8080")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-hosted-secret")
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "local-endpoint-key")
    client = ProviderRouter.from_env().build()
    assert client.api_key == "local-endpoint-key"
