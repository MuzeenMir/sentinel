"""Tests for the Anthropic client wrapper.

The wrapper must work without the `anthropic` SDK installed (lazy import) and
must be injectable so tests never touch the network.
"""

from types import SimpleNamespace

import pytest

from anthropic_client import (
    AnthropicClient,
    LLMConfigError,
    LLMResponse,
)


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def _tool_block(tool_id, name, tool_input):
    return SimpleNamespace(type="tool_use", id=tool_id, name=name, input=tool_input)


def _response(blocks, stop_reason="end_turn", cache_read=0):
    return SimpleNamespace(
        content=blocks,
        stop_reason=stop_reason,
        usage=SimpleNamespace(
            input_tokens=10,
            output_tokens=5,
            cache_read_input_tokens=cache_read,
        ),
    )


class FakeMessages:
    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeSDK:
    def __init__(self, outcomes):
        self.messages = FakeMessages(outcomes)


class TransientError(Exception):
    def __init__(self):
        super().__init__("overloaded")
        self.status_code = 529


def test_complete_returns_normalized_text():
    sdk = FakeSDK([_response([_text_block("hello world")])])
    client = AnthropicClient(sdk_client=sdk)

    result = client.complete(system="sys", messages=[{"role": "user", "content": "hi"}])

    assert isinstance(result, LLMResponse)
    assert result.text == "hello world"
    assert result.stop_reason == "end_turn"
    assert result.tool_calls == []
    assert result.usage["input_tokens"] == 10


def test_complete_extracts_tool_calls():
    sdk = FakeSDK(
        [_response([_tool_block("t1", "get_threat_score", {"entity_id": "e1"})],
                   stop_reason="tool_use")]
    )
    client = AnthropicClient(sdk_client=sdk)

    result = client.complete(system="sys", messages=[{"role": "user", "content": "hi"}])

    assert result.stop_reason == "tool_use"
    assert result.tool_calls == [
        {"id": "t1", "name": "get_threat_score", "input": {"entity_id": "e1"}}
    ]


def test_retries_transient_then_succeeds():
    sdk = FakeSDK([TransientError(), TransientError(), _response([_text_block("ok")])])
    client = AnthropicClient(sdk_client=sdk, max_attempts=3, sleep_fn=lambda _s: None)

    result = client.complete(system="s", messages=[{"role": "user", "content": "x"}])

    assert result.text == "ok"
    assert len(sdk.messages.calls) == 3


def test_gives_up_after_max_attempts():
    sdk = FakeSDK([TransientError(), TransientError(), TransientError()])
    client = AnthropicClient(sdk_client=sdk, max_attempts=3, sleep_fn=lambda _s: None)

    with pytest.raises(TransientError):
        client.complete(system="s", messages=[{"role": "user", "content": "x"}])
    assert len(sdk.messages.calls) == 3


def test_system_prompt_marked_for_caching():
    sdk = FakeSDK([_response([_text_block("ok")])])
    client = AnthropicClient(sdk_client=sdk)

    client.complete(system="big system prompt", messages=[{"role": "user", "content": "x"}])

    sent = sdk.messages.calls[0]
    assert isinstance(sent["system"], list)
    assert sent["system"][-1]["cache_control"] == {"type": "ephemeral"}
    assert sent["system"][-1]["text"] == "big system prompt"


def test_tools_marked_for_caching():
    sdk = FakeSDK([_response([_text_block("ok")])])
    client = AnthropicClient(sdk_client=sdk)
    tools = [{"name": "t", "description": "d", "input_schema": {"type": "object"}}]

    client.complete(
        system="s", messages=[{"role": "user", "content": "x"}], tools=tools
    )

    sent = sdk.messages.calls[0]
    assert sent["tools"][-1]["cache_control"] == {"type": "ephemeral"}


def test_missing_api_key_without_injected_client_raises():
    with pytest.raises(LLMConfigError):
        AnthropicClient(api_key="")


def test_default_model_is_latest_opus():
    sdk = FakeSDK([_response([_text_block("ok")])])
    client = AnthropicClient(sdk_client=sdk)
    client.complete(system="s", messages=[{"role": "user", "content": "x"}])
    assert sdk.messages.calls[0]["model"] == "claude-opus-4-8"
