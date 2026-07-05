"""C1 — self-hostable local inference adapter (llama.cpp / Gemma).

Talks to an **OpenAI-compatible** ``/v1/chat/completions`` endpoint (llama.cpp's
server, vLLM, Ollama, etc.) and normalizes the reply into the same
:class:`anthropic_client.LLMResponse` the hosted adapter returns, so
``copilot.py`` is provider-agnostic.

Honest boundary: this is the inference *seam* that makes on-prem a config swap.
It does not ship a model — the operator points ``LOCAL_LLM_BASE_URL`` at a
running OpenAI-compatible server. No data leaves that endpoint.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from anthropic_client import LLMResponse

DEFAULT_LOCAL_MODEL = "gemma-2"

# OpenAI finish_reason -> Anthropic-style stop_reason, so downstream code that
# already branches on the Anthropic vocabulary keeps working unchanged.
_FINISH_MAP = {
    "stop": "end_turn",
    "length": "max_tokens",
    "tool_calls": "tool_use",
    "function_call": "tool_use",
    "content_filter": "stop_sequence",
}


class LocalLLMClient:
    def __init__(
        self,
        base_url: str,
        session: Any = None,
        api_key: Optional[str] = None,
        default_model: str = DEFAULT_LOCAL_MODEL,
        max_tokens: int = 2048,
        timeout: float = 60.0,
    ):
        if not base_url:
            from anthropic_client import LLMConfigError

            raise LLMConfigError(
                "LOCAL_LLM_BASE_URL is required for the local provider"
            )
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.api_key = api_key
        self._session = session  # injectable; lazily built if None

    # -- request -----------------------------------------------------------

    def _http(self):
        if self._session is None:
            import requests  # lazy: only when a real call is made

            self._session = requests.Session()
        return self._session

    @staticmethod
    def _to_openai_tools(tools: Optional[list[dict]]) -> list[dict]:
        out = []
        for t in tools or []:
            out.append(
                {
                    "type": "function",
                    "function": {
                        "name": t.get("name"),
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema", t.get("parameters", {})),
                    },
                }
            )
        return out

    @staticmethod
    def _to_openai_messages(system: str, messages: list[dict]) -> list[dict]:
        """Translate the copilot's Anthropic-style history to the OpenAI wire.

        The copilot appends assistant ``tool_use`` blocks and user-turn
        ``tool_result`` blocks; OpenAI-compatible servers expect assistant
        ``tool_calls`` entries and dedicated ``role: tool`` turns instead and
        reject the block lists outright.
        """
        out: list[dict] = [{"role": "system", "content": system}]
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                out.append({"role": msg["role"], "content": content})
                continue
            text_parts: list[str] = []
            tool_calls: list[dict] = []
            tool_results: list[dict] = []
            for block in content or []:
                btype = block.get("type")
                if btype == "text":
                    text_parts.append(block.get("text", ""))
                elif btype == "tool_use":
                    tool_calls.append(
                        {
                            "id": block.get("id"),
                            "type": "function",
                            "function": {
                                "name": block.get("name"),
                                "arguments": json.dumps(block.get("input", {})),
                            },
                        }
                    )
                elif btype == "tool_result":
                    tool_results.append(
                        {
                            "role": "tool",
                            "tool_call_id": block.get("tool_use_id"),
                            "content": block.get("content", ""),
                        }
                    )
            if msg.get("role") == "assistant":
                entry: dict[str, Any] = {
                    "role": "assistant",
                    "content": "\n".join(text_parts) or None,
                }
                if tool_calls:
                    entry["tool_calls"] = tool_calls
                out.append(entry)
            else:
                out.extend(tool_results)
                if text_parts:
                    out.append({"role": msg["role"], "content": "\n".join(text_parts)})
        return out

    def complete(
        self,
        system: str,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        body: dict[str, Any] = {
            "model": model or self.default_model,
            "max_tokens": max_tokens or self.max_tokens,
            "messages": self._to_openai_messages(system, messages),
        }
        if tools:
            body["tools"] = self._to_openai_tools(tools)

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        resp = self._http().post(
            f"{self.base_url}/v1/chat/completions",
            json=body,
            timeout=self.timeout,
            headers=headers,
        )
        resp.raise_for_status()
        return self._normalize(resp.json())

    # -- response ----------------------------------------------------------

    @staticmethod
    def _normalize(payload: dict) -> LLMResponse:
        choices = payload.get("choices") or [{}]
        choice = choices[0]
        message = choice.get("message", {}) or {}

        text = message.get("content") or ""

        tool_calls: list[dict] = []
        for call in message.get("tool_calls") or []:
            fn = call.get("function", {}) or {}
            args = fn.get("arguments", "{}")
            try:
                parsed = json.loads(args) if isinstance(args, str) else (args or {})
            except (ValueError, TypeError):
                parsed = {}
            tool_calls.append(
                {"id": call.get("id"), "name": fn.get("name"), "input": parsed}
            )

        finish = choice.get("finish_reason")
        stop_reason = _FINISH_MAP.get(finish, finish)

        usage_obj = payload.get("usage") or {}
        usage = {
            "input_tokens": usage_obj.get("prompt_tokens", 0),
            "output_tokens": usage_obj.get("completion_tokens", 0),
            "cache_read_input_tokens": usage_obj.get("cache_read_input_tokens", 0),
        }

        return LLMResponse(
            text=text,
            stop_reason=stop_reason,
            tool_calls=tool_calls,
            usage=usage,
            raw=payload,
        )
