"""Thin, testable wrapper around the Anthropic Messages API.

Design goals:
- **Lazy import**: the `anthropic` SDK is imported only when a real client is
  constructed, so the module (and tests) load without the package installed.
- **Injectable**: tests pass ``sdk_client=`` to avoid any network call.
- **Prompt caching**: system prompt and tool definitions are marked with
  ``cache_control`` so repeated calls hit the Anthropic prompt cache.
- **Resilient**: transient (5xx / 429 / overloaded) failures are retried with
  exponential backoff; everything else surfaces immediately.
- **Normalized**: returns an :class:`LLMResponse` regardless of SDK internals.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from residency import AnthropicProvider, ResidencyConfig, resolve_residency

# Latest Claude models (see CLAUDE.md / model IDs).
DEFAULT_SYNTHESIS_MODEL = "claude-opus-4-8"
CLASSIFY_MODEL = "claude-haiku-4-5"

# Status codes that are safe to retry.
_RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}
# SDK exception class names that are transient (matched without importing them).
_RETRY_NAMES = {
    "APIConnectionError",
    "APITimeoutError",
    "RateLimitError",
    "InternalServerError",
    "OverloadedError",
    "ServiceUnavailableError",
}


class LLMGatewayError(Exception):
    """Base class for gateway inference errors."""


class LLMConfigError(LLMGatewayError):
    """Raised when the client is misconfigured (e.g. no API key)."""


@dataclass
class LLMResponse:
    text: str
    stop_reason: Optional[str]
    tool_calls: list[dict] = field(default_factory=list)
    usage: dict = field(default_factory=dict)
    raw: Any = None


def _is_retryable(exc: Exception) -> bool:
    if getattr(exc, "status_code", None) in _RETRY_STATUS:
        return True
    return type(exc).__name__ in _RETRY_NAMES


class AnthropicClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        sdk_client: Any = None,
        default_model: str = DEFAULT_SYNTHESIS_MODEL,
        max_tokens: int = 2048,
        max_attempts: int = 3,
        backoff_base: float = 0.5,
        sleep_fn: Callable[[float], None] = time.sleep,
        residency: Optional[ResidencyConfig] = None,
        provider: Any = None,
    ):
        self.default_model = default_model
        self.max_tokens = max_tokens
        self.max_attempts = max_attempts
        self.backoff_base = backoff_base
        self._sleep = sleep_fn
        # Where inference routes (default endpoint unless configured otherwise).
        self.residency = residency if residency is not None else resolve_residency()

        if sdk_client is not None:
            self._sdk = sdk_client
            return

        # api_key is only required for a real client; "" is an explicit error
        # so misconfiguration fails fast rather than at first request.
        if api_key is not None and api_key == "":
            raise LLMConfigError("ANTHROPIC_API_KEY is required for inference")
        self._provider = provider or AnthropicProvider()
        try:
            self._sdk = self._provider.build_client(api_key, self.residency)
        except ImportError as exc:  # pragma: no cover - depends on env
            raise LLMConfigError(
                "anthropic SDK not installed; pass sdk_client= or install anthropic"
            ) from exc

    @staticmethod
    def _cached_system(system: str) -> list[dict]:
        return [
            {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
        ]

    @staticmethod
    def _cached_tools(tools: list[dict]) -> list[dict]:
        out = [dict(t) for t in tools]
        if out:
            out[-1]["cache_control"] = {"type": "ephemeral"}
        return out

    @staticmethod
    def _normalize(resp: Any) -> LLMResponse:
        text_parts: list[str] = []
        tool_calls: list[dict] = []
        for block in getattr(resp, "content", []) or []:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
            elif btype == "tool_use":
                tool_calls.append(
                    {
                        "id": getattr(block, "id", None),
                        "name": getattr(block, "name", None),
                        "input": getattr(block, "input", {}),
                    }
                )
        usage_obj = getattr(resp, "usage", None)
        usage = {}
        if usage_obj is not None:
            usage = {
                "input_tokens": getattr(usage_obj, "input_tokens", 0),
                "output_tokens": getattr(usage_obj, "output_tokens", 0),
                "cache_read_input_tokens": getattr(
                    usage_obj, "cache_read_input_tokens", 0
                ),
            }
        return LLMResponse(
            text="".join(text_parts),
            stop_reason=getattr(resp, "stop_reason", None),
            tool_calls=tool_calls,
            usage=usage,
            raw=resp,
        )

    def complete(
        self,
        system: str,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        params: dict[str, Any] = {
            "model": model or self.default_model,
            "max_tokens": max_tokens or self.max_tokens,
            "system": self._cached_system(system),
            "messages": messages,
        }
        if tools:
            params["tools"] = self._cached_tools(tools)

        last_exc: Optional[Exception] = None
        for attempt in range(self.max_attempts):
            try:
                resp = self._sdk.messages.create(**params)
                return self._normalize(resp)
            except Exception as exc:  # noqa: BLE001 - re-raised below
                last_exc = exc
                if attempt + 1 >= self.max_attempts or not _is_retryable(exc):
                    raise
                self._sleep(self.backoff_base * (2**attempt))
        # Unreachable: loop either returns or raises.
        raise last_exc  # type: ignore[misc]  # pragma: no cover
