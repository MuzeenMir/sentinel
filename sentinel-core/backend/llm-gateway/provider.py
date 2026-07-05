"""C1 — inference provider abstraction.

``ProviderRouter`` selects which inference backend serves copilot answers:

- ``anthropic`` (default): the hosted Anthropic Messages API via
  :class:`anthropic_client.AnthropicClient`.
- ``local``: a self-hostable, OpenAI-compatible llama.cpp / Gemma endpoint via
  :class:`local_client.LocalLLMClient`.

Both adapters expose the same ``complete(system, messages, tools, ...) ->
LLMResponse`` contract, so a regulated/on-prem buyer who cannot send incident
data to a hosted API switches inference with a **config change, not a code
change**. Selection is read from ``INFERENCE_PROVIDER`` (shared with
``residency.resolve_residency``).
"""

from __future__ import annotations

import os
from typing import Any, Optional

# INFERENCE_PROVIDER values that route to the self-hosted adapter.
_LOCAL_NAMES = {"local", "llama_cpp", "llamacpp", "self_hosted", "on_prem"}

# The offline node's locked working default (see the production-pivot spec:
# Qwen2.5-14B-Instruct on a local GPU via Ollama). Overridable per deployment
# with LOCAL_LLM_MODEL (e.g. "qwen2.5:7b" for low-VRAM hosts). This is the
# model name sent to the OpenAI-compatible endpoint; it must match the tag the
# local server actually serves.
NODE_DEFAULT_LOCAL_MODEL = "qwen2.5:14b-instruct"


class ProviderRouter:
    """Selects and builds the inference client for the configured provider."""

    def __init__(self, name: str):
        self.name = name

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "ProviderRouter":
        source = os.environ if env is None else env
        raw = (source.get("INFERENCE_PROVIDER") or "anthropic").strip().lower()
        name = "local" if raw in _LOCAL_NAMES else "anthropic"
        return cls(name)

    def build(self, env: Optional[dict] = None, **kwargs: Any) -> Any:
        """Construct the inference client for the selected provider.

        Both returned clients expose the same
        ``complete(system, messages, tools, ...) -> LLMResponse`` contract.
        Extra ``kwargs`` (``sdk_client=`` / ``session=`` / ``api_key=`` …) pass
        through to the adapter, keeping construction injectable for tests.
        """
        source = os.environ if env is None else env
        if self.name == "local":
            from local_client import LocalLLMClient

            if "base_url" not in kwargs:
                kwargs["base_url"] = (
                    source.get("LOCAL_LLM_BASE_URL")
                    or source.get("INFERENCE_BASE_URL")
                    or ""
                )
            # Credential scoping: the local endpoint authenticates with its
            # own key. The hosted Anthropic credential must never be sent to
            # a non-Anthropic endpoint.
            if "api_key" not in kwargs:
                kwargs["api_key"] = source.get("LOCAL_LLM_API_KEY")
            # Node model selection: default to the spec-locked Qwen, overridable
            # per host with LOCAL_LLM_MODEL.
            if "default_model" not in kwargs:
                kwargs["default_model"] = (
                    source.get("LOCAL_LLM_MODEL") or NODE_DEFAULT_LOCAL_MODEL
                )
            # Per-call budget: CPU-only hosts need more than the 60s default.
            if "timeout" not in kwargs and source.get("LOCAL_LLM_TIMEOUT"):
                kwargs["timeout"] = float(source["LOCAL_LLM_TIMEOUT"])
            return LocalLLMClient(**kwargs)

        from anthropic_client import AnthropicClient

        if "api_key" not in kwargs:
            kwargs["api_key"] = source.get("ANTHROPIC_API_KEY")
        return AnthropicClient(**kwargs)
