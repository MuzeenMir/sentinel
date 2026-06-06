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
            return LocalLLMClient(**kwargs)

        from anthropic_client import AnthropicClient

        return AnthropicClient(**kwargs)
