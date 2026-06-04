"""Inference residency / provider seam (C5).

Selects WHERE copilot inference runs from config, so an EU-resident or on-prem
deployment is a **config swap, not a code change**. Default behavior is unchanged
(the SDK's default Anthropic endpoint).

Honest boundary: this is a *routing* seam. Setting a region/base_url only points
the client at the configured endpoint — it does NOT by itself make inference
"EU-resident". Real data residency is a deployment + contractual property of the
endpoint you configure. ADR-021 documents this; do not market EU-resident
inference unless an EU-resident endpoint is actually configured and contracted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable

# Known region -> base_url. None => SDK default endpoint. An EU/on-prem endpoint
# is supplied explicitly via INFERENCE_BASE_URL (kept out of source on purpose).
_REGION_ENDPOINTS: dict[str, Optional[str]] = {
    "default": None,
    "us": None,
}


@dataclass(frozen=True)
class ResidencyConfig:
    provider: str  # "anthropic" | "self_hosted" | ...
    region: str  # "default" | "us" | "eu" | "on_prem" | ...
    base_url: Optional[str]  # explicit endpoint; None => SDK default

    @property
    def is_default(self) -> bool:
        """True when nothing routes inference away from the default endpoint."""
        return self.provider == "anthropic" and self.base_url is None


def resolve_residency(env: Optional[dict] = None) -> ResidencyConfig:
    source = os.environ if env is None else env
    provider = (source.get("INFERENCE_PROVIDER") or "anthropic").strip().lower()
    region = (source.get("INFERENCE_REGION") or "default").strip().lower()
    base_url = (source.get("INFERENCE_BASE_URL") or "").strip() or None
    if base_url is None:
        base_url = _REGION_ENDPOINTS.get(region)
    return ResidencyConfig(provider=provider, region=region, base_url=base_url)


@runtime_checkable
class InferenceProvider(Protocol):
    """Adapter contract: build an SDK-compatible client for a residency config.

    A self-hosted/on-prem provider implements this to swap inference without
    touching the gateway. The returned object must expose ``messages.create``.
    """

    def build_client(self, api_key: Optional[str], config: ResidencyConfig) -> Any: ...


class AnthropicProvider:
    """Default provider: the Anthropic SDK, optionally pointed at ``base_url``."""

    def build_client(self, api_key: Optional[str], config: ResidencyConfig) -> Any:
        import anthropic  # lazy: only when a real client is built

        kwargs: dict[str, Any] = {"api_key": api_key or None}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        return anthropic.Anthropic(**kwargs)
