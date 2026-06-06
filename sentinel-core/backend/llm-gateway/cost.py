"""Cost and limit controls.

- Model routing: cheap classification on Haiku, synthesis on Opus.
- Cache-hit ratio from usage (prompt caching effectiveness).
- Rough USD cost estimate for budgeting/metrics.
- Token budget resolved from env.

Pricing constants are approximate (USD per 1M tokens) and used only for
relative budgeting/metrics, not billing.
"""

from __future__ import annotations

import os

from anthropic_client import CLASSIFY_MODEL, DEFAULT_SYNTHESIS_MODEL

DEFAULT_TOKEN_BUDGET = 100_000

# Approximate USD per 1M tokens (input, output).
_PRICING = {
    DEFAULT_SYNTHESIS_MODEL: (15.0, 75.0),
    CLASSIFY_MODEL: (1.0, 5.0),
}

_CLASSIFY_TASKS = {"classify", "triage", "route"}


def select_model(task: str) -> str:
    return CLASSIFY_MODEL if task in _CLASSIFY_TASKS else DEFAULT_SYNTHESIS_MODEL


def cache_hit_ratio(usage: dict) -> float:
    fresh = usage.get("input_tokens", 0)
    cached = usage.get("cache_read_input_tokens", 0)
    total = fresh + cached
    if total <= 0:
        return 0.0
    return cached / total


def estimate_cost_usd(usage: dict, model: str) -> float:
    rate_in, rate_out = _PRICING.get(model, _PRICING[DEFAULT_SYNTHESIS_MODEL])
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    return (inp / 1_000_000) * rate_in + (out / 1_000_000) * rate_out


def resolve_token_budget() -> int:
    raw = os.environ.get("COPILOT_MAX_TOTAL_TOKENS")
    if raw and raw.isdigit():
        return int(raw)
    return DEFAULT_TOKEN_BUDGET
