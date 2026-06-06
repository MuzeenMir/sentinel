"""Tests for cost/limit controls."""

from anthropic_client import CLASSIFY_MODEL, DEFAULT_SYNTHESIS_MODEL
from cost import cache_hit_ratio, estimate_cost_usd, resolve_token_budget, select_model


def test_select_model_routes_classify_to_haiku():
    assert select_model("classify") == CLASSIFY_MODEL


def test_select_model_defaults_to_opus_for_synthesis():
    assert select_model("summarize") == DEFAULT_SYNTHESIS_MODEL
    assert select_model("anything-else") == DEFAULT_SYNTHESIS_MODEL


def test_cache_hit_ratio_computed():
    usage = {"input_tokens": 30, "cache_read_input_tokens": 70}
    assert cache_hit_ratio(usage) == 0.7


def test_cache_hit_ratio_zero_when_no_input():
    assert cache_hit_ratio({"input_tokens": 0, "cache_read_input_tokens": 0}) == 0.0


def test_estimate_cost_is_positive_and_model_sensitive():
    usage = {"input_tokens": 1000, "output_tokens": 1000}
    opus = estimate_cost_usd(usage, DEFAULT_SYNTHESIS_MODEL)
    haiku = estimate_cost_usd(usage, CLASSIFY_MODEL)
    assert opus > 0 and haiku > 0
    assert opus > haiku


def test_resolve_token_budget_from_env(monkeypatch):
    monkeypatch.setenv("COPILOT_MAX_TOTAL_TOKENS", "12345")
    assert resolve_token_budget() == 12345


def test_resolve_token_budget_default(monkeypatch):
    monkeypatch.delenv("COPILOT_MAX_TOTAL_TOKENS", raising=False)
    assert resolve_token_budget() > 0
