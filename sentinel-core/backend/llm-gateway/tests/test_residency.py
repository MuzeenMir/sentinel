"""Tests for the inference residency / provider seam (C5).

This is a routing seam, not shipped EU-resident inference: setting a region only
points the client at the configured endpoint.
"""

from residency import (
    AnthropicProvider,
    ResidencyConfig,
    resolve_residency,
)


def test_default_is_unchanged_anthropic_endpoint():
    cfg = resolve_residency(env={})
    assert cfg.provider == "anthropic"
    assert cfg.region == "default"
    assert cfg.base_url is None
    assert cfg.is_default is True


def test_explicit_base_url_and_region_route_elsewhere():
    cfg = resolve_residency(
        env={
            "INFERENCE_REGION": "eu",
            "INFERENCE_BASE_URL": "https://eu.inference.example/v1",
        }
    )
    assert cfg.region == "eu"
    assert cfg.base_url == "https://eu.inference.example/v1"
    assert cfg.is_default is False


def test_self_hosted_provider_selected():
    cfg = resolve_residency(
        env={
            "INFERENCE_PROVIDER": "self_hosted",
            "INFERENCE_BASE_URL": "http://on-prem-llm:8000",
        }
    )
    assert cfg.provider == "self_hosted"
    assert cfg.base_url == "http://on-prem-llm:8000"
    assert cfg.is_default is False


def test_resolve_reads_injected_env_not_process_env():
    # env injection keeps the resolver pure/testable
    cfg = resolve_residency(env={"INFERENCE_REGION": "US"})
    assert cfg.region == "us"  # normalized lowercase


def test_provider_adapter_contract_is_callable():
    # Any on-prem provider implementing build_client(api_key, config) can drop in.
    provider = AnthropicProvider()
    assert hasattr(provider, "build_client")
    assert callable(provider.build_client)

    class FakeOnPremProvider:
        def __init__(self):
            self.built = None

        def build_client(self, api_key, config: ResidencyConfig):
            self.built = (api_key, config.base_url)
            return "fake-client"

    fake = FakeOnPremProvider()
    cfg = ResidencyConfig(provider="self_hosted", region="on_prem", base_url="http://x")
    assert fake.build_client("k", cfg) == "fake-client"
    assert fake.built == ("k", "http://x")
