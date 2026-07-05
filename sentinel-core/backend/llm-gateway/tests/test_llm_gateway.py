"""Health/readiness tests for the LLM Gateway Flask app."""


def test_health_returns_200(client):
    rv = client.get("/health")
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "llm-gateway"
    assert "timestamp" in data


def test_readyz_reports_dependencies(client):
    rv = client.get("/readyz")
    assert rv.status_code == 200
    data = rv.get_json()
    # readiness reflects whether inference is configured; without an API key
    # the gateway is "ready" to serve health but reports inference disabled.
    assert "inference_enabled" in data
    assert data["inference_enabled"] is False


def test_inference_enabled_true_for_local_provider(app_module, monkeypatch):
    """INFERENCE_PROVIDER=local needs a base URL, not an Anthropic key."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("INFERENCE_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:11434")
    assert app_module.inference_enabled() is True


def test_inference_enabled_false_for_local_provider_without_base_url(
    app_module, monkeypatch
):
    """Local provider fails closed when no endpoint URL is configured."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("INFERENCE_PROVIDER", "local")
    monkeypatch.delenv("LOCAL_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("INFERENCE_BASE_URL", raising=False)
    assert app_module.inference_enabled() is False


def test_inference_enabled_true_for_anthropic_with_key(app_module, monkeypatch):
    monkeypatch.delenv("INFERENCE_PROVIDER", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert app_module.inference_enabled() is True
