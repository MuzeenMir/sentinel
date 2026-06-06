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
