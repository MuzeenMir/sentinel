"""FastAPI parity tests for the api-gateway port."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api-gateway"))

os.environ.setdefault("AUTH_SERVICE_URL", "http://auth-service:5000")
os.environ.setdefault("DATA_COLLECTOR_URL", "http://data-collector:5001")
os.environ.setdefault("ALERT_SERVICE_URL", "http://alert-service:5002")
os.environ.setdefault("POLICY_SERVICE_URL", "http://policy-orchestrator:5004")
os.environ.setdefault("COMPLIANCE_ENGINE_URL", "http://compliance-engine:5007")
os.environ.setdefault("XAI_SERVICE_URL", "http://xai-service:5006")
os.environ.setdefault("AI_ENGINE_URL", "http://ai-engine:5003")
os.environ.setdefault("DRL_ENGINE_URL", "http://drl-engine:5005")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")

_redis_patcher = patch("redis.from_url")
_mock_redis_from_url = _redis_patcher.start()
_mock_redis_instance = MagicMock()
_mock_redis_from_url.return_value = _mock_redis_instance

import app as flask_gateway  # noqa: E402
from asgi_app import asgi  # noqa: E402

_redis_patcher.stop()


@pytest.fixture()
def flask_client():
    flask_gateway.app.config["TESTING"] = True
    flask_gateway.limiter.enabled = False
    with flask_gateway.app.test_client() as client:
        yield client


@pytest.fixture()
def asgi_client():
    return TestClient(asgi)


@pytest.fixture(autouse=True)
def _patch_redis_clients():
    mock_rc = MagicMock()
    mock_rc.get.return_value = None
    mock_rc.scan_iter.return_value = iter([])
    mock_rc.incr.return_value = 1
    with patch.object(flask_gateway, "redis_client", mock_rc):
        yield mock_rc


def test_health_matches_flask_shape(flask_client, asgi_client):
    flask_response = flask_client.get("/health")
    asgi_response = asgi_client.get("/health")

    assert asgi_response.status_code == flask_response.status_code == 200
    flask_body = flask_response.get_json()
    asgi_body = asgi_response.json()

    assert asgi_body["status"] == flask_body["status"] == "healthy"
    assert isinstance(asgi_body["timestamp"], float)
    assert asgi_body["request_stats"] == flask_body["request_stats"]


def test_readyz_reports_ready(asgi_client):
    response = asgi_client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
