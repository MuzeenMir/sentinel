"""FastAPI parity tests for the api-gateway port."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests as _requests_lib
from fastapi.testclient import TestClient
from starlette.datastructures import Headers, QueryParams
from starlette.requests import Request

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
import asgi_app  # noqa: E402
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


def test_auth_dependency_rejects_missing_token():
    request = _request()

    response = asgi_app.require_current_user(request)

    assert response.status_code == 401
    assert response.body == b'{"error":"Authorization token required"}'


@patch("requests.post", return_value=MagicMock(status_code=401))
def test_auth_dependency_rejects_invalid_token(_post):
    request = _request(headers={"authorization": "Bearer bad-token"})

    response = asgi_app.require_current_user(request)

    assert response.status_code == 401
    assert response.body == b'{"error":"Invalid token"}'


@patch(
    "requests.post",
    side_effect=_requests_lib.exceptions.ConnectionError("timeout"),
)
def test_auth_dependency_returns_503_when_auth_service_unavailable(_post):
    request = _request(headers={"authorization": "Bearer valid-token"})

    response = asgi_app.require_current_user(request)

    assert response.status_code == 503
    assert response.body == b'{"error":"Authentication service unavailable"}'


@patch("requests.post")
def test_auth_dependency_accepts_token_via_query_param(mock_post):
    mock_post.return_value = _response(
        200, {"user": {"username": "sse-user", "role": "viewer", "tenant_id": 7}}
    )
    request = _request(query_string="token=query-token")

    user = asgi_app.require_current_user(request)

    assert user == {"username": "sse-user", "role": "viewer", "tenant_id": 7}
    assert mock_post.call_args.kwargs["headers"] == {
        "Authorization": "Bearer query-token"
    }


def test_cors_preflight_uses_configured_allowlist(asgi_client):
    response = asgi_client.options(
        "/api/v1/test-rate-limit",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_rate_limit_endpoint_returns_200(asgi_client):
    response = asgi_client.get("/api/v1/test-rate-limit")

    assert response.status_code == 200
    assert response.json()["message"] == "Rate limit test successful"


def test_rate_limit_exceeded_returns_429(asgi_client):
    for _ in range(5):
        asgi_client.get("/api/v1/test-rate-limit")
    response = asgi_client.get("/api/v1/test-rate-limit")

    assert response.status_code == 429
    assert "rate limit" in response.json()["error"].lower()


@patch("requests.post")
def test_auth_login_proxy(mock_post, asgi_client):
    mock_post.return_value = _response(
        200, {"token": "jwt-token", "user": {"username": "admin"}}
    )

    response = asgi_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "secret"},
    )

    assert response.status_code == 200
    assert response.json() == {"token": "jwt-token", "user": {"username": "admin"}}
    assert mock_post.call_args.args[0] == "http://auth-service:5000/api/v1/auth/login"
    assert mock_post.call_args.kwargs["json"] == {
        "username": "admin",
        "password": "secret",
    }


@patch("requests.get")
def test_auth_get_proxy_strips_query_token_and_forwards_header(mock_get, asgi_client):
    mock_get.return_value = _response(200, {"users": []})

    response = asgi_client.get(
        "/api/v1/auth/users?token=secret&foo=bar",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"users": []}
    assert mock_get.call_args.args[0] == "http://auth-service:5000/api/v1/auth/users"
    assert mock_get.call_args.kwargs["params"] == {"foo": "bar"}
    assert mock_get.call_args.kwargs["headers"] == {
        "Authorization": "Bearer valid-token"
    }


@patch("requests.post")
def test_auth_verify_proxy(mock_post, asgi_client):
    mock_post.return_value = _response(
        200, {"user": {"username": "u", "role": "admin"}}
    )

    response = asgi_client.post(
        "/api/v1/auth/verify",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"user": {"username": "u", "role": "admin"}}
    assert mock_post.call_args.args[0] == (
        "http://auth-service:5000/api/v1/auth/verify"
    )
    assert mock_post.call_args.kwargs["headers"] == {
        "Authorization": "Bearer valid-token"
    }
    assert mock_post.call_args.kwargs["timeout"] == 5


@patch(
    "requests.post",
    side_effect=_requests_lib.exceptions.ConnectionError("conn refused"),
)
def test_auth_proxy_service_unavailable(_post, asgi_client):
    response = asgi_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "secret"},
    )

    assert response.status_code == 503
    assert response.json() == {"error": "Auth service unavailable"}


@patch("requests.get")
@patch("requests.post")
def test_get_threats_strips_query_token(mock_post, mock_get, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    mock_get.return_value = _response(200, {"threats": [{"id": 1}], "total": 1})

    response = asgi_client.get("/api/v1/threats?token=valid-token&foo=bar")

    assert response.status_code == 200
    assert response.json() == {"threats": [{"id": 1}], "total": 1}
    assert mock_get.call_args.args[0] == ("http://data-collector:5001/api/v1/threats")
    assert mock_get.call_args.kwargs["params"] == {"foo": "bar"}
    assert mock_get.call_args.kwargs["headers"] == {"Authorization": None}


@patch("requests.post")
def test_create_threat_admin_proxy(mock_post, asgi_client):
    def side_effect(url, **kwargs):
        if "/auth/verify" in url:
            return _response(200, {"user": {"username": "admin", "role": "admin"}})
        return _response(201, {"id": 1})

    mock_post.side_effect = side_effect

    response = asgi_client.post(
        "/api/v1/threats",
        headers={"Authorization": "Bearer valid-token"},
        json={"type": "manual"},
    )

    assert response.status_code == 201
    assert response.json() == {"id": 1}
    assert mock_post.call_args.args[0] == ("http://data-collector:5001/api/v1/threats")
    assert mock_post.call_args.kwargs["headers"] == {
        "Authorization": "Bearer valid-token"
    }
    assert mock_post.call_args.kwargs["json"] == {"type": "manual"}


@patch("requests.post")
def test_create_threat_viewer_forbidden(mock_post, asgi_client):
    mock_post.return_value = _response(
        200, {"user": {"username": "viewer", "role": "viewer"}}
    )

    response = asgi_client.post(
        "/api/v1/threats",
        headers={"Authorization": "Bearer valid-token"},
        json={"type": "manual"},
    )

    assert response.status_code == 403
    assert response.json() == {"error": "Insufficient permissions"}


def _request(
    *,
    headers: dict[str, str] | None = None,
    query_string: str = "",
) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/test",
        "headers": Headers(headers or {}).raw,
        "query_string": query_string.encode(),
    }
    request = Request(scope)
    request._query_params = QueryParams(query_string)  # noqa: SLF001
    return request


def _response(status_code=200, json_data=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {}
    return response


def _auth_verify_ok(*args, **kwargs):
    url = args[0] if args else kwargs.get("url", "")
    if "/auth/verify" in url:
        return _response(200, {"user": {"username": "testuser", "role": "admin"}})
    return _response(200, {})
