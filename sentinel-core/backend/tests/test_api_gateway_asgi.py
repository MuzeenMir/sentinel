"""FastAPI parity tests for the api-gateway port."""

import os
import sys
from pathlib import Path
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
    with (
        patch.object(flask_gateway, "redis_client", mock_rc),
        patch.object(asgi_app.core, "redis_client", mock_rc),
    ):
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


def test_gateway_core_is_framework_agnostic_and_asgi_does_not_import_flask_app():
    gateway_dir = Path(__file__).resolve().parents[1] / "api-gateway"
    core_source = (gateway_dir / "gateway_core.py").read_text(encoding="utf-8")
    asgi_source = (gateway_dir / "asgi_app.py").read_text(encoding="utf-8")

    assert "from flask" not in core_source
    assert "import flask" not in core_source
    assert "import app as flask_gateway" not in asgi_source


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


@patch("requests.get")
@patch("requests.post")
def test_get_alerts_strips_query_token(mock_post, mock_get, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    mock_get.return_value = _response(200, {"alerts": []})

    response = asgi_client.get("/api/v1/alerts?token=valid-token&status=open")

    assert response.status_code == 200
    assert response.json() == {"alerts": []}
    assert mock_get.call_args.args[0] == "http://alert-service:5002/api/v1/alerts"
    assert mock_get.call_args.kwargs["params"] == {"status": "open"}


@patch("requests.get")
@patch("requests.post")
def test_get_alert_detail(mock_post, mock_get, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    mock_get.return_value = _response(200, {"id": 7, "severity": "high"})

    response = asgi_client.get(
        "/api/v1/alerts/7", headers={"Authorization": "Bearer valid-token"}
    )

    assert response.status_code == 200
    assert response.json() == {"id": 7, "severity": "high"}
    assert mock_get.call_args.args[0] == "http://alert-service:5002/api/v1/alerts/7"


@patch("requests.post")
def test_create_alert_admin_proxy(mock_post, asgi_client):
    def side_effect(url, **kwargs):
        if "/auth/verify" in url:
            return _response(200, {"user": {"username": "admin", "role": "admin"}})
        return _response(201, {"id": 10})

    mock_post.side_effect = side_effect

    response = asgi_client.post(
        "/api/v1/alerts",
        headers={"Authorization": "Bearer valid-token"},
        json={"severity": "high"},
    )

    assert response.status_code == 201
    assert response.json() == {"id": 10}
    assert mock_post.call_args.args[0] == "http://alert-service:5002/api/v1/alerts"


@patch("requests.post")
def test_acknowledge_alert_admin_proxy(mock_post, asgi_client):
    def side_effect(url, **kwargs):
        if "/auth/verify" in url:
            return _response(200, {"user": {"username": "admin", "role": "admin"}})
        return _response(200, {"acknowledged": True})

    mock_post.side_effect = side_effect

    response = asgi_client.post(
        "/api/v1/alerts/7/acknowledge",
        headers={"Authorization": "Bearer valid-token"},
        json={"note": "seen"},
    )

    assert response.status_code == 200
    assert response.json() == {"acknowledged": True}
    assert mock_post.call_args.args[0] == (
        "http://alert-service:5002/api/v1/alerts/7/acknowledge"
    )


@patch("requests.post")
def test_resolve_alert_admin_proxy(mock_post, asgi_client):
    def side_effect(url, **kwargs):
        if "/auth/verify" in url:
            return _response(200, {"user": {"username": "admin", "role": "admin"}})
        return _response(200, {"resolved": True})

    mock_post.side_effect = side_effect

    response = asgi_client.post(
        "/api/v1/alerts/7/resolve",
        headers={"Authorization": "Bearer valid-token"},
        json={"resolution": "fixed"},
    )

    assert response.status_code == 200
    assert response.json() == {"resolved": True}
    assert mock_post.call_args.args[0] == (
        "http://alert-service:5002/api/v1/alerts/7/resolve"
    )


@patch("requests.put")
@patch("requests.post")
def test_update_alert_admin_proxy(mock_post, mock_put, asgi_client):
    mock_post.return_value = _response(
        200, {"user": {"username": "admin", "role": "admin"}}
    )
    mock_put.return_value = _response(200, {"updated": True})

    response = asgi_client.put(
        "/api/v1/alerts/7",
        headers={"Authorization": "Bearer valid-token"},
        json={"status": "ignored"},
    )

    assert response.status_code == 200
    assert response.json() == {"updated": True}
    assert mock_put.call_args.args[0] == "http://alert-service:5002/api/v1/alerts/7"


@patch("requests.get")
@patch("requests.post")
def test_get_alert_stats_proxy(mock_post, mock_get, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    mock_get.return_value = _response(200, {"total_alerts": 3})

    response = asgi_client.get(
        "/api/v1/alerts/stats",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"total_alerts": 3}
    assert mock_get.call_args.args[0] == (
        "http://alert-service:5002/api/v1/alerts/statistics"
    )


@patch("requests.post")
def test_get_config_returns_defaults(mock_post, asgi_client, _patch_redis_clients):
    mock_post.return_value = _response(
        200, {"user": {"username": "admin", "role": "admin"}}
    )
    _patch_redis_clients.get.return_value = None

    response = asgi_client.get(
        "/api/v1/config",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert response.json()["ai_engine"]["model_path"] == "/models/current_model.pkl"


@patch("requests.post")
def test_update_config_persists_admin_change(
    mock_post, asgi_client, _patch_redis_clients
):
    mock_post.return_value = _response(
        200, {"user": {"username": "admin", "role": "admin"}}
    )
    new_config = {
        "ai_engine": {"model_path": "/custom"},
        "firewall": {"max_rules": 100},
        "monitoring": {"retention_days": 30},
    }

    response = asgi_client.put(
        "/api/v1/config",
        headers={"Authorization": "Bearer valid-token"},
        json=new_config,
    )

    assert response.status_code == 200
    assert "updated" in response.json()["message"].lower()
    _patch_redis_clients.set.assert_called_once()


@patch("requests.post")
def test_update_config_requires_all_sections(mock_post, asgi_client):
    mock_post.return_value = _response(
        200, {"user": {"username": "admin", "role": "admin"}}
    )

    response = asgi_client.put(
        "/api/v1/config",
        headers={"Authorization": "Bearer valid-token"},
        json={"ai_engine": {}, "firewall": {}},
    )

    assert response.status_code == 400
    assert "monitoring" in response.json()["error"].lower()


@patch("requests.post")
def test_stats_aggregates_downstream(mock_post, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    with patch.object(
        asgi_app.core,
        "_fetch_downstream_stats",
        return_value={
            "threats_detected": 5,
            "alerts_total": 2,
            "alerts_by_severity": {"high": 1},
            "alerts_by_status": {"open": 2},
            "policies_total": 3,
            "policies_by_action": {"block": 1},
        },
    ):
        response = asgi_client.get(
            "/api/v1/stats",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["threats_detected"] == 5
    assert body["alerts_total"] == 2
    assert body["system_health"] == "healthy"


@patch("requests.post")
def test_statistics_alias_matches_stats(mock_post, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    with patch.object(
        asgi_app.core,
        "_fetch_downstream_stats",
        return_value={"threats_detected": 1},
    ):
        response = asgi_client.get(
            "/api/v1/statistics",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert response.status_code == 200
    assert response.json()["threats_detected"] == 1


@patch("requests.post")
def test_stats_runtime_misconfiguration_returns_503(mock_post, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    with patch.object(
        asgi_app.core,
        "_fetch_downstream_stats",
        side_effect=RuntimeError("missing token"),
    ):
        response = asgi_client.get(
            "/api/v1/stats",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert response.status_code == 503
    assert response.json() == {"error": "Statistics service misconfigured"}


@patch("requests.post")
def test_stream_threats_content_type(mock_post, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    mock_pubsub = MagicMock()
    mock_pubsub.get_message = MagicMock(side_effect=[None, GeneratorExit()])
    mock_redis_conn = MagicMock()
    mock_redis_conn.pubsub.return_value = mock_pubsub

    with patch("redis.from_url", return_value=mock_redis_conn):
        with asgi_client.stream(
            "GET",
            "/api/v1/stream/threats",
            headers={"Authorization": "Bearer valid-token"},
        ) as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            assert "no-cache" in response.headers.get("cache-control", "")


def test_stream_threats_requires_auth(asgi_client):
    response = asgi_client.get("/api/v1/stream/threats")

    assert response.status_code == 401
    assert response.json() == {"error": "Authorization token required"}


def test_404_handler_matches_gateway_shape(asgi_client):
    response = asgi_client.get("/api/v1/nonexistent-endpoint")

    assert response.status_code == 404
    assert response.json() == {
        "error": "Endpoint not found",
        "message": "The requested endpoint /api/v1/nonexistent-endpoint does not exist",
    }


@patch("requests.get")
@patch("requests.post")
def test_get_threat_detail_proxy(mock_post, mock_get, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    mock_get.return_value = _response(200, {"id": 42, "type": "brute_force"})

    response = asgi_client.get(
        "/api/v1/threats/42",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"id": 42, "type": "brute_force"}
    assert mock_get.call_args.args[0] == "http://data-collector:5001/api/v1/threats/42"


@patch("requests.post")
def test_create_policy_validates_required_fields(mock_post, asgi_client):
    mock_post.return_value = _response(
        200, {"user": {"username": "admin", "role": "admin"}}
    )

    response = asgi_client.post(
        "/api/v1/policies",
        headers={"Authorization": "Bearer valid-token"},
        json={"name": "incomplete"},
    )

    assert response.status_code == 400
    assert "missing required fields" in response.json()["error"].lower()


@patch("requests.post")
def test_create_policy_rejects_non_json(mock_post, asgi_client):
    mock_post.return_value = _response(
        200, {"user": {"username": "admin", "role": "admin"}}
    )

    response = asgi_client.post(
        "/api/v1/policies",
        headers={
            "Authorization": "Bearer valid-token",
            "Content-Type": "text/plain",
        },
        content="not json",
    )

    assert response.status_code == 400
    assert response.json() == {"error": "Content-Type must be application/json"}


@pytest.mark.parametrize(
    ("method", "path", "expected_url", "expected_status", "body"),
    [
        (
            "GET",
            "/api/v1/policies",
            "http://policy-orchestrator:5004/api/v1/policies",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/policies/p1",
            "http://policy-orchestrator:5004/api/v1/policies/p1",
            200,
            None,
        ),
        (
            "PUT",
            "/api/v1/policies/p1",
            "http://policy-orchestrator:5004/api/v1/policies/p1",
            200,
            {"action": "deny"},
        ),
        (
            "DELETE",
            "/api/v1/policies/p1",
            "http://policy-orchestrator:5004/api/v1/policies/p1",
            204,
            None,
        ),
        (
            "GET",
            "/api/v1/frameworks",
            "http://compliance-engine:5007/api/v1/frameworks",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/frameworks/cis",
            "http://compliance-engine:5007/api/v1/frameworks/cis",
            200,
            None,
        ),
        (
            "POST",
            "/api/v1/assess",
            "http://compliance-engine:5007/api/v1/assess",
            200,
            {"framework": "CIS"},
        ),
        (
            "POST",
            "/api/v1/gap-analysis",
            "http://compliance-engine:5007/api/v1/gap-analysis",
            200,
            {},
        ),
        (
            "POST",
            "/api/v1/reports",
            "http://compliance-engine:5007/api/v1/reports",
            200,
            {},
        ),
        (
            "GET",
            "/api/v1/reports/history",
            "http://compliance-engine:5007/api/v1/reports/history",
            200,
            None,
        ),
        (
            "POST",
            "/api/v1/map-policy",
            "http://compliance-engine:5007/api/v1/map-policy",
            200,
            {"policy_id": "p1"},
        ),
        (
            "POST",
            "/api/v1/explain/detection",
            "http://xai-service:5006/api/v1/explain/detection",
            200,
            {"detection_id": 1},
        ),
        (
            "POST",
            "/api/v1/explain/policy",
            "http://xai-service:5006/api/v1/explain/policy",
            200,
            {"policy_id": "p1"},
        ),
        (
            "GET",
            "/api/v1/audit-trail",
            "http://xai-service:5006/api/v1/audit-trail",
            200,
            None,
        ),
        (
            "POST",
            "/api/v1/report/compliance",
            "http://xai-service:5006/api/v1/report/compliance",
            200,
            {},
        ),
        (
            "GET",
            "/api/v1/xai/statistics",
            "http://xai-service:5006/api/v1/statistics",
            200,
            None,
        ),
        (
            "POST",
            "/api/v1/detect",
            "http://ai-engine:5003/api/v1/detect",
            200,
            {"packet": "sample"},
        ),
        (
            "POST",
            "/api/v1/detect/batch",
            "http://ai-engine:5003/api/v1/detect/batch",
            200,
            {"packets": []},
        ),
        (
            "POST",
            "/api/v1/decide",
            "http://drl-engine:5005/api/v1/decide",
            200,
            {"state": {}},
        ),
        (
            "POST",
            "/api/v1/decide/batch",
            "http://drl-engine:5005/api/v1/decide/batch",
            200,
            {"states": []},
        ),
        (
            "GET",
            "/api/v1/action-space",
            "http://drl-engine:5005/api/v1/action-space",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/state-space",
            "http://drl-engine:5005/api/v1/state-space",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/hardening/scan",
            "http://hardening-service:5011/api/v1/hardening/scan",
            200,
            None,
        ),
        (
            "POST",
            "/api/v1/hardening/scan",
            "http://hardening-service:5011/api/v1/hardening/scan",
            200,
            {},
        ),
        (
            "GET",
            "/api/v1/hardening/posture",
            "http://hardening-service:5011/api/v1/hardening/posture",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/hardening/remediations",
            "http://hardening-service:5011/api/v1/hardening/remediations",
            200,
            None,
        ),
        (
            "POST",
            "/api/v1/hardening/remediate/check-1",
            "http://hardening-service:5011/api/v1/hardening/remediate/check-1",
            200,
            {},
        ),
        (
            "GET",
            "/api/v1/hids/events",
            "http://hids-agent:5010/api/v1/hids/events",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/hids/alerts",
            "http://hids-agent:5010/api/v1/hids/alerts",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/hids/status",
            "http://hids-agent:5010/api/v1/hids/status",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/admin/users",
            "http://auth-service:5000/api/v1/auth/users",
            200,
            None,
        ),
        (
            "PUT",
            "/api/v1/admin/users/1",
            "http://auth-service:5000/api/v1/auth/users/1",
            200,
            {"role": "viewer"},
        ),
        (
            "GET",
            "/api/v1/traffic",
            "http://data-collector:5001/api/v1/traffic",
            200,
            None,
        ),
        (
            "GET",
            "/api/v1/tenants",
            "http://auth-service:5000/api/v1/tenants",
            200,
            None,
        ),
        (
            "POST",
            "/api/v1/tenants",
            "http://auth-service:5000/api/v1/tenants",
            200,
            {"name": "tenant-a"},
        ),
        (
            "GET",
            "/api/v1/tenants/1",
            "http://auth-service:5000/api/v1/tenants/1",
            200,
            None,
        ),
        (
            "PUT",
            "/api/v1/tenants/1",
            "http://auth-service:5000/api/v1/tenants/1",
            200,
            {"status": "active"},
        ),
        (
            "DELETE",
            "/api/v1/tenants/1",
            "http://auth-service:5000/api/v1/tenants/1",
            204,
            None,
        ),
        (
            "GET",
            "/api/v1/integrations",
            "http://alert-service:5002/api/v1/integrations",
            200,
            None,
        ),
        (
            "POST",
            "/api/v1/integrations",
            "http://alert-service:5002/api/v1/integrations",
            200,
            {"kind": "siem"},
        ),
        (
            "POST",
            "/api/v1/integrations/test",
            "http://alert-service:5002/api/v1/integrations/test",
            200,
            {"id": 1},
        ),
    ],
)
@patch("requests.delete")
@patch("requests.put")
@patch("requests.get")
@patch("requests.post")
def test_remaining_proxy_routes(
    mock_post,
    mock_get,
    mock_put,
    mock_delete,
    method,
    path,
    expected_url,
    expected_status,
    body,
    asgi_client,
):
    def post_side_effect(url, **kwargs):
        if "/auth/verify" in url:
            return _response(200, {"user": {"username": "admin", "role": "admin"}})
        return _response(expected_status, {"ok": True})

    mock_post.side_effect = post_side_effect
    mock_get.return_value = _response(expected_status, {"ok": True})
    mock_put.return_value = _response(expected_status, {"ok": True})
    mock_delete.return_value = _response(expected_status, {}, content=b"")

    response = asgi_client.request(
        method,
        path,
        headers={"Authorization": "Bearer valid-token"},
        json=body,
    )

    assert response.status_code == expected_status
    called_mock = {
        "GET": mock_get,
        "POST": mock_post,
        "PUT": mock_put,
        "DELETE": mock_delete,
    }[method]
    if method == "POST":
        assert called_mock.call_args_list[-1].args[0] == expected_url
    else:
        assert called_mock.call_args.args[0] == expected_url


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/admin/users"),
        ("PUT", "/api/v1/admin/users/1"),
        ("POST", "/api/v1/tenants"),
        ("PUT", "/api/v1/tenants/1"),
        ("DELETE", "/api/v1/tenants/1"),
    ],
)
@patch("requests.post")
def test_admin_and_tenant_mutations_require_admin(mock_post, method, path, asgi_client):
    mock_post.return_value = _response(
        200, {"user": {"username": "viewer", "role": "viewer"}}
    )

    response = asgi_client.request(
        method,
        path,
        headers={"Authorization": "Bearer valid-token"},
        json={"role": "admin"} if method in {"POST", "PUT"} else None,
    )

    assert response.status_code == 403
    assert response.json() == {"error": "Insufficient permissions"}


@patch.object(asgi_app.core, "query_audit_log")
@patch("requests.post")
def test_audit_events_reads_local_audit_log(mock_post, mock_query, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    mock_query.return_value = [{"id": "evt-1"}]

    response = asgi_client.get(
        "/api/v1/audit/events?category=login&limit=5000&offset=2",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"events": [{"id": "evt-1"}], "count": 1}
    assert mock_query.call_args.kwargs["category"] == "login"
    assert mock_query.call_args.kwargs["limit"] == 1000
    assert mock_query.call_args.kwargs["offset"] == 2


@patch.object(asgi_app.core, "get_audit_stats", return_value={"total": 3})
@patch("requests.post")
def test_audit_stats_reads_local_stats(mock_post, _stats, asgi_client):
    mock_post.side_effect = _auth_verify_ok

    response = asgi_client.get(
        "/api/v1/audit/stats",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"total": 3}


@patch.object(asgi_app.core, "verify_integrity")
@patch("requests.post")
def test_audit_verify_checks_record_integrity(mock_post, mock_verify, asgi_client):
    mock_post.side_effect = _auth_verify_ok
    mock_verify.return_value = True

    response = asgi_client.post(
        "/api/v1/audit/verify",
        headers={"Authorization": "Bearer valid-token"},
        json={"records": [{"id": "evt-1"}]},
    )

    assert response.status_code == 200
    assert response.json() == {"results": [{"id": "evt-1", "valid": True}], "total": 1}


@patch("requests.post")
def test_audit_categories_lists_categories(mock_post, asgi_client):
    mock_post.side_effect = _auth_verify_ok

    response = asgi_client.get(
        "/api/v1/audit/categories",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert "categories" in response.json()


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


def _response(status_code=200, json_data=None, content=b"ok"):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data or {}
    response.content = content
    return response


def _auth_verify_ok(*args, **kwargs):
    url = args[0] if args else kwargs.get("url", "")
    if "/auth/verify" in url:
        return _response(200, {"user": {"username": "testuser", "role": "admin"}})
    return _response(200, {})
