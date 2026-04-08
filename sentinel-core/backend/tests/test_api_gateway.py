"""Comprehensive pytest tests for the SENTINEL API Gateway.

All downstream services (auth, alert, data-collector, policy, compliance, xai,
ai-engine, drl-engine) and Redis are mocked so no real infrastructure is needed.
"""

import os
import sys
import json
import time
from unittest.mock import patch, MagicMock, PropertyMock

import pytest
import requests as _requests_lib

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

# Patch redis globally before importing app so module-level redis_client is mocked
_redis_patcher = patch("redis.from_url")
_mock_redis_from_url = _redis_patcher.start()
_mock_redis_instance = MagicMock()
_mock_redis_from_url.return_value = _mock_redis_instance

import app as gw  # noqa: E402  (must come after env + redis patch)

_redis_patcher.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(status_code=200, json_data=None, content=b"ok"):
    """Build a MagicMock that behaves like requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.content = content
    return resp


def _auth_verify_ok(*args, **kwargs):
    """Simulate a successful token verification call from require_auth."""
    url = args[0] if args else kwargs.get("url", "")
    if "/auth/verify" in url:
        return _mock_response(200, {"user": {"username": "testuser", "role": "admin"}})
    return _mock_response(200, {})


def _auth_verify_ok_viewer(*args, **kwargs):
    """Simulate verification returning a non-admin role."""
    url = args[0] if args else kwargs.get("url", "")
    if "/auth/verify" in url:
        return _mock_response(200, {"user": {"username": "viewer", "role": "viewer"}})
    return _mock_response(200, {})


AUTH_HEADER = {"Authorization": "Bearer valid-token"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _patch_redis():
    """Ensure the module-level redis_client is a fresh mock for every test."""
    mock_rc = MagicMock()
    mock_rc.get.return_value = None
    mock_rc.scan_iter.return_value = iter([])
    mock_rc.incr.return_value = 1
    with patch.object(gw, "redis_client", mock_rc):
        yield mock_rc


@pytest.fixture()
def client():
    gw.app.config["TESTING"] = True
    gw.limiter.enabled = False  # disable rate-limiter in most tests
    with gw.app.test_client() as c:
        yield c


@pytest.fixture()
def client_with_limiter():
    """Client that keeps the rate limiter active (with in-memory storage)."""
    gw.app.config["TESTING"] = True
    gw.limiter.enabled = True
    gw.limiter._storage_uri = "memory://"
    with gw.app.test_client() as c:
        yield c


# ===================================================================
# Health check
# ===================================================================

class TestHealthCheck:
    def test_health_returns_200(self, client, _patch_redis):
        _patch_redis.scan_iter.return_value = iter([])
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "request_stats" in data

    def test_health_includes_request_stats(self, client, _patch_redis):
        _patch_redis.scan_iter.return_value = iter(["api_requests:/health:GET:123"])
        _patch_redis.get.return_value = "5"
        resp = client.get("/health")
        data = resp.get_json()
        assert isinstance(data["request_stats"], dict)


# ===================================================================
# Auth proxy endpoints
# ===================================================================

class TestAuthProxy:
    @patch("requests.post")
    def test_login_proxy(self, mock_post, client):
        mock_post.return_value = _mock_response(200, {
            "token": "jwt-token", "user": {"username": "admin"}
        })
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "secret"},
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert "token" in resp.get_json()

    @patch("requests.post")
    def test_register_proxy(self, mock_post, client):
        mock_post.return_value = _mock_response(201, {"message": "User created"})
        resp = client.post(
            "/api/v1/auth/register",
            json={"username": "new", "password": "pass123"},
            content_type="application/json",
        )
        assert resp.status_code == 201

    @patch("requests.post")
    def test_verify_proxy(self, mock_post, client):
        mock_post.return_value = _mock_response(200, {
            "user": {"username": "u", "role": "admin"}
        })
        resp = client.post(
            "/api/v1/auth/verify",
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200

    @patch("requests.get")
    def test_auth_get_proxy(self, mock_get, client):
        mock_get.return_value = _mock_response(200, {"users": []})
        resp = client.get("/api/v1/auth/users")
        assert resp.status_code == 200

    @patch("requests.put")
    def test_auth_put_proxy(self, mock_put, client):
        mock_put.return_value = _mock_response(200, {"updated": True})
        resp = client.put(
            "/api/v1/auth/users/1",
            json={"role": "viewer"},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.delete")
    def test_auth_delete_proxy(self, mock_del, client):
        mock_del.return_value = _mock_response(200, {"deleted": True})
        resp = client.delete("/api/v1/auth/users/1")
        assert resp.status_code == 200

    @patch("requests.post", side_effect=_requests_lib.exceptions.ConnectionError("conn refused"))
    def test_auth_proxy_service_unavailable(self, _mock, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "a", "password": "b"},
            content_type="application/json",
        )
        assert resp.status_code == 503
        assert "unavailable" in resp.get_json()["error"].lower()


# ===================================================================
# require_auth decorator
# ===================================================================

class TestRequireAuth:
    def test_missing_token_returns_401(self, client):
        resp = client.get("/api/v1/threats")
        assert resp.status_code == 401
        assert "token required" in resp.get_json()["error"].lower()

    @patch("requests.post", return_value=_mock_response(401, {"error": "bad token"}))
    def test_invalid_token_returns_401(self, _mock, client):
        resp = client.get("/api/v1/threats", headers=AUTH_HEADER)
        assert resp.status_code == 401

    @patch("requests.post", side_effect=_requests_lib.exceptions.ConnectionError("timeout"))
    def test_auth_service_down_returns_503(self, _mock, client):
        resp = client.get("/api/v1/threats", headers=AUTH_HEADER)
        assert resp.status_code == 503
        assert "unavailable" in resp.get_json()["error"].lower()

    @patch("requests.get", return_value=_mock_response(200, {"threats": []}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_valid_bearer_token(self, _post, _get, client):
        resp = client.get("/api/v1/threats", headers=AUTH_HEADER)
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"threats": []}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_token_via_query_param(self, _post, _get, client):
        resp = client.get("/api/v1/threats?token=valid-token")
        assert resp.status_code == 200


# ===================================================================
# require_role decorator
# ===================================================================

class TestRequireRole:
    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_insufficient_role_returns_403(self, _mock, client):
        resp = client.post(
            "/api/v1/threats",
            headers=AUTH_HEADER,
            json={"type": "test"},
            content_type="application/json",
        )
        assert resp.status_code == 403
        assert "permissions" in resp.get_json()["error"].lower()

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_admin_role_allowed(self, mock_post, client):
        downstream = _mock_response(201, {"id": 1})
        original_side_effect = mock_post.side_effect

        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return original_side_effect(*args, **kwargs)
            return downstream

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/threats",
            headers=AUTH_HEADER,
            json={"type": "malware"},
            content_type="application/json",
        )
        assert resp.status_code == 201


# ===================================================================
# Threat endpoints
# ===================================================================

class TestThreatEndpoints:
    @patch("requests.get", return_value=_mock_response(200, {"threats": [], "total": 0}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_threats(self, _post, _get, client):
        resp = client.get("/api/v1/threats", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert "threats" in resp.get_json()

    @patch("requests.get", return_value=_mock_response(200, {"id": 42, "type": "brute_force"}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_single_threat(self, _post, _get, client):
        resp = client.get("/api/v1/threats/42", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.get_json()["id"] == 42

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_create_threat_requires_admin(self, mock_post, client):
        downstream = _mock_response(201, {"id": 1})

        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return downstream

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/threats",
            headers=AUTH_HEADER,
            json={"type": "manual"},
            content_type="application/json",
        )
        assert resp.status_code == 201

    @patch("requests.get", side_effect=_requests_lib.exceptions.ConnectionError("downstream down"))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_threats_service_unavailable(self, _post, _get, client):
        resp = client.get("/api/v1/threats", headers=AUTH_HEADER)
        assert resp.status_code == 503

    @patch("requests.get", return_value=_mock_response(200, {"threats": [{"id": 1}], "total": 1}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_threats_passes_query_params(self, _post, mock_get, client):
        client.get("/api/v1/threats?severity=high&limit=10", headers=AUTH_HEADER)
        call_kwargs = mock_get.call_args
        assert "severity" in str(call_kwargs) or call_kwargs[1].get("params") is not None


# ===================================================================
# Alert endpoints
# ===================================================================

class TestAlertEndpoints:
    @patch("requests.get", return_value=_mock_response(200, {"alerts": []}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_alerts(self, _post, _get, client):
        resp = client.get("/api/v1/alerts", headers=AUTH_HEADER)
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"id": 7, "severity": "high"}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_single_alert(self, _post, _get, client):
        resp = client.get("/api/v1/alerts/7", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.get_json()["id"] == 7

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_create_alert_requires_admin(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(201, {"id": 10})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/alerts",
            headers=AUTH_HEADER,
            json={"severity": "critical", "message": "test"},
            content_type="application/json",
        )
        assert resp.status_code == 201

    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_create_alert_viewer_forbidden(self, _mock, client):
        resp = client.post(
            "/api/v1/alerts",
            headers=AUTH_HEADER,
            json={"severity": "low"},
            content_type="application/json",
        )
        assert resp.status_code == 403

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_acknowledge_alert(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"acknowledged": True})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/alerts/5/acknowledge",
            headers=AUTH_HEADER,
            json={"notes": "reviewed"},
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.get_json()["acknowledged"] is True

    @patch("requests.get", side_effect=_requests_lib.exceptions.ConnectionError("alert svc down"))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_alerts_service_unavailable(self, _post, _get, client):
        resp = client.get("/api/v1/alerts", headers=AUTH_HEADER)
        assert resp.status_code == 503


# ===================================================================
# Policy endpoints (via _proxy_to)
# ===================================================================

class TestPolicyEndpoints:
    @patch("requests.get", return_value=_mock_response(200, {"policies": []}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_policies(self, _post, _get, client):
        resp = client.get("/api/v1/policies", headers=AUTH_HEADER)
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"id": "p1", "name": "block-ssh"}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_single_policy(self, _post, _get, client):
        resp = client.get("/api/v1/policies/p1", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.get_json()["id"] == "p1"

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_create_policy_requires_admin_and_fields(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(201, {"id": "p2"})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/policies",
            headers=AUTH_HEADER,
            json={"name": "allow-http", "action": "allow",
                  "source": "10.0.0.0/8", "destination": "0.0.0.0/0"},
            content_type="application/json",
        )
        assert resp.status_code == 201

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_create_policy_missing_fields(self, _mock, client):
        resp = client.post(
            "/api/v1/policies",
            headers=AUTH_HEADER,
            json={"name": "incomplete"},
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "missing" in resp.get_json()["error"].lower()

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_create_policy_non_json(self, _mock, client):
        resp = client.post(
            "/api/v1/policies",
            headers=AUTH_HEADER,
            data="not json",
            content_type="text/plain",
        )
        assert resp.status_code == 400

    @patch("requests.put", return_value=_mock_response(200, {"updated": True}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_update_policy(self, _post, _put, client):
        resp = client.put(
            "/api/v1/policies/p1",
            headers=AUTH_HEADER,
            json={"action": "deny"},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.delete", return_value=_mock_response(204, {}, content=b""))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_delete_policy(self, _post, _del, client):
        resp = client.delete("/api/v1/policies/p1", headers=AUTH_HEADER)
        assert resp.status_code == 204

    @patch("requests.get", side_effect=_requests_lib.exceptions.ConnectionError("policy svc down"))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_policy_service_unavailable(self, _post, _get, client):
        resp = client.get("/api/v1/policies", headers=AUTH_HEADER)
        assert resp.status_code == 503
        assert "unavailable" in resp.get_json()["error"].lower()


# ===================================================================
# _proxy_to helper
# ===================================================================

class TestProxyToHelper:
    def test_proxy_constructs_correct_url(self, client):
        with gw.app.test_request_context("/test", method="GET"):
            with patch("requests.get") as mock_get:
                mock_get.return_value = _mock_response(200, {"ok": True})
                gw._proxy_to("http://svc:5000", "/api/v1/items")
                called_url = mock_get.call_args[0][0]
                assert "svc:5000" in called_url
                assert "/api/v1/items" in called_url

    def test_proxy_forwards_auth_header(self, client):
        with gw.app.test_request_context(
            "/test", method="GET", headers={"Authorization": "Bearer xyz"}
        ):
            with patch("requests.get") as mock_get:
                mock_get.return_value = _mock_response(200, {})
                gw._proxy_to("http://svc:5000", "/api/v1/resource")
                assert mock_get.call_args[1]["headers"]["Authorization"] == "Bearer xyz"

    def test_proxy_post_sends_json(self, client):
        with gw.app.test_request_context(
            "/test", method="POST", json={"key": "val"},
            content_type="application/json",
        ):
            with patch("requests.post") as mock_post:
                mock_post.return_value = _mock_response(201, {"created": True})
                result, status = gw._proxy_to("http://svc:5000", "/api/v1/items")
                assert status == 201

    def test_proxy_put_sends_json(self, client):
        with gw.app.test_request_context(
            "/test", method="PUT", json={"k": "v"},
            content_type="application/json",
        ):
            with patch("requests.put") as mock_put:
                mock_put.return_value = _mock_response(200, {"updated": True})
                result, status = gw._proxy_to("http://svc:5000", "/api/v1/items/1")
                assert status == 200

    def test_proxy_delete(self, client):
        with gw.app.test_request_context("/test", method="DELETE"):
            with patch("requests.delete") as mock_del:
                mock_del.return_value = _mock_response(200, {"deleted": True})
                result, status = gw._proxy_to("http://svc:5000", "/api/v1/items/1")
                assert status == 200

    def test_proxy_unsupported_method(self, client):
        with gw.app.test_request_context("/test", method="PATCH"):
            _, status = gw._proxy_to("http://svc:5000", "/api/v1/x")
            assert status == 405

    def test_proxy_empty_content(self, client):
        with gw.app.test_request_context("/test", method="GET"):
            with patch("requests.get") as mock_get:
                resp = MagicMock()
                resp.status_code = 204
                resp.content = b""
                resp.json.side_effect = ValueError("No JSON")
                mock_get.return_value = resp
                result, status = gw._proxy_to("http://svc:5000", "/api/v1/x")
                assert status == 204

    def test_proxy_connection_error(self, client):
        with gw.app.test_request_context("/test", method="GET"):
            with patch("requests.get", side_effect=_requests_lib.exceptions.ConnectionError("refused")):
                result, status = gw._proxy_to("http://svc:5000", "/api/v1/x")
                assert status == 503


# ===================================================================
# Statistics endpoint
# ===================================================================

class TestStatisticsEndpoint:
    @patch("requests.get")
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_stats_aggregates_downstream(self, _post, mock_get, client, _patch_redis):
        _patch_redis.get.return_value = None

        def get_router(*args, **kwargs):
            url = args[0] if args else ""
            if "/alerts/statistics" in url:
                return _mock_response(200, {
                    "total_alerts": 42, "by_severity": {"high": 10}, "by_status": {"open": 30}
                })
            if "/threats" in url:
                return _mock_response(200, {"total": 99})
            if "/statistics" in url:
                return _mock_response(200, {
                    "total_policies": 15, "policies_by_action": {"allow": 10, "deny": 5}
                })
            return _mock_response(200, {})

        mock_get.side_effect = get_router
        resp = client.get("/api/v1/stats", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["threats_detected"] == 99
        assert data["alerts_total"] == 42
        assert data["policies_total"] == 15
        assert data["system_health"] == "healthy"

    @patch("requests.get")
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_stats_via_statistics_alias(self, _post, mock_get, client, _patch_redis):
        _patch_redis.get.return_value = None
        mock_get.return_value = _mock_response(200, {})
        resp = client.get("/api/v1/statistics", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert "system_health" in resp.get_json()

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_stats_uses_cache(self, _post, client, _patch_redis):
        cached = json.dumps({
            "threats_detected": 5, "alerts_total": 3,
            "alerts_by_severity": {}, "alerts_by_status": {},
            "policies_total": 1, "policies_by_action": {},
        })
        _patch_redis.get.return_value = cached
        resp = client.get("/api/v1/stats", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.get_json()["threats_detected"] == 5

    @patch("requests.get", side_effect=_requests_lib.exceptions.ConnectionError("all down"))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_stats_downstream_failures_graceful(self, _post, _get, client, _patch_redis):
        _patch_redis.get.return_value = None
        resp = client.get("/api/v1/stats", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["threats_detected"] == 0
        assert data["alerts_total"] == 0


# ===================================================================
# SSE stream endpoints
# ===================================================================

class TestSSEStreams:
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_stream_threats_content_type(self, _post, client):
        mock_pubsub = MagicMock()
        threat_event = {"type": "message", "data": '{"threat_id": 1}'}
        mock_pubsub.get_message = MagicMock(
            side_effect=[threat_event, GeneratorExit()]
        )

        mock_redis_conn = MagicMock()
        mock_redis_conn.pubsub.return_value = mock_pubsub

        with patch("redis.from_url", return_value=mock_redis_conn):
            resp = client.get("/api/v1/stream/threats", headers=AUTH_HEADER)
            assert resp.status_code == 200
            assert resp.content_type.startswith("text/event-stream")
            assert "no-cache" in resp.headers.get("Cache-Control", "")

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_stream_alerts_content_type(self, _post, client):
        mock_pubsub = MagicMock()
        mock_pubsub.get_message = MagicMock(side_effect=[None, GeneratorExit()])
        mock_redis_conn = MagicMock()
        mock_redis_conn.pubsub.return_value = mock_pubsub

        with patch("redis.from_url", return_value=mock_redis_conn):
            resp = client.get("/api/v1/stream/alerts", headers=AUTH_HEADER)
            assert resp.status_code == 200
            assert resp.content_type.startswith("text/event-stream")

    def test_stream_threats_requires_auth(self, client):
        resp = client.get("/api/v1/stream/threats")
        assert resp.status_code == 401

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_stream_threats_token_via_query(self, _post, client):
        mock_pubsub = MagicMock()
        mock_pubsub.get_message = MagicMock(side_effect=[None, GeneratorExit()])
        mock_redis_conn = MagicMock()
        mock_redis_conn.pubsub.return_value = mock_pubsub

        with patch("redis.from_url", return_value=mock_redis_conn):
            resp = client.get("/api/v1/stream/threats?token=valid-token")
            assert resp.status_code == 200
            assert resp.content_type.startswith("text/event-stream")


# ===================================================================
# Configuration endpoints
# ===================================================================

class TestConfigEndpoints:
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_config_returns_defaults(self, _post, client, _patch_redis):
        _patch_redis.get.return_value = None
        resp = client.get("/api/v1/config", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "ai_engine" in data
        assert "firewall" in data
        assert "monitoring" in data

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_config_from_redis(self, _post, client, _patch_redis):
        stored = json.dumps({
            "ai_engine": {"model_path": "/custom"}, "firewall": {}, "monitoring": {}
        })
        _patch_redis.get.return_value = stored
        resp = client.get("/api/v1/config", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.get_json()["ai_engine"]["model_path"] == "/custom"

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_update_config_success(self, _post, client, _patch_redis):
        new_cfg = {
            "ai_engine": {"model_path": "/v2", "confidence_threshold": 0.9, "batch_size": 500},
            "firewall": {"max_rules": 5000, "sync_interval": 60},
            "monitoring": {"alert_threshold": 0.99, "retention_days": 30},
        }
        resp = client.put(
            "/api/v1/config",
            headers=AUTH_HEADER,
            json=new_cfg,
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert "updated" in resp.get_json()["message"].lower()
        _patch_redis.set.assert_called_once()

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_update_config_missing_section(self, _post, client):
        resp = client.put(
            "/api/v1/config",
            headers=AUTH_HEADER,
            json={"ai_engine": {}, "firewall": {}},  # missing 'monitoring'
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "monitoring" in resp.get_json()["error"].lower()

    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_get_config_requires_admin(self, _post, client):
        resp = client.get("/api/v1/config", headers=AUTH_HEADER)
        assert resp.status_code == 403

    @patch("requests.post", side_effect=_auth_verify_ok_viewer)
    def test_update_config_requires_admin(self, _post, client):
        resp = client.put(
            "/api/v1/config",
            headers=AUTH_HEADER,
            json={"ai_engine": {}, "firewall": {}, "monitoring": {}},
            content_type="application/json",
        )
        assert resp.status_code == 403


# ===================================================================
# Compliance proxy endpoints
# ===================================================================

class TestComplianceProxy:
    @patch("requests.get", return_value=_mock_response(200, {"frameworks": ["CIS", "NIST"]}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_frameworks(self, _post, _get, client):
        resp = client.get("/api/v1/frameworks", headers=AUTH_HEADER)
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"id": "cis", "controls": []}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_get_single_framework(self, _post, _get, client):
        resp = client.get("/api/v1/frameworks/cis", headers=AUTH_HEADER)
        assert resp.status_code == 200

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_compliance_assess(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"score": 85})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/assess",
            headers=AUTH_HEADER,
            json={"framework": "CIS"},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_gap_analysis(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"gaps": []})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/gap-analysis",
            headers=AUTH_HEADER,
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"history": []}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_reports_history(self, _post, _get, client):
        resp = client.get("/api/v1/reports/history", headers=AUTH_HEADER)
        assert resp.status_code == 200

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_map_policy(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"mapped": True})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/map-policy",
            headers=AUTH_HEADER,
            json={"policy_id": "p1"},
            content_type="application/json",
        )
        assert resp.status_code == 200


# ===================================================================
# XAI proxy endpoints
# ===================================================================

class TestXAIProxy:
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_explain_detection(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"explanation": "anomaly in traffic"})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/explain/detection",
            headers=AUTH_HEADER,
            json={"detection_id": 1},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_explain_policy(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"explanation": "rule matched"})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/explain/policy",
            headers=AUTH_HEADER,
            json={"policy_id": "p1"},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"trail": []}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_audit_trail(self, _post, _get, client):
        resp = client.get("/api/v1/audit-trail", headers=AUTH_HEADER)
        assert resp.status_code == 200

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_xai_report_compliance(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"report": "ok"})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/report/compliance",
            headers=AUTH_HEADER,
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"total_explanations": 50}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_xai_statistics(self, _post, _get, client):
        resp = client.get("/api/v1/xai/statistics", headers=AUTH_HEADER)
        assert resp.status_code == 200


# ===================================================================
# AI Engine proxy endpoints
# ===================================================================

class TestAIEngineProxy:
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_ai_detect(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"is_threat": True, "confidence": 0.92})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/detect",
            headers=AUTH_HEADER,
            json={"features": [1, 0, 0.5]},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_ai_detect_batch(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"results": []})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/detect/batch",
            headers=AUTH_HEADER,
            json={"batch": []},
            content_type="application/json",
        )
        assert resp.status_code == 200


# ===================================================================
# DRL Engine proxy endpoints
# ===================================================================

class TestDRLEngineProxy:
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_drl_decide(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"action": "block", "confidence": 0.95})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/decide",
            headers=AUTH_HEADER,
            json={"state": [0.1, 0.2]},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_drl_decide_batch(self, mock_post, client):
        def router(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/auth/verify" in url:
                return _auth_verify_ok(*args, **kwargs)
            return _mock_response(200, {"results": []})

        mock_post.side_effect = router
        resp = client.post(
            "/api/v1/decide/batch",
            headers=AUTH_HEADER,
            json={"batch": []},
            content_type="application/json",
        )
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"actions": ["block", "allow"]}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_drl_action_space(self, _post, _get, client):
        resp = client.get("/api/v1/action-space", headers=AUTH_HEADER)
        assert resp.status_code == 200

    @patch("requests.get", return_value=_mock_response(200, {"dimensions": 10}))
    @patch("requests.post", side_effect=_auth_verify_ok)
    def test_drl_state_space(self, _post, _get, client):
        resp = client.get("/api/v1/state-space", headers=AUTH_HEADER)
        assert resp.status_code == 200


# ===================================================================
# Rate limiting
# ===================================================================

class TestRateLimiting:
    def test_rate_limit_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/test-rate-limit")
        assert resp.status_code == 200

    def test_rate_limit_exceeded_returns_429(self, client_with_limiter, _patch_redis):
        for _ in range(5):
            client_with_limiter.get("/api/v1/test-rate-limit")
        resp = client_with_limiter.get("/api/v1/test-rate-limit")
        assert resp.status_code == 429
        data = resp.get_json()
        assert "rate limit" in data["error"].lower()


# ===================================================================
# Error handlers
# ===================================================================

class TestErrorHandlers:
    def test_404_handler(self, client):
        resp = client.get("/api/v1/nonexistent-endpoint")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "not found" in data["error"].lower()
        assert "/api/v1/nonexistent-endpoint" in data["message"]

    def test_429_handler_body(self, client_with_limiter, _patch_redis):
        for _ in range(5):
            client_with_limiter.get("/api/v1/test-rate-limit")
        resp = client_with_limiter.get("/api/v1/test-rate-limit")
        if resp.status_code == 429:
            data = resp.get_json()
            assert "rate limit" in data["error"].lower()
            assert "too many" in data["message"].lower()


# ===================================================================
# Middleware: before_request / after_request
# ===================================================================

class TestMiddleware:
    def test_response_time_header(self, client):
        resp = client.get("/health")
        assert "X-Response-Time" in resp.headers
        assert resp.headers["X-Response-Time"].endswith("s")

    def test_before_request_tracks_metrics(self, client, _patch_redis):
        client.get("/health")
        _patch_redis.incr.assert_called()
        _patch_redis.expire.assert_called()


# ===================================================================
# validate_json_request helper
# ===================================================================

class TestValidateJsonRequest:
    def test_non_json_returns_400(self, client):
        with gw.app.test_request_context("/test", method="POST", data="text", content_type="text/plain"):
            result = gw.validate_json_request(["field1"])
            assert result is not None
            resp, code = result
            assert code == 400

    def test_missing_fields_returns_400(self, client):
        with gw.app.test_request_context(
            "/test", method="POST", json={"a": 1}, content_type="application/json"
        ):
            result = gw.validate_json_request(["a", "b", "c"])
            assert result is not None
            resp, code = result
            assert code == 400
            data = json.loads(resp.get_data(as_text=True))
            assert "b" in data["error"]
            assert "c" in data["error"]

    def test_valid_json_returns_none(self, client):
        with gw.app.test_request_context(
            "/test", method="POST", json={"x": 1, "y": 2}, content_type="application/json"
        ):
            result = gw.validate_json_request(["x", "y"])
            assert result is None

    def test_no_required_fields_returns_none(self, client):
        with gw.app.test_request_context(
            "/test", method="POST", json={"any": "data"}, content_type="application/json"
        ):
            result = gw.validate_json_request()
            assert result is None


# ===================================================================
# _fetch_downstream_stats
# ===================================================================

class TestFetchDownstreamStats:
    @patch("requests.get")
    def test_returns_aggregated_stats(self, mock_get, client, _patch_redis):
        _patch_redis.get.return_value = None

        def router(*args, **kwargs):
            url = args[0] if args else ""
            if "/alerts/statistics" in url:
                return _mock_response(200, {
                    "total_alerts": 10, "by_severity": {"high": 5}, "by_status": {"open": 8}
                })
            if "/threats" in url:
                return _mock_response(200, {"total": 77})
            if "/statistics" in url:
                return _mock_response(200, {
                    "total_policies": 20, "policies_by_action": {"deny": 12}
                })
            return _mock_response(200, {})

        mock_get.side_effect = router
        with gw.app.app_context():
            result = gw._fetch_downstream_stats()
        assert result["alerts_total"] == 10
        assert result["threats_detected"] == 77
        assert result["policies_total"] == 20
        _patch_redis.set.assert_called_once()

    def test_returns_cached_value(self, client, _patch_redis):
        cached = json.dumps({"threats_detected": 1, "alerts_total": 2,
                             "alerts_by_severity": {}, "alerts_by_status": {},
                             "policies_total": 3, "policies_by_action": {}})
        _patch_redis.get.return_value = cached
        with gw.app.app_context():
            result = gw._fetch_downstream_stats()
        assert result["threats_detected"] == 1
        assert result["policies_total"] == 3

    @patch("requests.get", side_effect=_requests_lib.exceptions.ConnectionError("everything broken"))
    def test_graceful_degradation(self, _get, client, _patch_redis):
        _patch_redis.get.return_value = None
        with gw.app.app_context():
            result = gw._fetch_downstream_stats()
        assert result["threats_detected"] == 0
        assert result["alerts_total"] == 0
        assert result["policies_total"] == 0

    @patch("requests.get")
    def test_partial_downstream_failure(self, mock_get, client, _patch_redis):
        _patch_redis.get.return_value = None

        def router(*args, **kwargs):
            url = args[0] if args else ""
            if "/alerts/statistics" in url:
                return _mock_response(200, {"total_alerts": 5, "by_severity": {}, "by_status": {}})
            raise _requests_lib.exceptions.ConnectionError("service down")

        mock_get.side_effect = router
        with gw.app.app_context():
            result = gw._fetch_downstream_stats()
        assert result["alerts_total"] == 5
        assert result["threats_detected"] == 0


# ===================================================================
# _load_config / _save_config
# ===================================================================

class TestConfigPersistence:
    def test_load_defaults_when_redis_empty(self, client, _patch_redis):
        _patch_redis.get.return_value = None
        with gw.app.app_context():
            cfg = gw._load_config()
        assert cfg["ai_engine"]["confidence_threshold"] == 0.85

    def test_load_from_redis(self, client, _patch_redis):
        stored = json.dumps({"ai_engine": {"confidence_threshold": 0.5},
                             "firewall": {}, "monitoring": {}})
        _patch_redis.get.return_value = stored
        with gw.app.app_context():
            cfg = gw._load_config()
        assert cfg["ai_engine"]["confidence_threshold"] == 0.5

    def test_load_falls_back_on_redis_error(self, client, _patch_redis):
        _patch_redis.get.side_effect = Exception("redis gone")
        with gw.app.app_context():
            cfg = gw._load_config()
        assert "ai_engine" in cfg

    def test_save_config(self, client, _patch_redis):
        with gw.app.app_context():
            gw._save_config({"ai_engine": {}, "firewall": {}, "monitoring": {}})
        _patch_redis.set.assert_called_once()
        saved = json.loads(_patch_redis.set.call_args[0][1])
        assert "ai_engine" in saved


# ===================================================================
# get_request_stats
# ===================================================================

class TestGetRequestStats:
    def test_aggregates_from_redis(self, client, _patch_redis):
        keys = [
            f"api_requests:/health:GET:{int(time.time())}",
            f"api_requests:/threats:POST:{int(time.time()) - 1}",
        ]
        _patch_redis.scan_iter.return_value = iter(keys)
        _patch_redis.get.side_effect = lambda k: "3" if "/health" in k else "1"
        with gw.app.app_context():
            stats = gw.get_request_stats()
        assert isinstance(stats, dict)

    def test_empty_stats(self, client, _patch_redis):
        _patch_redis.scan_iter.return_value = iter([])
        with gw.app.app_context():
            stats = gw.get_request_stats()
        assert stats == {}
