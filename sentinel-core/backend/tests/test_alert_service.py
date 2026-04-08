"""
Comprehensive tests for the SENTINEL Alert Service.

Covers Flask routes, AlertEngine logic, Redis interactions,
SSE publish, and email/Slack notification triggering.
All Redis and auth-service calls are mocked — nothing hits the network.
"""

import json
import os
import sys
import time
from datetime import datetime
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# Patch Redis and auth decorators BEFORE the alert-service module is imported
# so module-level code never touches real Redis or auth-service.
# ---------------------------------------------------------------------------

# Build a fake Redis that stores data in plain dicts so we can assert on it.
_fake_redis_store: dict = {}
_fake_redis_sets: dict = {}
_fake_redis_expiry: dict = {}
_fake_redis_publish_log: list = []


class _FakeRedis:
    """In-memory Redis stand-in used for unit tests."""

    def __init__(self, *args, **kwargs):
        pass

    # -- hash commands -------------------------------------------------------
    def hset(self, key, field=None, value=None, mapping=None):
        if key not in _fake_redis_store:
            _fake_redis_store[key] = {}
        if mapping:
            _fake_redis_store[key].update(mapping)
        elif field is not None:
            _fake_redis_store[key][field] = value

    def hgetall(self, key):
        return dict(_fake_redis_store.get(key, {}))

    # -- set commands --------------------------------------------------------
    def sadd(self, key, *values):
        if key not in _fake_redis_sets:
            _fake_redis_sets[key] = set()
        _fake_redis_sets[key].update(values)

    def srem(self, key, *values):
        if key in _fake_redis_sets:
            _fake_redis_sets[key] -= set(values)

    def smembers(self, key):
        return set(_fake_redis_sets.get(key, set()))

    def sinter(self, *keys):
        sets = [_fake_redis_sets.get(k, set()) for k in keys]
        if not sets:
            return set()
        return set.intersection(*sets)

    def scard(self, key):
        return len(_fake_redis_sets.get(key, set()))

    # -- key commands --------------------------------------------------------
    def expire(self, key, seconds):
        _fake_redis_expiry[key] = seconds

    # -- pub/sub -------------------------------------------------------------
    def publish(self, channel, message):
        _fake_redis_publish_log.append((channel, message))


def _noop_auth(fn):
    """Pass-through replacement for require_auth."""
    return fn


def _noop_role(*_roles):
    """Pass-through replacement for require_role."""
    def decorator(fn):
        return fn
    return decorator


# Patch redis module and auth decorators before importing the service.
_fake_redis_instance = _FakeRedis()
_fake_pool = MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "alert-service"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

with patch.dict("sys.modules", {
    "redis": MagicMock(
        ConnectionPool=MagicMock(from_url=MagicMock(return_value=_fake_pool)),
        Redis=MagicMock(return_value=_fake_redis_instance),
    ),
}), patch.dict("sys.modules", {
    "auth_middleware": MagicMock(
        require_auth=_noop_auth,
        require_role=_noop_role,
    ),
}):
    import importlib
    # Force a fresh import so module-level code uses our fakes
    if "app" in sys.modules:
        del sys.modules["app"]
    import app as alert_app

# Redirect the module-level redis_client to our fake
alert_app.redis_client = _fake_redis_instance


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_state():
    """Clear all fake Redis state between tests."""
    _fake_redis_store.clear()
    _fake_redis_sets.clear()
    _fake_redis_expiry.clear()
    _fake_redis_publish_log.clear()
    yield


@pytest.fixture()
def client():
    alert_app.app.config["TESTING"] = True
    with alert_app.app.test_client() as c:
        yield c


def _post_alert(client, data=None, **kwargs):
    """Helper: POST a valid alert."""
    payload = data or {
        "type": "brute_force",
        "description": "SSH brute-force detected from 10.0.0.5",
        "severity": "high",
        "source": "hids-agent",
        "details": {"ip": "10.0.0.5", "attempts": 42},
    }
    return client.post(
        "/api/v1/alerts",
        data=json.dumps(payload),
        content_type="application/json",
        **kwargs,
    )


# ===================================================================
# Health check
# ===================================================================

class TestHealthCheck:
    def test_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "healthy"
        assert "timestamp" in body


# ===================================================================
# Create alert
# ===================================================================

class TestCreateAlert:
    def test_success(self, client):
        resp = _post_alert(client)
        assert resp.status_code == 201
        body = resp.get_json()
        assert "alert_id" in body
        assert body["message"] == "Alert created successfully"

    def test_stores_in_redis(self, client):
        resp = _post_alert(client)
        alert_id = resp.get_json()["alert_id"]
        stored = _fake_redis_store.get(f"alert:{alert_id}")
        assert stored is not None
        assert stored["type"] == "brute_force"
        assert stored["severity"] == "high"
        assert stored["status"] == "new"

    def test_missing_type_returns_400(self, client):
        resp = client.post(
            "/api/v1/alerts",
            data=json.dumps({"description": "no type"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "Missing required fields" in resp.get_json()["error"]

    def test_missing_description_returns_400(self, client):
        resp = client.post(
            "/api/v1/alerts",
            data=json.dumps({"type": "brute_force"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_empty_body_returns_400(self, client):
        resp = client.post(
            "/api/v1/alerts",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_default_severity_is_medium(self, client):
        resp = _post_alert(client, data={
            "type": "network_anomaly",
            "description": "No severity specified",
        })
        alert_id = resp.get_json()["alert_id"]
        stored = _fake_redis_store[f"alert:{alert_id}"]
        assert stored["severity"] == "medium"

    def test_adds_to_all_and_severity_sets(self, client):
        resp = _post_alert(client)
        alert_id = resp.get_json()["alert_id"]
        assert alert_id in _fake_redis_sets.get("alerts:all", set())
        assert alert_id in _fake_redis_sets.get("alerts:severity:high", set())
        assert alert_id in _fake_redis_sets.get("alerts:status:new", set())

    def test_sets_ttl_on_alert_key(self, client):
        resp = _post_alert(client)
        alert_id = resp.get_json()["alert_id"]
        assert _fake_redis_expiry.get(f"alert:{alert_id}") == 2592000


# ===================================================================
# Get alerts (with filters and pagination)
# ===================================================================

class TestGetAlerts:
    def _seed_alerts(self, client, n=5):
        ids = []
        for i in range(n):
            severity = "critical" if i % 2 == 0 else "low"
            resp = _post_alert(client, data={
                "type": "network_anomaly",
                "description": f"alert {i}",
                "severity": severity,
            })
            ids.append(resp.get_json()["alert_id"])
        return ids

    def test_get_all(self, client):
        self._seed_alerts(client, 3)
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["total"] == 3

    def test_filter_by_severity(self, client):
        self._seed_alerts(client, 4)
        resp = client.get("/api/v1/alerts?severity=critical")
        assert resp.status_code == 200
        body = resp.get_json()
        for a in body["alerts"]:
            assert a["severity"] == "critical"

    def test_filter_by_status(self, client):
        self._seed_alerts(client, 2)
        resp = client.get("/api/v1/alerts?status=new")
        assert resp.status_code == 200
        assert resp.get_json()["total"] == 2

    def test_pagination_limit(self, client):
        self._seed_alerts(client, 5)
        resp = client.get("/api/v1/alerts?limit=2&offset=0")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["total"] <= 2
        assert body["limit"] == 2
        assert body["offset"] == 0

    def test_pagination_offset(self, client):
        ids = self._seed_alerts(client, 5)
        all_resp = client.get("/api/v1/alerts?limit=100")
        full_count = all_resp.get_json()["total"]

        offset_resp = client.get(f"/api/v1/alerts?limit=100&offset={full_count}")
        assert offset_resp.get_json()["total"] == 0

    def test_combined_severity_and_status_filter(self, client):
        self._seed_alerts(client, 4)
        resp = client.get("/api/v1/alerts?severity=critical&status=new")
        assert resp.status_code == 200
        for a in resp.get_json()["alerts"]:
            assert a["severity"] == "critical"
            assert a["status"] == "new"


# ===================================================================
# Get single alert
# ===================================================================

class TestGetSingleAlert:
    def test_found(self, client):
        create_resp = _post_alert(client)
        alert_id = create_resp.get_json()["alert_id"]
        resp = client.get(f"/api/v1/alerts/{alert_id}")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["id"] == alert_id
        assert body["type"] == "brute_force"

    def test_not_found(self, client):
        resp = client.get("/api/v1/alerts/nonexistent_id")
        assert resp.status_code == 404
        assert "not found" in resp.get_json()["error"].lower()

    def test_details_deserialized(self, client):
        create_resp = _post_alert(client, data={
            "type": "malware_detected",
            "description": "test",
            "details": {"file": "/tmp/bad.exe"},
        })
        alert_id = create_resp.get_json()["alert_id"]
        resp = client.get(f"/api/v1/alerts/{alert_id}")
        assert resp.get_json()["details"] == {"file": "/tmp/bad.exe"}


# ===================================================================
# Update alert status
# ===================================================================

class TestUpdateAlertStatus:
    def test_update_success(self, client):
        aid = _post_alert(client).get_json()["alert_id"]
        resp = client.put(
            f"/api/v1/alerts/{aid}",
            data=json.dumps({"status": "acknowledged"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.get_json()["message"] == "Alert updated successfully"

    def test_status_persists(self, client):
        aid = _post_alert(client).get_json()["alert_id"]
        client.put(
            f"/api/v1/alerts/{aid}",
            data=json.dumps({"status": "resolved"}),
            content_type="application/json",
        )
        get_resp = client.get(f"/api/v1/alerts/{aid}")
        assert get_resp.get_json()["status"] == "resolved"

    def test_missing_status_returns_400(self, client):
        aid = _post_alert(client).get_json()["alert_id"]
        resp = client.put(
            f"/api/v1/alerts/{aid}",
            data=json.dumps({"assigned_to": "alice"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_invalid_status_returns_400(self, client):
        aid = _post_alert(client).get_json()["alert_id"]
        resp = client.put(
            f"/api/v1/alerts/{aid}",
            data=json.dumps({"status": "banana"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "Invalid status" in resp.get_json()["error"]

    def test_nonexistent_alert_returns_404(self, client):
        resp = client.put(
            "/api/v1/alerts/fake_id",
            data=json.dumps({"status": "resolved"}),
            content_type="application/json",
        )
        assert resp.status_code == 404

    def test_assigned_to_stored(self, client):
        aid = _post_alert(client).get_json()["alert_id"]
        client.put(
            f"/api/v1/alerts/{aid}",
            data=json.dumps({"status": "acknowledged", "assigned_to": "bob"}),
            content_type="application/json",
        )
        stored = _fake_redis_store[f"alert:{aid}"]
        assert stored["assigned_to"] == "bob"

    def test_status_set_migration(self, client):
        """Old status set loses the id, new status set gains it."""
        aid = _post_alert(client).get_json()["alert_id"]
        assert aid in _fake_redis_sets.get("alerts:status:new", set())

        client.put(
            f"/api/v1/alerts/{aid}",
            data=json.dumps({"status": "acknowledged"}),
            content_type="application/json",
        )
        assert aid not in _fake_redis_sets.get("alerts:status:new", set())
        assert aid in _fake_redis_sets.get("alerts:status:acknowledged", set())


# ===================================================================
# Acknowledge / Resolve shortcuts
# ===================================================================

class TestAcknowledgeResolve:
    def test_acknowledge_success(self, client):
        aid = _post_alert(client).get_json()["alert_id"]
        resp = client.post(f"/api/v1/alerts/{aid}/acknowledge")
        assert resp.status_code == 200
        assert "acknowledged" in resp.get_json()["message"].lower()

    def test_acknowledge_not_found(self, client):
        resp = client.post("/api/v1/alerts/fake/acknowledge")
        assert resp.status_code == 404

    def test_resolve_success(self, client):
        aid = _post_alert(client).get_json()["alert_id"]
        resp = client.post(f"/api/v1/alerts/{aid}/resolve")
        assert resp.status_code == 200
        assert "resolved" in resp.get_json()["message"].lower()

    def test_resolve_not_found(self, client):
        resp = client.post("/api/v1/alerts/fake/resolve")
        assert resp.status_code == 404

    def test_acknowledge_then_resolve_lifecycle(self, client):
        aid = _post_alert(client).get_json()["alert_id"]
        client.post(f"/api/v1/alerts/{aid}/acknowledge")
        client.post(f"/api/v1/alerts/{aid}/resolve")
        get_resp = client.get(f"/api/v1/alerts/{aid}")
        assert get_resp.get_json()["status"] == "resolved"


# ===================================================================
# Alert statistics
# ===================================================================

class TestAlertStatistics:
    def test_empty_stats(self, client):
        resp = client.get("/api/v1/alerts/statistics")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["total_alerts"] == 0
        assert "by_severity" in body
        assert "by_status" in body

    def test_stats_reflect_created_alerts(self, client):
        _post_alert(client, data={
            "type": "brute_force", "description": "a", "severity": "high",
        })
        _post_alert(client, data={
            "type": "brute_force", "description": "b", "severity": "critical",
        })
        resp = client.get("/api/v1/alerts/statistics")
        body = resp.get_json()
        assert body["total_alerts"] == 2
        assert body["by_severity"]["high"] == 1
        assert body["by_severity"]["critical"] == 1
        assert body["by_status"]["new"] == 2


# ===================================================================
# Alert types endpoint
# ===================================================================

class TestAlertTypes:
    def test_returns_enums(self, client):
        resp = client.get("/api/v1/alerts/types")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "brute_force" in body["types"]
        assert "critical" in body["severities"]
        assert "new" in body["statuses"]

    def test_all_enum_values_present(self, client):
        resp = client.get("/api/v1/alerts/types")
        body = resp.get_json()
        assert len(body["types"]) == len(alert_app.AlertType)
        assert len(body["severities"]) == len(alert_app.AlertSeverity)
        assert len(body["statuses"]) == len(alert_app.AlertStatus)


# ===================================================================
# SSE publish on alert creation (Redis pub/sub)
# ===================================================================

class TestSSEPublish:
    def test_publish_called_on_create(self, client):
        _post_alert(client)
        assert len(_fake_redis_publish_log) == 1
        channel, raw = _fake_redis_publish_log[0]
        assert channel == "sentinel:sse:alerts"
        payload = json.loads(raw)
        assert payload["type"] == "new_alert"
        assert "alert" in payload
        assert payload["alert"]["severity"] == "high"

    def test_publish_contains_alert_fields(self, client):
        _post_alert(client, data={
            "type": "malware_detected",
            "description": "trojan found",
            "severity": "critical",
            "source": "hids-agent",
        })
        _, raw = _fake_redis_publish_log[0]
        alert_payload = json.loads(raw)["alert"]
        assert alert_payload["type"] == "malware_detected"
        assert alert_payload["source"] == "hids-agent"
        assert "id" in alert_payload
        assert "timestamp" in alert_payload

    def test_publish_failure_does_not_break_create(self, client):
        """If publish raises, the alert is still created successfully."""
        original_publish = _fake_redis_instance.publish

        def _exploding_publish(*a, **kw):
            raise ConnectionError("Redis down")

        _fake_redis_instance.publish = _exploding_publish
        try:
            resp = _post_alert(client)
            assert resp.status_code == 201
        finally:
            _fake_redis_instance.publish = original_publish


# ===================================================================
# Email and Slack notification triggering
# ===================================================================

class TestNotificationTriggering:
    def test_email_triggered_for_high_severity(self):
        engine = alert_app.alert_engine
        with patch.object(alert_app.notification_executor, "submit") as mock_submit:
            engine.create_alert({
                "type": "brute_force",
                "description": "test",
                "severity": "high",
            })
            submitted_fns = [c.args[0].__name__ for c in mock_submit.call_args_list]
            assert "_send_email_async" in submitted_fns

    def test_email_triggered_for_critical_severity(self):
        engine = alert_app.alert_engine
        with patch.object(alert_app.notification_executor, "submit") as mock_submit:
            engine.create_alert({
                "type": "malware_detected",
                "description": "test",
                "severity": "critical",
            })
            submitted_fns = [c.args[0].__name__ for c in mock_submit.call_args_list]
            assert "_send_email_async" in submitted_fns

    def test_email_not_triggered_for_low_severity(self):
        engine = alert_app.alert_engine
        with patch.object(alert_app.notification_executor, "submit") as mock_submit:
            engine.create_alert({
                "type": "configuration_change",
                "description": "test",
                "severity": "low",
            })
            submitted_fns = [c.args[0].__name__ for c in mock_submit.call_args_list]
            assert "_send_email_async" not in submitted_fns

    def test_slack_triggered_for_critical_with_webhook(self):
        engine = alert_app.alert_engine
        alert_app.app.config["SLACK_WEBHOOK_URL"] = "https://hooks.slack.com/test"
        try:
            with patch.object(alert_app.notification_executor, "submit") as mock_submit:
                engine.create_alert({
                    "type": "malware_detected",
                    "description": "test",
                    "severity": "critical",
                })
                submitted_fns = [c.args[0].__name__ for c in mock_submit.call_args_list]
                assert "_send_slack_async" in submitted_fns
        finally:
            alert_app.app.config["SLACK_WEBHOOK_URL"] = ""

    def test_slack_not_triggered_without_webhook(self):
        engine = alert_app.alert_engine
        alert_app.app.config["SLACK_WEBHOOK_URL"] = ""
        with patch.object(alert_app.notification_executor, "submit") as mock_submit:
            engine.create_alert({
                "type": "malware_detected",
                "description": "test",
                "severity": "critical",
            })
            submitted_fns = [c.args[0].__name__ for c in mock_submit.call_args_list]
            assert "_send_slack_async" not in submitted_fns

    def test_slack_not_triggered_for_non_critical(self):
        engine = alert_app.alert_engine
        alert_app.app.config["SLACK_WEBHOOK_URL"] = "https://hooks.slack.com/test"
        try:
            with patch.object(alert_app.notification_executor, "submit") as mock_submit:
                engine.create_alert({
                    "type": "brute_force",
                    "description": "test",
                    "severity": "high",
                })
                submitted_fns = [c.args[0].__name__ for c in mock_submit.call_args_list]
                assert "_send_slack_async" not in submitted_fns
        finally:
            alert_app.app.config["SLACK_WEBHOOK_URL"] = ""


# ===================================================================
# AlertEngine unit tests (direct, not through Flask)
# ===================================================================

class TestAlertEngineUnit:
    def test_create_returns_id_string(self):
        engine = alert_app.AlertEngine()
        aid = engine.create_alert({
            "type": "test", "description": "unit", "severity": "low",
        })
        assert isinstance(aid, str)
        assert aid.startswith("alert_")

    def test_get_alert_returns_none_for_missing(self):
        engine = alert_app.AlertEngine()
        assert engine.get_alert("nonexistent") is None

    def test_get_alerts_empty(self):
        engine = alert_app.AlertEngine()
        assert engine.get_alerts() == []

    def test_update_status_returns_false_for_missing(self):
        engine = alert_app.AlertEngine()
        result = engine.update_alert_status("fake", alert_app.AlertStatus.RESOLVED)
        assert result is False

    def test_correlation_id_stored(self):
        engine = alert_app.AlertEngine()
        aid = engine.create_alert({
            "type": "test",
            "description": "corr",
            "correlation_id": "corr-999",
        })
        alert = engine.get_alert(aid)
        assert alert["correlation_id"] == "corr-999"

    def test_tags_round_trip(self):
        engine = alert_app.AlertEngine()
        aid = engine.create_alert({
            "type": "test",
            "description": "tags",
            "tags": ["ssh", "external"],
        })
        alert = engine.get_alert(aid)
        assert alert["tags"] == ["ssh", "external"]
