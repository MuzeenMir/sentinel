"""
Comprehensive pytest tests for the SENTINEL XDP Collector service.

Covers all Flask endpoints, the CollectorStats dataclass, KafkaPublisher,
BlocklistManager, and XDPCollectorService with all system-level dependencies
(eBPF, Kafka, Redis) mocked out.
"""

import importlib.util
import json
import os
import sys
import time
import types
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_tests_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.join(_tests_dir, "..")
_xdp_dir = os.path.join(_backend_dir, "xdp-collector")
sys.path.insert(0, _xdp_dir)
sys.path.insert(0, _backend_dir)

# ---------------------------------------------------------------------------
# Pre-import mocks — ebpf_lib, confluent_kafka, and Redis are stubbed before
# the module-level code in app.py runs (including background thread start).
# ---------------------------------------------------------------------------

# Stub ebpf_lib.schemas.events
_events_mod = types.ModuleType("ebpf_lib.schemas.events")
_events_mod.EventType = MagicMock()
_events_mod.NetworkFlowEvent = type("NetworkFlowEvent", (), {
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 12345,
    "dst_port": 80,
    "protocol": 6,
    "bytes_sent": 1024,
    "bytes_recv": 2048,
})
_events_mod.decode_event = MagicMock(return_value=None)
_events_mod.event_to_json = MagicMock(return_value='{"src_ip":"10.0.0.1"}')

# Stub ebpf_lib.loader
_mock_program_info = MagicMock()
_mock_program_info.name = "xdp/xdp_flow"
_mock_program_info.sha256 = "abc123"
_mock_program_info.fd = -1
_mock_program_info.map_fds = {}

_mock_loader_instance = MagicMock()
_mock_loader_instance.load.return_value = _mock_program_info
_mock_loader_instance.is_loaded.return_value = False

_mock_ring_reader = MagicMock()

_loader_mod = types.ModuleType("ebpf_lib.loader")
_loader_mod.ProgramLoader = MagicMock(return_value=_mock_loader_instance)
_loader_mod.RingBufferReader = MagicMock(return_value=_mock_ring_reader)

# Register ebpf_lib stub hierarchy
if "ebpf_lib" not in sys.modules:
    _ebpf_lib = types.ModuleType("ebpf_lib")
    sys.modules["ebpf_lib"] = _ebpf_lib
if "ebpf_lib.schemas" not in sys.modules:
    _schemas = types.ModuleType("ebpf_lib.schemas")
    sys.modules["ebpf_lib.schemas"] = _schemas
sys.modules["ebpf_lib.schemas.events"] = _events_mod
sys.modules["ebpf_lib.loader"] = _loader_mod

# Stub confluent_kafka
_mock_kafka_producer = MagicMock()
_kafka_mod = types.ModuleType("confluent_kafka")
_kafka_mod.Producer = MagicMock(return_value=_mock_kafka_producer)
sys.modules.setdefault("confluent_kafka", _kafka_mod)

# Stub Redis
import types as _types
from functools import wraps as _wraps


def _make_enforcing_auth_mod():
    """Return a proper auth_middleware module that enforces JWT auth via _verify_token."""
    _mod = _types.ModuleType("auth_middleware")

    def _verify_token(token):  # default: reject
        return None

    _mod._verify_token = _verify_token

    def require_auth(fn):
        @_wraps(fn)
        def decorated(*args, **kwargs):
            from flask import g, jsonify, request
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Unauthorized"}), 401
            tok = auth[7:]
            _m = sys.modules.get("auth_middleware")
            user = _m._verify_token(tok)
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
            g.current_user = user
            return fn(*args, **kwargs)
        return decorated

    def require_role(*roles):
        def decorator(fn):
            @_wraps(fn)
            def inner(*args, **kwargs):
                from flask import g, jsonify
                user = getattr(g, "current_user", None)
                if not user:
                    return jsonify({"error": "Unauthorized"}), 401
                if roles and user.get("role") not in roles:
                    return jsonify({"error": "Forbidden"}), 403
                return fn(*args, **kwargs)
            return inner
        return decorator

    _mod.require_auth = require_auth
    _mod.require_role = require_role
    return _mod


sys.modules["auth_middleware"] = _make_enforcing_auth_mod()

_mock_redis_client = MagicMock()
_mock_redis_client.ping.return_value = True
_redis_patcher = patch("redis.from_url", return_value=_mock_redis_client)
_redis_patcher.start()

# Prevent the background collector thread from actually starting
_bg_patcher = patch.dict(os.environ, {"XDP_ENABLED": "false"})
_bg_patcher.start()

_spec = importlib.util.spec_from_file_location(
    "sentinel_xdp_app",
    os.path.join(_xdp_dir, "app.py"),
    submodule_search_locations=[],
)
xdp_app = importlib.util.module_from_spec(_spec)
sys.modules["sentinel_xdp_app"] = xdp_app

_spec.loader.exec_module(xdp_app)


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture(autouse=True)
def _bypass_auth():
    with patch("auth_middleware._verify_token") as mock_verify:
        mock_verify.return_value = {
            "user_id": "test-user-1",
            "username": "test_admin",
            "role": "admin",
            "email": "admin@sentinel.test",
        }
        yield mock_verify


@pytest.fixture()
def auth_headers():
    return {"Authorization": "Bearer test-valid-token", "Content-Type": "application/json"}


@pytest.fixture()
def collector():
    """Return the module-level collector and reset its stats between tests."""
    c = xdp_app.collector
    c.stats = xdp_app.CollectorStats()
    c.blocklist._blocklist.clear()
    c._running = False
    c._loader = None
    c._reader = None
    yield c


@pytest.fixture()
def client(collector):
    xdp_app.app.config["TESTING"] = True
    with xdp_app.app.test_client() as c:
        yield c


@pytest.fixture()
def bare_client():
    xdp_app.app.config["TESTING"] = True
    with xdp_app.app.test_client() as c:
        yield c


# ===================================================================
# Health — GET /health
# ===================================================================


class TestHealth:
    def test_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_healthy_status(self, client):
        data = client.get("/health").get_json()
        assert data["status"] == "healthy"
        assert data["service"] == "xdp-collector"

    def test_reports_xdp_enabled_flag(self, client, collector):
        data = client.get("/health").get_json()
        assert data["xdp_enabled"] == collector.enabled

    def test_xdp_loaded_false_when_no_loader(self, client, collector):
        collector._loader = None
        data = client.get("/health").get_json()
        assert data["xdp_loaded"] is False

    def test_xdp_loaded_true_when_program_loaded(self, client, collector):
        mock_loader = MagicMock()
        mock_loader.is_loaded.return_value = True
        collector._loader = mock_loader
        data = client.get("/health").get_json()
        assert data["xdp_loaded"] is True

    def test_reports_interface(self, client, collector):
        data = client.get("/health").get_json()
        assert data["interface"] == collector.interface

    def test_does_not_require_auth(self, bare_client):
        with patch("auth_middleware._verify_token", return_value=None):
            resp = bare_client.get("/health")
            assert resp.status_code == 200


# ===================================================================
# Metrics — GET /metrics
# ===================================================================


class TestMetrics:
    def test_returns_stats_dict(self, client, auth_headers, collector):
        collector.stats.flows_exported = 42
        collector.stats.events_published = 40
        collector.stats.events_dropped = 2
        resp = client.get("/metrics", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["flows_exported"] == 42
        assert data["events_published"] == 40
        assert data["events_dropped"] == 2

    def test_includes_uptime(self, client, auth_headers, collector):
        data = client.get("/metrics", headers=auth_headers).get_json()
        assert "uptime_seconds" in data
        assert data["uptime_seconds"] >= 0

    def test_events_per_second_calculated(self, client, auth_headers, collector):
        collector.stats.events_published = 100
        data = client.get("/metrics", headers=auth_headers).get_json()
        assert data["events_per_second"] >= 0

    def test_last_error_reported(self, client, auth_headers, collector):
        collector.stats.last_error = "test error"
        data = client.get("/metrics", headers=auth_headers).get_json()
        assert data["last_error"] == "test error"

    def test_last_error_null_when_clean(self, client, auth_headers, collector):
        data = client.get("/metrics", headers=auth_headers).get_json()
        assert data["last_error"] is None

    def test_requires_auth(self, bare_client):
        resp = bare_client.get("/metrics")
        assert resp.status_code == 401


# ===================================================================
# Config — GET /config
# ===================================================================


class TestConfig:
    def test_returns_config(self, client, auth_headers, collector):
        resp = client.get("/config", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "interface" in data
        assert "enabled" in data
        assert "kafka_topic" in data
        assert "blocklist_size" in data

    def test_blocklist_size_reflects_actual(self, client, auth_headers, collector):
        collector.blocklist.add_ip("1.2.3.4", "test")
        collector.blocklist.add_ip("5.6.7.8", "test")
        data = client.get("/config", headers=auth_headers).get_json()
        assert data["blocklist_size"] == 2

    def test_empty_blocklist_size(self, client, auth_headers, collector):
        data = client.get("/config", headers=auth_headers).get_json()
        assert data["blocklist_size"] == 0

    def test_requires_auth(self, bare_client):
        resp = bare_client.get("/config")
        assert resp.status_code == 401


# ===================================================================
# Blocklist — GET/POST /blocklist
# ===================================================================


class TestGetBlocklist:
    def test_returns_blocklist(self, client, auth_headers, collector):
        collector.blocklist.add_ip("10.0.0.1", "malicious")
        resp = client.get("/blocklist", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "10.0.0.1" in data
        assert data["10.0.0.1"]["reason"] == "malicious"

    def test_empty_blocklist(self, client, auth_headers, collector):
        resp = client.get("/blocklist", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json() == {}

    def test_requires_auth(self, bare_client):
        resp = bare_client.get("/blocklist")
        assert resp.status_code == 401

    def test_forbidden_for_viewer_role(self, client, auth_headers):
        with patch("auth_middleware._verify_token") as mock_verify:
            mock_verify.return_value = {
                "user_id": "u2",
                "username": "viewer_user",
                "role": "viewer",
            }
            resp = client.get("/blocklist", headers=auth_headers)
            assert resp.status_code == 403

    def test_allowed_for_security_analyst(self, client, auth_headers):
        with patch("auth_middleware._verify_token") as mock_verify:
            mock_verify.return_value = {
                "user_id": "u3",
                "username": "analyst",
                "role": "security_analyst",
            }
            resp = client.get("/blocklist", headers=auth_headers)
            assert resp.status_code == 200


class TestUpdateBlocklist:
    def test_add_ip(self, client, auth_headers, collector):
        resp = client.post(
            "/blocklist",
            headers=auth_headers,
            json={"ip": "192.168.1.100", "action": "add", "reason": "brute_force"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["ip"] == "192.168.1.100"
        assert data["action"] == "add"
        assert "192.168.1.100" in collector.blocklist.get_all()

    def test_remove_ip(self, client, auth_headers, collector):
        collector.blocklist.add_ip("192.168.1.100", "test")
        resp = client.post(
            "/blocklist",
            headers=auth_headers,
            json={"ip": "192.168.1.100", "action": "remove"},
        )
        assert resp.status_code == 200
        assert "192.168.1.100" not in collector.blocklist.get_all()

    def test_default_action_is_add(self, client, auth_headers, collector):
        resp = client.post(
            "/blocklist",
            headers=auth_headers,
            json={"ip": "10.0.0.50"},
        )
        assert resp.status_code == 200
        assert "10.0.0.50" in collector.blocklist.get_all()

    def test_missing_ip_returns_400(self, client, auth_headers):
        resp = client.post(
            "/blocklist",
            headers=auth_headers,
            json={"action": "add"},
        )
        assert resp.status_code == 400
        assert "ip" in resp.get_json()["error"]

    def test_empty_body_returns_400(self, client, auth_headers):
        resp = client.post(
            "/blocklist",
            headers=auth_headers,
            data="",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_invalid_action_returns_400(self, client, auth_headers):
        resp = client.post(
            "/blocklist",
            headers=auth_headers,
            json={"ip": "1.2.3.4", "action": "destroy"},
        )
        assert resp.status_code == 400
        assert "action" in resp.get_json()["error"]

    def test_remove_nonexistent_ip_succeeds(self, client, auth_headers, collector):
        resp = client.post(
            "/blocklist",
            headers=auth_headers,
            json={"ip": "99.99.99.99", "action": "remove"},
        )
        assert resp.status_code == 200

    def test_requires_auth(self, bare_client):
        resp = bare_client.post("/blocklist", json={"ip": "1.2.3.4"})
        assert resp.status_code == 401

    def test_forbidden_for_analyst_role(self, client, auth_headers):
        with patch("auth_middleware._verify_token") as mock_verify:
            mock_verify.return_value = {
                "user_id": "u4",
                "username": "analyst",
                "role": "security_analyst",
            }
            resp = client.post(
                "/blocklist",
                headers=auth_headers,
                json={"ip": "1.2.3.4"},
            )
            assert resp.status_code == 403

    def test_allowed_for_operator_role(self, client, auth_headers, collector):
        with patch("auth_middleware._verify_token") as mock_verify:
            mock_verify.return_value = {
                "user_id": "u5",
                "username": "operator",
                "role": "operator",
            }
            resp = client.post(
                "/blocklist",
                headers=auth_headers,
                json={"ip": "1.2.3.4"},
            )
            assert resp.status_code == 200


# ===================================================================
# CollectorStats dataclass
# ===================================================================


class TestCollectorStats:
    def test_defaults(self):
        stats = xdp_app.CollectorStats()
        assert stats.flows_exported == 0
        assert stats.events_published == 0
        assert stats.events_dropped == 0
        assert stats.packets_blocked == 0
        assert stats.bytes_blocked == 0
        assert stats.last_error is None

    def test_to_dict_keys(self):
        stats = xdp_app.CollectorStats()
        d = stats.to_dict()
        expected_keys = {
            "flows_exported", "events_published", "events_dropped",
            "packets_blocked", "bytes_blocked", "uptime_seconds",
            "events_per_second", "last_event_time", "last_error",
        }
        assert set(d.keys()) == expected_keys

    def test_uptime_increases(self):
        stats = xdp_app.CollectorStats()
        stats.start_time = time.time() - 60
        d = stats.to_dict()
        assert d["uptime_seconds"] >= 59

    def test_events_per_second_calculation(self):
        stats = xdp_app.CollectorStats()
        stats.start_time = time.time() - 10
        stats.events_published = 50
        d = stats.to_dict()
        assert d["events_per_second"] == pytest.approx(5.0, abs=1.0)

    def test_events_per_second_zero_uptime(self):
        stats = xdp_app.CollectorStats()
        stats.start_time = time.time()
        stats.events_published = 0
        d = stats.to_dict()
        assert d["events_per_second"] >= 0

    def test_last_error_serialised(self):
        stats = xdp_app.CollectorStats()
        stats.last_error = "eBPF load failed: permission denied"
        d = stats.to_dict()
        assert d["last_error"] == "eBPF load failed: permission denied"


# ===================================================================
# KafkaPublisher
# ===================================================================


class TestKafkaPublisher:
    def test_publish_returns_true_with_producer(self):
        publisher = xdp_app.KafkaPublisher("test-topic")
        event = MagicMock()
        event.src_ip = "10.0.0.1"
        _events_mod.event_to_json.return_value = '{"src_ip":"10.0.0.1"}'
        result = publisher.publish(event)
        assert result is True

    def test_publish_returns_false_without_producer(self):
        publisher = xdp_app.KafkaPublisher("test-topic")
        publisher._producer = None
        event = MagicMock()
        assert publisher.publish(event) is False

    def test_publish_handles_exception(self):
        publisher = xdp_app.KafkaPublisher("test-topic")
        publisher._producer = MagicMock()
        publisher._producer.produce.side_effect = RuntimeError("Kafka down")
        event = MagicMock()
        event.src_ip = "10.0.0.1"
        _events_mod.event_to_json.return_value = '{"src_ip":"10.0.0.1"}'
        assert publisher.publish(event) is False

    def test_flush_calls_producer(self):
        publisher = xdp_app.KafkaPublisher("test-topic")
        publisher._producer = MagicMock()
        publisher.flush(timeout=2.0)
        publisher._producer.flush.assert_called_once_with(2.0)

    def test_flush_noop_without_producer(self):
        publisher = xdp_app.KafkaPublisher("test-topic")
        publisher._producer = None
        publisher.flush()


# ===================================================================
# BlocklistManager
# ===================================================================


class TestBlocklistManager:
    def test_add_and_retrieve(self):
        mgr = xdp_app.BlocklistManager()
        mgr.add_ip("192.168.1.1", "test_reason")
        entries = mgr.get_all()
        assert "192.168.1.1" in entries
        assert entries["192.168.1.1"]["reason"] == "test_reason"
        assert "added_at" in entries["192.168.1.1"]

    def test_remove_ip(self):
        mgr = xdp_app.BlocklistManager()
        mgr.add_ip("192.168.1.1", "test")
        mgr.remove_ip("192.168.1.1")
        assert "192.168.1.1" not in mgr.get_all()

    def test_remove_nonexistent_ip_no_error(self):
        mgr = xdp_app.BlocklistManager()
        mgr.remove_ip("99.99.99.99")

    def test_get_all_returns_copy(self):
        mgr = xdp_app.BlocklistManager()
        mgr.add_ip("1.1.1.1", "test")
        copy = mgr.get_all()
        copy.pop("1.1.1.1")
        assert "1.1.1.1" in mgr.get_all()

    def test_multiple_ips(self):
        mgr = xdp_app.BlocklistManager()
        for i in range(5):
            mgr.add_ip(f"10.0.0.{i}", f"reason_{i}")
        assert len(mgr.get_all()) == 5

    def test_overwrite_existing_ip(self):
        mgr = xdp_app.BlocklistManager()
        mgr.add_ip("10.0.0.1", "reason_a")
        mgr.add_ip("10.0.0.1", "reason_b")
        assert mgr.get_all()["10.0.0.1"]["reason"] == "reason_b"


# ===================================================================
# XDPCollectorService — start / stop / event handling
# ===================================================================


class TestXDPCollectorService:
    def test_start_disabled_does_nothing(self, collector):
        collector.enabled = False
        collector.start()
        assert collector._running is False

    def test_start_enabled_sets_running(self, collector):
        collector.enabled = True
        _loader_mod.ProgramLoader.return_value = _mock_loader_instance
        _mock_program_info.fd = -1
        collector.start()
        assert collector._running is True

    def test_stop_flushes_kafka(self, collector):
        collector._running = True
        collector.publisher = MagicMock()
        collector._reader = None
        collector._loader = None
        collector.stop()
        collector.publisher.flush.assert_called_once()
        assert collector._running is False

    def test_stop_unloads_ebpf_program(self, collector):
        collector._running = True
        mock_loader = MagicMock()
        mock_loader.is_loaded.return_value = True
        collector._loader = mock_loader
        collector._reader = MagicMock()
        collector.publisher = MagicMock()
        collector.stop()
        mock_loader.unload.assert_called_once_with("xdp/xdp_flow")
        collector._reader.stop.assert_called_once()

    def test_stop_without_loader_no_error(self, collector):
        collector._running = True
        collector._loader = None
        collector._reader = None
        collector.publisher = MagicMock()
        collector.stop()

    def test_on_flow_event_publishes_and_counts(self, collector):
        collector.publisher = MagicMock()
        collector.publisher.publish.return_value = True
        event = _events_mod.NetworkFlowEvent()
        collector._on_flow_event(event)
        assert collector.stats.flows_exported == 1
        assert collector.stats.events_published == 1
        assert collector.stats.events_dropped == 0

    def test_on_flow_event_counts_drop_on_publish_failure(self, collector):
        collector.publisher = MagicMock()
        collector.publisher.publish.return_value = False
        event = _events_mod.NetworkFlowEvent()
        collector._on_flow_event(event)
        assert collector.stats.flows_exported == 1
        assert collector.stats.events_published == 0
        assert collector.stats.events_dropped == 1

    def test_on_flow_event_ignores_non_flow_events(self, collector):
        collector.publisher = MagicMock()
        collector._on_flow_event("not_a_flow_event")
        collector.publisher.publish.assert_not_called()
        assert collector.stats.flows_exported == 0

    def test_on_flow_event_updates_last_event_time(self, collector):
        collector.publisher = MagicMock()
        collector.publisher.publish.return_value = True
        before = time.time()
        event = _events_mod.NetworkFlowEvent()
        collector._on_flow_event(event)
        assert collector.stats.last_event_time >= before

    def test_start_records_error_on_permission_error(self, collector):
        collector.enabled = True
        mock_ldr = MagicMock()
        mock_ldr.load.side_effect = PermissionError("signature check failed")
        _loader_mod.ProgramLoader.return_value = mock_ldr
        collector.start()
        assert collector.stats.last_error == "signature check failed"

    def test_start_handles_file_not_found(self, collector):
        collector.enabled = True
        mock_ldr = MagicMock()
        mock_ldr.load.side_effect = FileNotFoundError("no compiled objects")
        _loader_mod.ProgramLoader.return_value = mock_ldr
        collector.start()
        assert collector.stats.last_error is None

    def test_start_handles_generic_exception(self, collector):
        collector.enabled = True
        mock_ldr = MagicMock()
        mock_ldr.load.side_effect = RuntimeError("unexpected")
        _loader_mod.ProgramLoader.return_value = mock_ldr
        collector.start()
        assert collector.stats.last_error == "unexpected"

    def test_start_with_valid_fd_creates_ring_reader(self, collector):
        collector.enabled = True
        info = MagicMock()
        info.name = "xdp/xdp_flow"
        info.sha256 = "abc"
        info.fd = 5
        info.map_fds = {"flow_events": 7}

        mock_ldr = MagicMock()
        mock_ldr.load.return_value = info
        _loader_mod.ProgramLoader.return_value = mock_ldr

        mock_reader = MagicMock()
        _loader_mod.RingBufferReader.return_value = mock_reader

        collector.start()
        mock_reader.register.assert_called_once()
        mock_reader.start.assert_called_once()

    def test_on_audit_event_logs(self, collector):
        collector._on_audit_event({"action": "load", "program": "xdp_flow"})
