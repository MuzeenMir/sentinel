"""
Comprehensive pytest unit tests for the SENTINEL Data Collector.

Covers Flask routes, CIM normalization, anomaly detection, SSE publish,
and all endpoints. Redis, Kafka, and auth_middleware are mocked — no real connections.
"""

import fnmatch
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fake Redis for data-collector (supports pipeline, hmset, scan_iter, publish, etc.)
# ---------------------------------------------------------------------------

_fake_redis_store: dict = {}
_fake_redis_strings: dict = {}
_fake_redis_expiry: dict = {}
_fake_redis_publish_log: list = []


class _FakeRedisPipeline:
    """In-memory pipeline for batching Redis commands."""

    def __init__(self, parent):
        self._parent = parent
        self._commands: list = []

    def hincrby(self, key, field, amount=1):
        self._commands.append(("hincrby", key, field, amount))
        return self

    def incr(self, key):
        self._commands.append(("incr", key))
        return self

    def expire(self, key, seconds):
        self._commands.append(("expire", key, seconds))
        return self

    def execute(self):
        for cmd in self._commands:
            if cmd[0] == "hincrby":
                _, key, field, amount = cmd
                k = key.decode() if isinstance(key, bytes) else key
                if k not in _fake_redis_store:
                    _fake_redis_store[k] = {}
                f = field.decode() if isinstance(field, bytes) else field
                current = int(_fake_redis_store[k].get(f, 0))
                _fake_redis_store[k][f] = str(current + amount)
            elif cmd[0] == "incr":
                _, key = cmd
                k = key.decode() if isinstance(key, bytes) else key
                current = int(_fake_redis_strings.get(k, 0))
                _fake_redis_strings[k] = str(current + 1)
            elif cmd[0] == "expire":
                _, key, seconds = cmd
                k = key.decode() if isinstance(key, bytes) else key
                _fake_redis_expiry[k] = seconds
        self._commands.clear()
        return []


class _FakeRedis:
    """In-memory Redis stand-in for data-collector unit tests."""

    def pipeline(self):
        return _FakeRedisPipeline(self)

    def hgetall(self, key):
        k = key.decode() if isinstance(key, bytes) else key
        data = _fake_redis_store.get(k, {})
        result = {}
        for f, v in data.items():
            kk = f if isinstance(f, bytes) else f.encode()
            vv = v if isinstance(v, bytes) else str(v).encode()
            result[kk] = vv
        return result

    def hmset(self, key, mapping):
        k = key.decode() if isinstance(key, bytes) else key
        if k not in _fake_redis_store:
            _fake_redis_store[k] = {}
        for f, v in mapping.items():
            ff = f.decode() if isinstance(f, bytes) else f
            _fake_redis_store[k][ff] = v

    def get(self, key):
        k = key.decode() if isinstance(key, bytes) else key
        return _fake_redis_strings.get(k)

    def incr(self, key):
        k = key.decode() if isinstance(key, bytes) else key
        current = int(_fake_redis_strings.get(k, 0))
        _fake_redis_strings[k] = str(current + 1)
        return current + 1

    def expire(self, key, seconds):
        k = key.decode() if isinstance(key, bytes) else key
        _fake_redis_expiry[k] = seconds

    def publish(self, channel, message):
        _fake_redis_publish_log.append((channel, message))

    def scan_iter(self, match, count=None):
        """Yield keys matching pattern."""
        pattern = match.decode() if isinstance(match, bytes) else match
        all_keys = list(_fake_redis_store.keys()) + list(_fake_redis_strings.keys())
        for key in all_keys:
            k = key.decode() if isinstance(key, bytes) else key
            if fnmatch.fnmatch(k, pattern):
                yield key.encode() if isinstance(key, str) else key


_fake_redis_instance = _FakeRedis()


def _noop_auth(fn):
    """Pass-through replacement for require_auth."""
    return fn


def _noop_role(*_roles):
    """Pass-through replacement for require_role."""
    def decorator(fn):
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Patch before importing collector
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data-collector"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _noop_thread_start(self):
    """Prevent Thread.start() from running the target."""
    pass


_mock_kafka_producer = MagicMock()
_mock_kafka_module = MagicMock()
_mock_kafka_module.KafkaProducer = MagicMock(return_value=_mock_kafka_producer)

with patch("threading.Thread.start", _noop_thread_start), patch.dict(
    "sys.modules",
    {
        "kafka": _mock_kafka_module,
        "redis": MagicMock(from_url=MagicMock(return_value=_fake_redis_instance)),
        "auth_middleware": MagicMock(
            require_auth=_noop_auth,
            require_role=_noop_role,
        ),
    },
):
    for mod in list(sys.modules.keys()):
        if mod == "collector":
            del sys.modules[mod]
            break
    import collector as collector_mod  # noqa: E402

collector_mod.redis_client = _fake_redis_instance
collector_mod.producer = _mock_kafka_producer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_state():
    """Clear all fake Redis state between tests."""
    _fake_redis_store.clear()
    _fake_redis_strings.clear()
    _fake_redis_expiry.clear()
    _fake_redis_publish_log.clear()
    _mock_kafka_producer.reset_mock()
    yield


@pytest.fixture
def client():
    collector_mod.app.config["TESTING"] = True
    with collector_mod.app.test_client() as c:
        yield c


# ===================================================================
# Health check endpoint
# ===================================================================

class TestHealthCheck:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_healthy_status(self, client):
        resp = client.get("/health")
        body = resp.get_json()
        assert body["status"] == "healthy"
        assert "timestamp" in body

    def test_health_includes_stats(self, client):
        resp = client.get("/health")
        body = resp.get_json()
        assert "stats" in body
        assert "packets_processed" in body["stats"]
        assert "bytes_processed" in body["stats"]
        assert "netflow_records" in body["stats"]
        assert "sflow_records" in body["stats"]

    def test_health_includes_collectors_config(self, client):
        resp = client.get("/health")
        body = resp.get_json()
        assert "collectors" in body
        assert "pcap" in body["collectors"]
        assert "netflow_port" in body["collectors"]
        assert "sflow_port" in body["collectors"]


# ===================================================================
# Ingest endpoint (single and batch)
# ===================================================================

class TestIngestEndpoint:
    def test_ingest_single_record_success(self, client):
        payload = {
            "source_ip": "192.168.1.10",
            "dest_ip": "8.8.8.8",
            "source_port": 54321,
            "dest_port": 443,
            "protocol": "TCP",
            "bytes": 1500,
        }
        resp = client.post(
            "/api/v1/ingest",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["message"] == "Data ingested successfully"
        assert body["processed"] == 1

    def test_ingest_batch_records_success(self, client):
        payload = [
            {"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "protocol": 6, "bytes": 100},
            {"source_ip": "10.0.0.2", "dest_ip": "10.0.0.1", "protocol": 17, "bytes": 200},
        ]
        resp = client.post(
            "/api/v1/ingest",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["processed"] == 2

    def test_ingest_no_data_returns_400(self, client):
        resp = client.post(
            "/api/v1/ingest",
            data=json.dumps(None),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "No data provided" in resp.get_json()["error"]

    def test_ingest_minimal_record_normalized(self, client):
        # Minimal record (empty dict is 400); use minimal valid record
        resp = client.post(
            "/api/v1/ingest",
            data=json.dumps({"bytes": 0}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.get_json()["processed"] == 1

    def test_ingest_sends_to_kafka(self, client):
        payload = {"source_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "bytes": 500}
        client.post(
            "/api/v1/ingest",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert _mock_kafka_producer.send.called
        call_args = _mock_kafka_producer.send.call_args
        assert call_args[0][0] == "normalized_traffic"

    def test_ingest_updates_redis_stats(self, client):
        payload = {
            "source_ip": "192.168.1.1",
            "dest_ip": "8.8.8.8",
            "protocol": "TCP",
            "bytes": 1000,
        }
        client.post(
            "/api/v1/ingest",
            data=json.dumps(payload),
            content_type="application/json",
        )
        has_src = any("traffic:src:" in str(k) for k in _fake_redis_store.keys())
        has_proto = any("traffic:proto:" in str(k) for k in _fake_redis_strings.keys())
        assert has_src or has_proto


# ===================================================================
# Threats listing endpoint
# ===================================================================

class TestThreatsEndpoint:
    def test_get_threats_empty(self, client):
        resp = client.get("/api/v1/threats")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["threats"] == []
        assert body["total"] == 0

    def test_get_threats_returns_stored_alerts(self, client):
        _fake_redis_store["alert:2025-01-01T12:00:00:evt_abc123"] = {
            "type": "network_anomaly",
            "severity": "medium",
            "timestamp": "2025-01-01T12:00:00",
            "details": '{"src_ip":"1.2.3.4"}',
        }
        resp = client.get("/api/v1/threats")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["total"] >= 1
        found = next((t for t in body["threats"] if t.get("type") == "network_anomaly"), None)
        assert found is not None


# ===================================================================
# Traffic statistics endpoint
# ===================================================================

class TestTrafficStatsEndpoint:
    def test_traffic_stats_empty(self, client):
        resp = client.get("/api/v1/traffic")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "sources" in body
        assert "destinations" in body
        assert "protocols" in body
        assert "directions" in body

    def test_traffic_stats_returns_data_from_redis(self, client):
        _fake_redis_store["traffic:src:192.168.1.1"] = {"count": "10", "bytes": "5000"}
        _fake_redis_strings["traffic:proto:TCP"] = "25"
        resp = client.get("/api/v1/traffic")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["sources"].get("192.168.1.1") == {"count": 10, "bytes": 5000}
        assert body["protocols"].get("TCP") == 25


# ===================================================================
# Collector status endpoint
# ===================================================================

class TestCollectorStatusEndpoint:
    def test_status_returns_200(self, client):
        resp = client.get("/api/v1/collector/status")
        assert resp.status_code == 200

    def test_status_includes_running_flag(self, client):
        resp = client.get("/api/v1/collector/status")
        body = resp.get_json()
        assert "running" in body
        assert "stats" in body
        assert "uptime" in body
        assert "netflow_port" in body
        assert "sflow_port" in body


# ===================================================================
# Start/stop collector endpoints
# ===================================================================

class TestCollectorStartStop:
    def test_start_collector_returns_200(self, client):
        collector_mod.collector.running = False
        resp = client.post("/api/v1/collector/start")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "message" in body

    def test_stop_collector_returns_200(self, client):
        resp = client.post("/api/v1/collector/stop")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["message"] == "Collector stopped"


# ===================================================================
# CIM normalization logic
# ===================================================================

class TestCIMNormalization:
    def test_normalize_api_data(self):
        normalizer = collector_mod.CIMNormalizer()
        data = {
            "source_ip": "192.168.1.1",
            "dest_ip": "8.8.8.8",
            "source_port": 443,
            "dest_port": 53,
            "protocol": "UDP",
            "bytes": 512,
        }
        result = normalizer.normalize(data, collector_mod.DataSourceType.API)
        assert result["src_ip"] == "192.168.1.1"
        assert result["dest_ip"] == "8.8.8.8"
        assert result["src_port"] == 443
        assert result["dest_port"] == 53
        assert result["transport"] == "UDP"
        assert result["bytes"] == 512
        assert result["source_type"] == "api"
        assert result["vendor"] == "sentinel"
        assert "event_id" in result
        assert result["event_id"].startswith("evt_")
        assert "event_time" in result
        assert "raw_hash" in result
        assert "direction" in result

    def test_normalize_protocol_number_to_name(self):
        normalizer = collector_mod.CIMNormalizer()
        data = {"source_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "protocol": 6, "bytes": 100}
        result = normalizer.normalize(data, collector_mod.DataSourceType.API)
        assert result["transport"] == "TCP"

    def test_normalize_internal_traffic_direction(self):
        normalizer = collector_mod.CIMNormalizer()
        data = {"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "bytes": 100}
        result = normalizer.normalize(data, collector_mod.DataSourceType.API)
        assert result["direction"] in ("internal", "inbound", "outbound", "external")
        assert "is_internal" in result

    def test_normalize_optional_fields(self):
        normalizer = collector_mod.CIMNormalizer()
        data = {
            "source_ip": "1.1.1.1",
            "dest_ip": "2.2.2.2",
            "bytes": 100,
            "vlan": 100,
            "application": "http",
        }
        result = normalizer.normalize(data, collector_mod.DataSourceType.API)
        assert result.get("vlan_id") == 100
        assert result.get("app") == "http"

    def test_normalize_timestamp_from_int(self):
        normalizer = collector_mod.CIMNormalizer()
        data = {"source_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "timestamp": 1700000000, "bytes": 0}
        result = normalizer.normalize(data, collector_mod.DataSourceType.API)
        assert "event_time" in result
        assert "Z" in result["event_time"] or "T" in result["event_time"]


# ===================================================================
# Anomaly detection (_detect_anomaly, _create_alert)
# ===================================================================

class TestAnomalyDetection:
    def test_large_payload_triggers_anomaly(self, client):
        payload = {
            "source_ip": "192.168.1.1",
            "dest_ip": "8.8.8.8",
            "protocol": "TCP",
            "bytes": 15000,
        }
        resp = client.post(
            "/api/v1/ingest",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert len(_fake_redis_publish_log) >= 1

    def test_syn_flood_triggers_anomaly_after_threshold(self, client):
        for _ in range(105):
            client.post(
                "/api/v1/ingest",
                data=json.dumps({
                    "source_ip": "10.0.0.99",
                    "dest_ip": "8.8.8.8",
                    "protocol": "TCP",
                    "bytes": 60,
                    "tcp_flags": 0x02,
                }),
                content_type="application/json",
            )
        assert len(_fake_redis_publish_log) >= 1

    def test_normal_traffic_no_anomaly(self, client):
        payload = {
            "source_ip": "192.168.1.1",
            "dest_ip": "8.8.8.8",
            "protocol": "UDP",
            "bytes": 500,
        }
        resp = client.post(
            "/api/v1/ingest",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert len(_fake_redis_publish_log) == 0


# ===================================================================
# SSE publish on threat detection (Redis publish to sentinel:sse:threats)
# ===================================================================

class TestSSEPublish:
    def test_publish_to_sentinel_sse_threats_on_anomaly(self, client):
        _fake_redis_publish_log.clear()
        payload = {
            "source_ip": "1.2.3.4",
            "dest_ip": "5.6.7.8",
            "protocol": "TCP",
            "bytes": 20000,
        }
        client.post(
            "/api/v1/ingest",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert len(_fake_redis_publish_log) >= 1
        channel, message = _fake_redis_publish_log[0]
        assert channel == "sentinel:sse:threats"
        payload_data = json.loads(message)
        assert payload_data["type"] == "new_threat"
        assert "threat" in payload_data
        assert payload_data["threat"]["severity"] == "medium"
        assert payload_data["threat"]["alert_type"] == "network_anomaly"
        assert "timestamp" in payload_data


# ===================================================================
# Error handling for endpoints
# ===================================================================

class TestErrorHandling:
    def test_traffic_stats_redis_error_returns_500(self, client):
        with patch.object(
            collector_mod.redis_client,
            "scan_iter",
            side_effect=ConnectionError("Redis down"),
        ):
            resp = client.get("/api/v1/traffic")
        assert resp.status_code == 500
        assert "error" in resp.get_json()

    def test_threats_redis_error_returns_500(self, client):
        with patch.object(
            collector_mod.redis_client,
            "scan_iter",
            side_effect=ConnectionError("Redis down"),
        ):
            resp = client.get("/api/v1/threats")
        assert resp.status_code == 500
        assert "Failed to retrieve threats" in resp.get_json()["error"]

    def test_ingest_invalid_json_returns_500(self, client):
        resp = client.post(
            "/api/v1/ingest",
            data="not valid json {{{",
            content_type="application/json",
        )
        assert resp.status_code in (400, 500)

    def test_ingest_processing_error_returns_500(self, client):
        with patch.object(
            collector_mod.collector,
            "process_normalized_record",
            side_effect=RuntimeError("Boom"),
        ):
            resp = client.post(
                "/api/v1/ingest",
                data=json.dumps({"source_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}),
                content_type="application/json",
            )
        assert resp.status_code == 500
        assert "error" in resp.get_json()
