"""Tests for the HIDS agent service."""

import importlib.util
import os
import sys
import tempfile
import pytest

_backend = os.path.join(os.path.dirname(__file__), "..")
_hids_agent_dir = os.path.join(_backend, "hids-agent")
sys.path.insert(0, _backend)

os.environ.setdefault("HOST_ROOT", "")
os.environ.setdefault("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
os.environ.setdefault("FIM_PATHS", "")

# Load hids-agent app in isolation so we don't get hardening-service's cached 'app'
_spec = importlib.util.spec_from_file_location("hids_agent_app", os.path.join(_hids_agent_dir, "app.py"))
_hids_module = importlib.util.module_from_spec(_spec)
sys.modules["hids_agent_app"] = _hids_module
_spec.loader.exec_module(_hids_module)
hids_app = _hids_module


class TestBaselineRuleEngine:
    def setup_method(self):
        self.rules = hids_app.BaselineRuleEngine()

    def test_default_allowed_execs(self):
        allowed = self.rules.get_allowed_execs()
        assert "/usr/sbin/sshd" in allowed
        assert "/usr/bin/cron" in allowed

    def test_known_exec_not_alerted(self):
        from ebpf_lib.schemas.events import ProcessExecEvent
        event = ProcessExecEvent(filename="/usr/sbin/sshd")
        assert self.rules.should_alert_exec(event) is False

    def test_unknown_exec_alerted(self):
        from ebpf_lib.schemas.events import ProcessExecEvent
        event = ProcessExecEvent(filename="/tmp/malware")
        assert self.rules.should_alert_exec(event) is True

    def test_add_remove_allowed(self):
        self.rules.add_allowed_exec("/opt/myapp")
        assert "/opt/myapp" in self.rules.get_allowed_execs()
        self.rules.remove_allowed_exec("/opt/myapp")
        assert "/opt/myapp" not in self.rules.get_allowed_execs()


class TestFileIntegrityMonitor:
    def test_baseline_and_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = os.path.join(tmpdir, "test.conf")
            with open(f1, "w") as f:
                f.write("test content")

            fim = hids_app.FileIntegrityMonitor([f1], host_root="")
            baselines = fim.build_baseline()
            assert f1 in baselines

            changes = fim.check()
            assert len(changes) == 0

            with open(f1, "w") as f:
                f.write("modified")
            changes = fim.check()
            assert len(changes) == 1
            assert changes[0]["type"] == "modified"


class TestHIDSFlaskApp:
    def setup_method(self):
        hids_app.app.config["TESTING"] = True
        self.client = hids_app.app.test_client()

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["service"] == "hids-agent"

    def test_status_endpoint(self):
        resp = self.client.get("/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "stats" in data
        assert "ebpf_programs" in data

    def test_events_endpoint(self):
        resp = self.client.get("/events")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_events_with_limit(self):
        resp = self.client.get("/events?limit=5")
        assert resp.status_code == 200

    def test_baselines_endpoint(self):
        resp = self.client.get("/baselines")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "file_hashes" in data
        assert "allowed_execs" in data

    def test_rebuild_baselines(self):
        resp = self.client.post("/baselines/rebuild")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_update_allowed_execs(self):
        resp = self.client.post(
            "/baselines/execs",
            json={"path": "/opt/testapp", "action": "add"},
        )
        assert resp.status_code == 200

    def test_fim_alerts_endpoint(self):
        resp = self.client.get("/fim/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)
