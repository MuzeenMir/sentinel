"""Tests for the HIDS agent service."""

import importlib.util
import os
import sys
import tempfile
import time
from unittest.mock import patch, MagicMock

_backend = os.path.join(os.path.dirname(__file__), "..")
_hids_agent_dir = os.path.join(_backend, "hids-agent")
sys.path.insert(0, _backend)

os.environ.setdefault("HOST_ROOT", "")
os.environ.setdefault("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
os.environ.setdefault("FIM_PATHS", "")

# Load hids-agent app in isolation so we don't get hardening-service's cached 'app'
_spec = importlib.util.spec_from_file_location(
    "hids_agent_app", os.path.join(_hids_agent_dir, "app.py")
)
_hids_module = importlib.util.module_from_spec(_spec)
sys.modules["hids_agent_app"] = _hids_module
_spec.loader.exec_module(_hids_module)
hids_app = _hids_module

# Import ProcessExecEvent early, before other tests can pollute sys.modules
from ebpf_lib.schemas.events import ProcessExecEvent as _ProcessExecEvent


class TestBaselineRuleEngine:
    def setup_method(self):
        self.rules = hids_app.BaselineRuleEngine()

    def test_default_allowed_execs(self):
        allowed = self.rules.get_allowed_execs()
        assert "/usr/sbin/sshd" in allowed
        assert "/usr/bin/cron" in allowed

    def test_known_exec_not_alerted(self):
        event = _ProcessExecEvent(
            timestamp=time.time(),
            pid=1,
            ppid=0,
            uid=0,
            comm="sshd",
            filename="/usr/sbin/sshd",
        )
        assert self.rules.should_alert_exec(event) is False

    def test_unknown_exec_alerted(self):
        event = _ProcessExecEvent(
            timestamp=time.time(),
            pid=100,
            ppid=1,
            uid=1000,
            comm="malware",
            filename="/tmp/malware",
        )
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


def _mock_auth_user():
    """Return a mock user dict and patch auth middleware to pass through."""
    return {"id": 1, "username": "test", "role": "admin", "tenant_id": 1}


def _fake_auth_post(*args, **kwargs):
    """Fake requests.post that simulates a successful auth-service verify."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"user": _mock_auth_user()}
    return resp


class TestHIDSFlaskApp:
    def setup_method(self):
        hids_app.app.config["TESTING"] = True
        self.client = hids_app.app.test_client()
        # Patch requests.post globally — auth_middleware module may have been
        # replaced in sys.modules by other test files, so we can't patch it there.
        self._auth_patch = patch("requests.post", side_effect=_fake_auth_post)
        self._auth_patch.start()

    def teardown_method(self):
        self._auth_patch.stop()

    def _headers(self):
        return {"Authorization": "Bearer test-token"}

    def _get(self, path):
        return self.client.get(path, headers=self._headers())

    def _post(self, path, **kwargs):
        return self.client.post(path, headers=self._headers(), **kwargs)

    def test_health_endpoint(self):
        # /health typically has no auth
        resp = self.client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["service"] == "hids-agent"

    def test_status_endpoint(self):
        resp = self._get("/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "stats" in data
        assert "ebpf_programs" in data

    def test_events_endpoint(self):
        resp = self._get("/events")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_events_with_limit(self):
        resp = self._get("/events?limit=5")
        assert resp.status_code == 200

    def test_baselines_endpoint(self):
        resp = self._get("/baselines")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "file_hashes" in data
        assert "allowed_execs" in data

    def test_rebuild_baselines(self):
        resp = self._post("/baselines/rebuild")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_update_allowed_execs(self):
        resp = self._post(
            "/baselines/execs",
            json={"path": "/opt/testapp", "action": "add"},
        )
        assert resp.status_code == 200

    def test_fim_alerts_endpoint(self):
        resp = self._get("/fim/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)
