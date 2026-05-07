"""Tests for the hardening service CIS benchmark engine."""

import importlib.util
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch
import pytest

_backend = os.path.join(os.path.dirname(__file__), "..")
_hardening_dir = os.path.join(_backend, "hardening-service")
sys.path.insert(0, _backend)

os.environ.setdefault("HOST_ROOT", "")
os.environ.setdefault("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

# Load hardening-service app in isolation to avoid module cache collisions
_spec = importlib.util.spec_from_file_location(
    "hardening_app",
    os.path.join(_hardening_dir, "app.py"),
    submodule_search_locations=[_hardening_dir],
)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["hardening_app"] = _mod
_spec.loader.exec_module(_mod)
hardening_app = _mod


class TestCISBenchmarkEngine:
    def setup_method(self):
        self.engine = hardening_app.CISBenchmarkEngine()

    def test_get_check_ids_returns_all(self):
        ids = self.engine.get_check_ids()
        assert len(ids) >= 20
        assert "sysctl_ip_forward" in ids
        assert "ssh_root_login" in ids
        assert "password_max_days" in ids

    def test_run_all_returns_results(self):
        results = self.engine.run_all()
        assert len(results) >= 20
        for r in results:
            assert r.check_id != ""
            assert r.status in ("pass", "fail", "error", "not_applicable")
            assert r.severity in ("critical", "high", "medium", "low", "info")

    def test_run_single_check(self):
        result = self.engine.run_check("sysctl_aslr")
        assert result is not None
        assert result.check_id == "sysctl_aslr"
        assert result.cis_reference == "CIS 1.5.2"

    def test_run_nonexistent_check(self):
        result = self.engine.run_check("nonexistent_check")
        assert result is None

    def test_ssh_checks_have_cis_references(self):
        ssh_checks = [
            "ssh_root_login",
            "ssh_protocol",
            "ssh_max_auth_tries",
            "ssh_permit_empty_passwords",
            "ssh_idle_timeout",
            "ssh_password_auth",
        ]
        for check_id in ssh_checks:
            result = self.engine.run_check(check_id)
            assert result is not None
            assert result.cis_reference.startswith("CIS")
            assert result.category == "ssh"


class TestCheckResult:
    def test_dataclass_fields(self):
        from dataclasses import asdict

        result = hardening_app.CheckResult(
            check_id="test",
            title="Test Check",
            description="A test",
            status="pass",
            severity="low",
            category="test",
            remediation="None needed",
        )
        d = asdict(result)
        assert d["check_id"] == "test"
        assert d["auto_remediable"] is False
        assert d["compliance_frameworks"] == []


@pytest.mark.skipif(
    not getattr(hardening_app, "FileIntegrityMonitor", None),
    reason="hardening-service has no FileIntegrityMonitor",
)
class TestFileIntegrityMonitor:
    def test_build_baseline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.conf")
            with open(test_file, "w") as f:
                f.write("test content")

            FileIntegrityMonitor = hardening_app.FileIntegrityMonitor
            fim = FileIntegrityMonitor([test_file], host_root="")
            baselines = fim.build_baseline()
            assert test_file in baselines
            assert len(baselines[test_file]) == 64  # SHA-256 hex

    def test_detect_modification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.conf")
            with open(test_file, "w") as f:
                f.write("original content")

            FileIntegrityMonitor = hardening_app.FileIntegrityMonitor
            fim = FileIntegrityMonitor([test_file], host_root="")
            fim.build_baseline()

            with open(test_file, "w") as f:
                f.write("modified content")

            changes = fim.check()
            assert len(changes) == 1
            assert changes[0]["type"] == "modified"
            assert changes[0]["path"] == test_file

    def test_detect_deletion(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.conf")
            with open(test_file, "w") as f:
                f.write("content")

            FileIntegrityMonitor = hardening_app.FileIntegrityMonitor
            fim = FileIntegrityMonitor([test_file], host_root="")
            fim.build_baseline()
            os.remove(test_file)

            changes = fim.check()
            assert len(changes) == 1
            assert changes[0]["type"] == "deleted"

    def test_no_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.conf")
            with open(test_file, "w") as f:
                f.write("stable content")

            FileIntegrityMonitor = hardening_app.FileIntegrityMonitor
            fim = FileIntegrityMonitor([test_file], host_root="")
            fim.build_baseline()
            changes = fim.check()
            assert len(changes) == 0


def _mock_admin_user():
    return {"id": 1, "username": "test", "role": "admin", "tenant_id": 1}


def _fake_auth_post(*args, **kwargs):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"user": _mock_admin_user()}
    return resp


class TestFlaskApp:
    def setup_method(self):
        hardening_app.app.config["TESTING"] = True
        self.client = hardening_app.app.test_client()
        self._auth_patch = patch("requests.post", side_effect=_fake_auth_post)
        self._auth_patch.start()

    def teardown_method(self):
        self._auth_patch.stop()

    def _headers(self):
        return {"Authorization": "Bearer test-token"}

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["service"] == "hardening-service"

    def test_posture_endpoint(self):
        resp = self.client.get("/posture", headers=self._headers())
        assert resp.status_code == 200
        data = resp.get_json()
        assert "posture_score" in data

    def test_list_checks(self):
        resp = self.client.get("/checks", headers=self._headers())
        assert resp.status_code == 200
        data = resp.get_json()
        assert "check_ids" in data
        assert data["total"] >= 20

    def test_run_single_check_endpoint(self):
        resp = self.client.get("/checks/sysctl_aslr", headers=self._headers())
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["check_id"] == "sysctl_aslr"

    def test_nonexistent_check_returns_404(self):
        resp = self.client.get("/checks/nonexistent", headers=self._headers())
        assert resp.status_code == 404

    def test_scan_endpoint(self):
        resp = self.client.post("/scan", headers=self._headers())
        assert resp.status_code == 200
        data = resp.get_json()
        assert "checks_run" in data
        assert "posture_score" in data

    def test_enforce_endpoint(self):
        resp = self.client.get("/enforce", headers=self._headers())
        assert resp.status_code == 200
        data = resp.get_json()
        assert "mode" in data
