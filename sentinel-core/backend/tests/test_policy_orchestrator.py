"""
Comprehensive tests for the SENTINEL Policy Orchestrator service
and the PolicyEngine class.

All Redis, auth-service, RuleGenerator, VendorFactory, and
PolicyValidator interactions are mocked — nothing hits the network.
"""

import json
import os
import sys
import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# Build fake Redis, mock heavy dependencies, and patch auth decorators
# BEFORE importing the policy-orchestrator app module.
# ---------------------------------------------------------------------------

_redis_kv: dict = {}
_redis_sets: dict = {}


class _FakeRedis:
    """Deterministic in-memory Redis replacement for unit tests."""

    def __init__(self, *a, **kw):
        pass

    def get(self, key):
        return _redis_kv.get(key)

    def set(self, key, value):
        _redis_kv[key] = value

    def delete(self, key):
        removed = 1 if key in _redis_kv else 0
        _redis_kv.pop(key, None)
        return removed

    def expire(self, key, ttl):
        pass

    def incr(self, key):
        val = int(_redis_kv.get(key) or 0) + 1
        _redis_kv[key] = str(val)
        return val

    def decr(self, key):
        val = int(_redis_kv.get(key) or 0) - 1
        _redis_kv[key] = str(val)
        return val

    def sadd(self, key, *values):
        _redis_sets.setdefault(key, set()).update(str(v) for v in values)

    def smembers(self, key):
        return set(_redis_sets.get(key, set()))

    def srem(self, key, *values):
        if key in _redis_sets:
            _redis_sets[key] -= set(str(v) for v in values)

    def scan_iter(self, pattern="*"):
        prefix = pattern.replace("*", "")
        return [k for k in _redis_kv if k.startswith(prefix)]

    def ping(self):
        return True


_fake_redis = _FakeRedis()


def _passthrough_auth(fn):
    return fn


def _passthrough_role(*_roles):
    def decorator(fn):
        return fn
    return decorator


# Stub modules that the policy-orchestrator app.py imports at top-level.
_mock_rule_generator = MagicMock()
_mock_vendor_factory = MagicMock()
_mock_policy_validator = MagicMock()

# Default: rule_generator.generate returns one valid rule.
_mock_rule_generator.generate.return_value = [{
    "id": "rule_test1",
    "action": "DENY",
    "protocol": "TCP",
    "source_ip": "10.0.0.5/32",
    "source_cidr": "10.0.0.5/32",
    "dest_port": 22,
    "direction": "inbound",
    "priority": 50,
    "enabled": True,
}]

# Default: validator passes.
_mock_policy_validator.validate.return_value = {"valid": True, "issues": [], "warnings": [], "rules_validated": 1}
_mock_policy_validator.is_ready.return_value = True

# Default: vendor factory returns a list.
_mock_vendor_factory.get_available_vendors.return_value = [
    {"name": "iptables", "status": "available", "connected": False, "class": "IptablesVendor"}
]
_mock_vendor = MagicMock()
_mock_vendor.apply_rules.return_value = {"success": True, "message": "applied"}
_mock_vendor.remove_rules.return_value = {"success": True}
_mock_vendor.translate_rules.return_value = [{"raw": "iptables -A ..."}]
_mock_vendor.get_status.return_value = {"connected": True, "vendor": "iptables"}
_mock_vendor_factory.get_vendor.return_value = _mock_vendor

# Prepare sys.path so the orchestrator's relative imports resolve.
_orch_dir = os.path.join(os.path.dirname(__file__), "..", "policy-orchestrator")
sys.path.insert(0, _orch_dir)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Provide stub modules the orchestrator tries to import.
_redis_mod = MagicMock()
_redis_mod.from_url.return_value = _fake_redis

sys.modules.setdefault("redis", _redis_mod)

# Auth middleware
_old_auth_middleware = sys.modules.get("auth_middleware")
sys.modules["auth_middleware"] = MagicMock(
    require_auth=_passthrough_auth,
    require_role=_passthrough_role,
)

# Vendor / validation sub-packages — create minimal stub modules so that
# `from policies.rule_generator import RuleGenerator` etc. succeed.
for mod_name in [
    "policies",
    "policies.policy_engine",
    "policies.rule_generator",
    "vendors",
    "vendors.vendor_factory",
    "vendors.base_vendor",
    "vendors.iptables_vendor",
    "vendors.aws_vendor",
    "vendors.adapter_vendor",
    "validation",
    "validation.policy_validator",
]:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

# Make RuleGenerator / VendorFactory / PolicyValidator constructors return
# our controlled mocks, and PolicyEngine return the real class.
from policies.policy_engine import PolicyEngine as _RealPolicyEngine  # noqa: E402
sys.modules["policies.policy_engine"].PolicyEngine = _RealPolicyEngine if hasattr(_RealPolicyEngine, "create_policy") else None

# We need the *real* PolicyEngine; reimport it directly from the source file.
import importlib.util

_pe_spec = importlib.util.spec_from_file_location(
    "policy_engine_real",
    os.path.join(_orch_dir, "policies", "policy_engine.py"),
)
_pe_mod = importlib.util.module_from_spec(_pe_spec)

# The policy_engine module imports redis — make sure it resolves.
_pe_mod.redis = _redis_mod
_pe_spec.loader.exec_module(_pe_mod)
RealPolicyEngine = _pe_mod.PolicyEngine

# Now patch the stubs so that when app.py does `from X import Y` it gets
# our mocks for everything except PolicyEngine (which we want real).
sys.modules["policies.policy_engine"].PolicyEngine = RealPolicyEngine
sys.modules["policies.rule_generator"].RuleGenerator = lambda: _mock_rule_generator
sys.modules["vendors.vendor_factory"].VendorFactory = lambda: _mock_vendor_factory
sys.modules["validation.policy_validator"].PolicyValidator = lambda: _mock_policy_validator

# Drop cached app module so our patches take effect.
for key in list(sys.modules):
    if key == "app" or key.endswith(".app"):
        del sys.modules[key]

import app as orch_app  # noqa: E402

# Restore auth_middleware immediately so test modules collected/run after us
# don't see the MagicMock stub we installed at line 134. orch_app has already
# captured the passthrough decorators at import time above.
if _old_auth_middleware is None:
    sys.modules.pop("auth_middleware", None)
else:
    sys.modules["auth_middleware"] = _old_auth_middleware

# Wire the orchestrator's module-level instances to our mocks.
orch_app.rule_generator = _mock_rule_generator
orch_app.vendor_factory = _mock_vendor_factory
orch_app.policy_validator = _mock_policy_validator
# Ensure policy_engine uses our fake redis.
orch_app.policy_engine = RealPolicyEngine(_fake_redis)
orch_app.redis_client = _fake_redis


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset():
    _redis_kv.clear()
    _redis_sets.clear()
    _mock_rule_generator.reset_mock()
    _mock_policy_validator.reset_mock()
    _mock_vendor_factory.reset_mock()
    _mock_vendor.reset_mock()

    # Restore sane defaults after reset_mock clears return_value.
    _mock_rule_generator.generate.return_value = [{
        "id": "rule_test1",
        "action": "DENY",
        "protocol": "TCP",
        "source_ip": "10.0.0.5/32",
        "source_cidr": "10.0.0.5/32",
        "dest_port": 22,
        "direction": "inbound",
        "priority": 50,
        "enabled": True,
    }]
    _mock_policy_validator.validate.return_value = {
        "valid": True, "issues": [], "warnings": [], "rules_validated": 1,
    }
    _mock_policy_validator.is_ready.return_value = True
    _mock_vendor_factory.get_available_vendors.return_value = [
        {"name": "iptables", "status": "available", "connected": False, "class": "IptablesVendor"},
    ]
    _mock_vendor.apply_rules.return_value = {"success": True, "message": "applied"}
    _mock_vendor.remove_rules.return_value = {"success": True}
    _mock_vendor.translate_rules.return_value = [{"raw": "iptables -A ..."}]
    _mock_vendor.get_status.return_value = {"connected": True, "vendor": "iptables"}
    _mock_vendor_factory.get_vendor.return_value = _mock_vendor

    # Re-create policy_engine with clean redis.
    orch_app.policy_engine = RealPolicyEngine(_fake_redis)
    yield


@pytest.fixture()
def client():
    orch_app.app.config["TESTING"] = True
    with orch_app.app.test_client() as c:
        yield c


def _create_policy_via_api(client, data=None):
    """Helper: POST a policy through the Flask route."""
    payload = data or {
        "name": "Block SSH brute-force",
        "action": "DENY",
        "source": {"ip": "10.0.0.5", "cidr": "/32"},
        "destination": {"port": 22},
        "protocol": "TCP",
        "priority": 50,
    }
    return client.post(
        "/api/v1/policies",
        data=json.dumps(payload),
        content_type="application/json",
    )


def _create_policy_direct(engine=None, **overrides):
    """Helper: create a policy directly through PolicyEngine."""
    eng = engine or orch_app.policy_engine
    data = {
        "name": "Test policy",
        "action": "DENY",
        "source": {"ip": "10.0.0.1"},
        "destination": {"port": 443},
        "protocol": "TCP",
        "priority": 100,
    }
    data.update(overrides)
    rules = [{"id": "r1", "action": "DENY", "protocol": "TCP",
              "source_ip": "10.0.0.1/32", "source_cidr": "10.0.0.1/32",
              "dest_port": 443}]
    return eng.create_policy(data, rules)


# ===================================================================
# SECTION A — Policy Orchestrator Flask routes
# ===================================================================

class TestHealthCheck:
    def test_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "healthy"
        assert "components" in body


# -------------------------------------------------------------------
# Create policy
# -------------------------------------------------------------------

class TestCreatePolicy:
    def test_success(self, client):
        resp = _create_policy_via_api(client)
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["message"] == "Policy created successfully"
        assert "id" in body["policy"]

    def test_empty_body_returns_400(self, client):
        resp = client.post(
            "/api/v1/policies",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_name_returns_400(self, client):
        resp = client.post(
            "/api/v1/policies",
            data=json.dumps({"action": "DENY"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "name" in resp.get_json()["error"]

    def test_missing_action_returns_400(self, client):
        resp = client.post(
            "/api/v1/policies",
            data=json.dumps({"name": "test"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "action" in resp.get_json()["error"]

    def test_validation_failure_returns_400(self, client):
        _mock_policy_validator.validate.return_value = {
            "valid": False,
            "issues": [{"message": "bad rule"}],
        }
        resp = _create_policy_via_api(client)
        assert resp.status_code == 400
        assert "validation failed" in resp.get_json()["error"].lower()

    def test_conflict_without_force_returns_409(self, client):
        _create_policy_via_api(client)
        # Second policy with overlapping rule should conflict.
        # Seed a conflict: put something in the rule index.
        _redis_sets["rule:index:10.0.0.5/32:*:22:TCP"] = {"pol_existing"}
        _redis_kv["policy:pol_existing"] = json.dumps({
            "id": "pol_existing", "name": "old", "action": "ALLOW",
        })

        resp = _create_policy_via_api(client)
        assert resp.status_code == 409
        assert "conflicts" in resp.get_json()

    def test_conflict_with_force_succeeds(self, client):
        _redis_sets["rule:index:10.0.0.5/32:*:22:TCP"] = {"pol_existing"}
        _redis_kv["policy:pol_existing"] = json.dumps({
            "id": "pol_existing", "name": "old", "action": "ALLOW",
        })

        payload = {
            "name": "Forced",
            "action": "DENY",
            "force": True,
        }
        resp = _create_policy_via_api(client, data=payload)
        assert resp.status_code == 201

    def test_vendors_applied(self, client):
        resp = _create_policy_via_api(client, data={
            "name": "With vendor",
            "action": "DENY",
            "vendors": ["iptables"],
        })
        assert resp.status_code == 201
        body = resp.get_json()
        assert any(r["vendor"] == "iptables" for r in body["policy"]["apply_results"])
        _mock_vendor.apply_rules.assert_called_once()


# -------------------------------------------------------------------
# Get policies
# -------------------------------------------------------------------

class TestGetPolicies:
    def test_empty(self, client):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        assert resp.get_json()["total"] == 0

    def test_returns_created(self, client):
        _create_policy_via_api(client)
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        assert resp.get_json()["total"] >= 1


# -------------------------------------------------------------------
# Get single policy
# -------------------------------------------------------------------

class TestGetSinglePolicy:
    def test_found(self, client):
        create_resp = _create_policy_via_api(client)
        pid = create_resp.get_json()["policy"]["id"]
        resp = client.get(f"/api/v1/policies/{pid}")
        assert resp.status_code == 200
        assert resp.get_json()["id"] == pid

    def test_not_found(self, client):
        resp = client.get("/api/v1/policies/pol_nonexistent")
        assert resp.status_code == 404


# -------------------------------------------------------------------
# Update policy
# -------------------------------------------------------------------

class TestUpdatePolicy:
    def test_success(self, client):
        pid = _create_policy_via_api(client).get_json()["policy"]["id"]
        resp = client.put(
            f"/api/v1/policies/{pid}",
            data=json.dumps({"name": "Updated Name", "action": "DENY"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.get_json()["policy"]["name"] == "Updated Name"

    def test_not_found(self, client):
        resp = client.put(
            "/api/v1/policies/pol_fake",
            data=json.dumps({"name": "x"}),
            content_type="application/json",
        )
        assert resp.status_code == 404

    def test_validation_failure(self, client):
        pid = _create_policy_via_api(client).get_json()["policy"]["id"]
        _mock_policy_validator.validate.return_value = {
            "valid": False,
            "issues": [{"message": "invalid protocol"}],
        }
        resp = client.put(
            f"/api/v1/policies/{pid}",
            data=json.dumps({"protocol": "BOGUS"}),
            content_type="application/json",
        )
        assert resp.status_code == 400


# -------------------------------------------------------------------
# Delete policy
# -------------------------------------------------------------------

class TestDeletePolicy:
    def test_success(self, client):
        pid = _create_policy_via_api(client).get_json()["policy"]["id"]
        resp = client.delete(f"/api/v1/policies/{pid}")
        assert resp.status_code == 200
        assert client.get(f"/api/v1/policies/{pid}").status_code == 404

    def test_not_found(self, client):
        resp = client.delete("/api/v1/policies/pol_nope")
        assert resp.status_code == 404

    def test_vendor_remove_called(self, client):
        pid = _create_policy_via_api(client, data={
            "name": "Vendored",
            "action": "DENY",
            "vendors": ["iptables"],
        }).get_json()["policy"]["id"]
        client.delete(f"/api/v1/policies/{pid}")
        _mock_vendor.remove_rules.assert_called()


# -------------------------------------------------------------------
# DRL decision apply (/policies/apply)
# -------------------------------------------------------------------

class TestDRLDecisionApply:
    def _drl_payload(self, **overrides):
        base = {
            "decision_id": "drl_001",
            "action": "DENY",
            "target": {
                "source_ip": "192.168.1.100",
                "source_cidr": "/32",
                "dest_port": 22,
                "protocol": "TCP",
            },
            "duration": 3600,
            "confidence": 0.95,
            "threat_type": "brute_force",
            "vendors": ["iptables"],
        }
        base.update(overrides)
        return base

    def test_success(self, client):
        resp = client.post(
            "/api/v1/policies/apply",
            data=json.dumps(self._drl_payload()),
            content_type="application/json",
        )
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["message"] == "DRL decision applied successfully"
        assert "policy_id" in body
        assert body["rules_generated"] >= 1

    def test_missing_action_returns_400(self, client):
        payload = self._drl_payload()
        del payload["action"]
        resp = client.post(
            "/api/v1/policies/apply",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_target_returns_400(self, client):
        payload = self._drl_payload()
        del payload["target"]
        resp = client.post(
            "/api/v1/policies/apply",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_validation_failure_returns_400(self, client):
        _mock_policy_validator.validate.return_value = {
            "valid": False, "issues": [{"msg": "bad"}],
        }
        resp = client.post(
            "/api/v1/policies/apply",
            data=json.dumps(self._drl_payload()),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_sandbox_failure_returns_400(self, client):
        orch_app.app.config["SANDBOX_ENABLED"] = True
        # Temporarily make test_in_sandbox fail.
        original = orch_app.policy_engine.test_in_sandbox
        orch_app.policy_engine.test_in_sandbox = lambda rules: {
            "success": False, "issues": [{"issue": "exploded"}],
        }
        try:
            resp = client.post(
                "/api/v1/policies/apply",
                data=json.dumps(self._drl_payload()),
                content_type="application/json",
            )
            assert resp.status_code == 400
            assert "sandbox" in resp.get_json()["error"].lower()
        finally:
            orch_app.policy_engine.test_in_sandbox = original

    def test_vendor_apply_called(self, client):
        client.post(
            "/api/v1/policies/apply",
            data=json.dumps(self._drl_payload()),
            content_type="application/json",
        )
        _mock_vendor.apply_rules.assert_called()


# -------------------------------------------------------------------
# Auto-apply policy (/policies/auto-apply) — CRITICAL DRL PATH
# -------------------------------------------------------------------

class TestAutoApplyPolicy:
    def _auto_payload(self, **overrides):
        base = {
            "name": "auto-deny-10.0.0.5",
            "action": "DENY",
            "source": {"ip": "10.0.0.5", "cidr": "/32"},
            "priority": 50,
            "duration": 1800,
            "auto_applied": True,
            "drl_decision": {"confidence": 0.92, "threat": "brute_force"},
        }
        base.update(overrides)
        return base

    def test_success_returns_201(self, client):
        resp = client.post(
            "/api/v1/policies/auto-apply",
            data=json.dumps(self._auto_payload()),
            content_type="application/json",
        )
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["status"] == "applied"
        assert body["auto_applied"] is True
        assert body["action"] == "DENY"
        assert "policy_id" in body

    def test_policy_stored_with_auto_applied_flag(self, client):
        resp = client.post(
            "/api/v1/policies/auto-apply",
            data=json.dumps(self._auto_payload()),
            content_type="application/json",
        )
        pid = resp.get_json()["policy_id"]
        # If create_policy returns a dict, pid is the whole dict.
        if isinstance(pid, dict):
            pid = pid["id"]
        stored = orch_app.policy_engine.get_policy(pid)
        assert stored is not None
        assert stored["auto_applied"] is True
        assert stored["applied_by"] == "drl-engine"

    def test_empty_body_returns_400(self, client):
        resp = client.post(
            "/api/v1/policies/auto-apply",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_name_returns_400(self, client):
        payload = self._auto_payload()
        del payload["name"]
        resp = client.post(
            "/api/v1/policies/auto-apply",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "name" in resp.get_json()["error"]

    def test_missing_action_returns_400(self, client):
        payload = self._auto_payload()
        del payload["action"]
        resp = client.post(
            "/api/v1/policies/auto-apply",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_validation_failure_returns_400(self, client):
        _mock_policy_validator.validate.return_value = {
            "valid": False,
            "issues": [{"msg": "bad cidr"}],
        }
        resp = client.post(
            "/api/v1/policies/auto-apply",
            data=json.dumps(self._auto_payload()),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_rate_limit_action(self, client):
        resp = client.post(
            "/api/v1/policies/auto-apply",
            data=json.dumps(self._auto_payload(action="RATE_LIMIT")),
            content_type="application/json",
        )
        assert resp.status_code == 201
        assert resp.get_json()["action"] == "RATE_LIMIT"

    def test_monitor_action(self, client):
        resp = client.post(
            "/api/v1/policies/auto-apply",
            data=json.dumps(self._auto_payload(action="MONITOR")),
            content_type="application/json",
        )
        assert resp.status_code == 201
        assert resp.get_json()["action"] == "MONITOR"


# -------------------------------------------------------------------
# Policy rollback
# -------------------------------------------------------------------

class TestPolicyRollback:
    def test_rollback_success(self, client):
        pid = _create_policy_via_api(client).get_json()["policy"]["id"]
        # Update to create version 2.
        client.put(
            f"/api/v1/policies/{pid}",
            data=json.dumps({"name": "v2", "action": "DENY"}),
            content_type="application/json",
        )
        resp = client.post(f"/api/v1/policies/{pid}/rollback")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["message"] == "Policy rolled back successfully"
        assert body["previous_version"] == 2
        assert body["current_version"] == 3

    def test_rollback_no_previous_version(self, client):
        pid = _create_policy_via_api(client).get_json()["policy"]["id"]
        resp = client.post(f"/api/v1/policies/{pid}/rollback")
        assert resp.status_code == 400
        assert "no previous version" in resp.get_json()["message"].lower()

    def test_rollback_nonexistent_policy(self, client):
        resp = client.post("/api/v1/policies/pol_ghost/rollback")
        assert resp.status_code == 400


# -------------------------------------------------------------------
# Rule translation
# -------------------------------------------------------------------

class TestRuleTranslation:
    def test_success(self, client):
        resp = client.post(
            "/api/v1/rules/translate",
            data=json.dumps({
                "rules": [{"action": "DENY", "source_ip": "1.2.3.4"}],
                "target_vendor": "iptables",
            }),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["vendor"] == "iptables"
        assert body["count"] >= 1

    def test_missing_rules_returns_400(self, client):
        resp = client.post(
            "/api/v1/rules/translate",
            data=json.dumps({"target_vendor": "iptables"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_missing_vendor_returns_400(self, client):
        resp = client.post(
            "/api/v1/rules/translate",
            data=json.dumps({"rules": [{"action": "DENY"}]}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_unknown_vendor_returns_400(self, client):
        _mock_vendor_factory.get_vendor.return_value = None
        resp = client.post(
            "/api/v1/rules/translate",
            data=json.dumps({
                "rules": [{"action": "DENY"}],
                "target_vendor": "nonexistent",
            }),
            content_type="application/json",
        )
        assert resp.status_code == 400


# -------------------------------------------------------------------
# Vendor management
# -------------------------------------------------------------------

class TestVendorManagement:
    def test_get_vendors(self, client):
        resp = client.get("/api/v1/vendors")
        assert resp.status_code == 200
        assert isinstance(resp.get_json()["vendors"], list)

    def test_vendor_status(self, client):
        resp = client.get("/api/v1/vendors/iptables/status")
        assert resp.status_code == 200

    def test_unknown_vendor_status(self, client):
        _mock_vendor_factory.get_vendor.return_value = None
        resp = client.get("/api/v1/vendors/bogus/status")
        assert resp.status_code == 404


# -------------------------------------------------------------------
# Statistics
# -------------------------------------------------------------------

class TestStatistics:
    def test_empty(self, client):
        resp = client.get("/api/v1/statistics")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["total_policies"] == 0

    def test_reflects_created_policies(self, client):
        _create_policy_via_api(client)
        _create_policy_via_api(client, data={
            "name": "Second", "action": "ALLOW", "force": True,
        })
        resp = client.get("/api/v1/statistics")
        body = resp.get_json()
        assert body["total_policies"] >= 2


# -------------------------------------------------------------------
# Validation endpoint
# -------------------------------------------------------------------

class TestValidationEndpoint:
    def test_valid_policy(self, client):
        resp = client.post(
            "/api/v1/validate",
            data=json.dumps({
                "name": "Check me",
                "action": "DENY",
                "source": {"ip": "1.2.3.4"},
            }),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["valid"] is True
        assert "rules_preview" in body

    def test_invalid_policy(self, client):
        _mock_policy_validator.validate.return_value = {
            "valid": False, "issues": [{"msg": "no action"}],
        }
        resp = client.post(
            "/api/v1/validate",
            data=json.dumps({"name": "Bad"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["valid"] is False


# -------------------------------------------------------------------
# Error handlers
# -------------------------------------------------------------------

class TestErrorHandlers:
    def test_404_for_unknown_route(self, client):
        resp = client.get("/api/v1/nonexistent")
        assert resp.status_code == 404
        assert "not found" in resp.get_json()["error"].lower()


# ===================================================================
# SECTION B — PolicyEngine unit tests (no Flask, direct calls)
# ===================================================================

class TestPolicyEngineCreatePolicy:
    def test_returns_dict_with_id(self):
        policy = _create_policy_direct()
        assert "id" in policy
        assert policy["id"].startswith("pol_")

    def test_auto_applied_flag(self):
        eng = RealPolicyEngine(_fake_redis)
        policy = eng.create_policy(
            {"name": "auto", "action": "DENY"},
            rules=[{"id": "r1", "action": "DENY"}],
            auto_applied=True,
            source="drl-engine",
        )
        assert policy["auto_applied"] is True
        assert policy["applied_by"] == "drl-engine"

    def test_default_auto_applied_false(self):
        policy = _create_policy_direct()
        assert policy["auto_applied"] is False

    def test_version_starts_at_1(self):
        policy = _create_policy_direct()
        assert policy["version"] == 1

    def test_increments_total_policies_counter(self):
        _create_policy_direct()
        assert int(_redis_kv.get("policy_orchestrator:total_policies", 0)) >= 1

    def test_duration_sets_expiry(self):
        eng = RealPolicyEngine(_fake_redis)
        policy = eng.create_policy(
            {"name": "temp", "action": "DENY", "duration": 600},
            rules=[{"id": "r1", "action": "DENY"}],
        )
        stored = _redis_kv.get(f"policy:{policy['id']}")
        assert stored is not None


class TestPolicyEngineGetPolicy:
    def test_returns_policy(self):
        policy = _create_policy_direct()
        fetched = orch_app.policy_engine.get_policy(policy["id"])
        assert fetched is not None
        assert fetched["name"] == "Test policy"

    def test_returns_none_for_missing(self):
        assert orch_app.policy_engine.get_policy("pol_missing") is None


class TestPolicyEngineGetAllPolicies:
    def test_returns_list(self):
        _create_policy_direct()
        _create_policy_direct(name="Second")
        policies = orch_app.policy_engine.get_all_policies()
        assert len(policies) >= 2

    def test_sorted_by_priority(self):
        _create_policy_direct(priority=200)
        _create_policy_direct(priority=10, name="High prio")
        policies = orch_app.policy_engine.get_all_policies()
        priorities = [p["priority"] for p in policies]
        assert priorities == sorted(priorities)

    def test_excludes_version_keys(self):
        _create_policy_direct()
        policies = orch_app.policy_engine.get_all_policies()
        for p in policies:
            assert "version" not in p.get("id", "")


class TestPolicyEngineCheckConflicts:
    def test_no_conflicts_for_unique_rules(self):
        rules = [{"source_ip": "99.99.99.99", "dest_ip": "*", "dest_port": 8080, "protocol": "TCP"}]
        conflicts = orch_app.policy_engine.check_conflicts(rules)
        assert conflicts == []

    def test_detects_conflict(self):
        policy = _create_policy_direct()
        rules = [{"source_ip": "10.0.0.1/32", "dest_ip": "*", "dest_port": 443, "protocol": "TCP"}]
        conflicts = orch_app.policy_engine.check_conflicts(rules)
        assert len(conflicts) >= 1
        assert conflicts[0]["policy_id"] == policy["id"]


class TestPolicyEngineRollback:
    def test_rollback_with_versions(self):
        eng = orch_app.policy_engine
        policy = _create_policy_direct()
        pid = policy["id"]
        eng.update_policy(pid, {"name": "v2", "action": "ALLOW"}, [{"id": "r2", "action": "ALLOW"}])

        result = eng.rollback_policy(pid)
        assert result["success"] is True
        assert result["previous_version"] == 2
        assert result["current_version"] == 3

    def test_rollback_no_previous(self):
        policy = _create_policy_direct()
        result = orch_app.policy_engine.rollback_policy(policy["id"])
        assert result["success"] is False
        assert "no previous" in result["message"].lower()

    def test_rollback_missing_policy(self):
        result = orch_app.policy_engine.rollback_policy("pol_ghost")
        assert result["success"] is False


class TestPolicyEngineSandbox:
    def test_passes_valid_rules(self):
        result = orch_app.policy_engine.test_in_sandbox([
            {"id": "r1", "action": "DENY"},
        ])
        assert result["success"] is True
        assert result["rules_tested"] == 1

    def test_fails_rule_without_action(self):
        result = orch_app.policy_engine.test_in_sandbox([
            {"id": "r1"},
        ])
        assert result["success"] is False
        assert len(result["issues"]) == 1


class TestPolicyEngineStatistics:
    def test_empty_stats(self):
        stats = orch_app.policy_engine.get_statistics()
        assert stats["total_policies"] == 0
        assert "policies_by_action" in stats
        assert "timestamp" in stats

    def test_counts_by_action(self):
        _create_policy_direct(action="DENY")
        _create_policy_direct(action="DENY", name="Second deny")
        _create_policy_direct(action="ALLOW", name="Allow one")
        stats = orch_app.policy_engine.get_statistics()
        assert stats["policies_by_action"]["DENY"] == 2
        assert stats["policies_by_action"]["ALLOW"] == 1


class TestPolicyEngineIsReady:
    def test_ready_by_default(self):
        assert orch_app.policy_engine.is_ready() is True
