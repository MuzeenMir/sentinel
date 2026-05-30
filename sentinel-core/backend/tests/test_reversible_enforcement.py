"""Tests for reversible firewall enforcement records."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests import test_policy_orchestrator as policy_support


orch_app = policy_support.orch_app


class FakeEnforcementStore:
    def __init__(self):
        self.created = []
        self.confirmed = []

    def create_active_record(
        self,
        *,
        policy_id,
        vendor_name,
        rules,
        apply_result,
        expires_at,
        tenant_id,
    ):
        action_id = f"enf_{len(self.created) + 1}"
        record = {
            "action_id": action_id,
            "policy_id": policy_id,
            "vendor_name": vendor_name,
            "rules": rules,
            "apply_result": apply_result,
            "expires_at": expires_at,
            "tenant_id": tenant_id,
            "rollback_state": "active",
            "confirmed_permanent": False,
        }
        self.created.append(record)
        return record

    def confirm_permanent(self, action_id, *, tenant_id):
        self.confirmed.append({"action_id": action_id, "tenant_id": tenant_id})
        return {
            "action_id": action_id,
            "confirmed_permanent": True,
            "expires_at": None,
            "rollback_state": "confirmed",
        }


@pytest.fixture(autouse=True)
def _reset_policy_orchestrator(monkeypatch):
    policy_support._redis_kv.clear()
    policy_support._redis_sets.clear()
    policy_support._mock_rule_generator.reset_mock()
    policy_support._mock_policy_validator.reset_mock()
    policy_support._mock_vendor_factory.reset_mock()
    policy_support._mock_vendor.reset_mock()

    policy_support._mock_rule_generator.generate.return_value = [
        {
            "id": "rule_test1",
            "action": "DENY",
            "protocol": "TCP",
            "source_ip": "10.0.0.5",
            "source_cidr": "/32",
            "dest_port": 22,
            "direction": "INBOUND",
            "priority": 50,
            "enabled": True,
        }
    ]
    policy_support._mock_policy_validator.validate.return_value = {
        "valid": True,
        "issues": [],
        "warnings": [],
        "rules_validated": 1,
    }
    policy_support._mock_vendor.apply_rules.return_value = {
        "success": True,
        "message": "applied",
    }
    policy_support._mock_vendor.remove_rules.return_value = {"success": True}
    policy_support._mock_vendor_factory.get_vendor.return_value = (
        policy_support._mock_vendor
    )
    orch_app.policy_engine = policy_support.RealPolicyEngine(policy_support._fake_redis)
    orch_app.redis_client = policy_support._fake_redis

    store = FakeEnforcementStore()
    audits = []
    monkeypatch.setattr(orch_app, "enforcement_store", store, raising=False)
    monkeypatch.setattr(
        orch_app,
        "audit_log",
        lambda category, action, **kwargs: audits.append(
            {"category": category, "action": action, **kwargs}
        )
        or "audit_stub",
    )
    orch_app.app.config["TESTING"] = True
    orch_app.app.config["USE_V2_REVERSIBLE_ENFORCEMENT"] = True
    orch_app.app.config["ENFORCEMENT_DEFAULT_TTL_SECONDS"] = 900

    yield store, audits


@pytest.fixture()
def client():
    with orch_app.app.test_client() as c:
        yield c


def test_vendored_policy_stamps_default_ttl_and_active_rollback_record(
    client, _reset_policy_orchestrator
):
    store, audits = _reset_policy_orchestrator
    before = datetime.now(timezone.utc)

    resp = client.post(
        "/api/v1/policies",
        data=json.dumps(
            {
                "name": "Reversible block",
                "action": "DENY",
                "source": {"ip": "10.0.0.5", "cidr": "/32"},
                "destination": {"port": 22},
                "protocol": "TCP",
                "vendors": ["iptables"],
            }
        ),
        content_type="application/json",
    )

    assert resp.status_code == 201
    body = resp.get_json()
    assert body["policy"]["apply_results"][0]["enforcement_action_id"] == "enf_1"

    assert len(store.created) == 1
    record = store.created[0]
    assert record["vendor_name"] == "iptables"
    assert record["rollback_state"] == "active"
    assert record["confirmed_permanent"] is False
    assert record["expires_at"] >= before
    assert 899 <= (record["expires_at"] - before).total_seconds() <= 905
    assert any(audit["action"] == "enforcement_applied" for audit in audits)


def test_confirm_permanent_marks_action_confirmed_and_audits(
    client, _reset_policy_orchestrator
):
    store, audits = _reset_policy_orchestrator

    resp = client.post("/api/v1/enforcement-actions/enf_123/confirm")

    assert resp.status_code == 200
    assert resp.get_json()["enforcement_action"]["rollback_state"] == "confirmed"
    assert store.confirmed == [{"action_id": "enf_123", "tenant_id": None}]
    assert any(audit["action"] == "enforcement_confirmed" for audit in audits)


def test_confirm_permanent_route_is_admin_rbac_gated():
    app_source = Path(orch_app.__file__).read_text()
    route_pos = app_source.index(
        '@app.route("/api/v1/enforcement-actions/<action_id>/confirm"'
    )
    route_block = app_source[route_pos : route_pos + 250]

    assert '@require_role("admin")' in route_block
