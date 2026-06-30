"""The POST /enforcement endpoint: the verified-approval -> reversible-enforcement bridge.

This is where a copilot's SIGNED, advisory proposal becomes a real (but TTL-bound,
auto-reverting) firewall action -- and only when an authenticated HUMAN admin
confirms it. Every test here pins one rung of the #1 hard constraint:

    no LLM output reaches an enforcement adapter; a human approves, and the
    action is reversible.

So the suite proves both directions: a valid, human-approved proposal IS enforced
and recorded as reversible (so the reaper can roll it back on TTL); and every
failure mode -- forgery, replay, expiry, no human, wrong role, dead adapter --
fails CLOSED with nothing enforced.
"""

import types

import pytest

import app as app_module
import auth_middleware
from _lib.proposal_sig import ProposalSigner

KEY = b"test-enforce-secret"


class _FakeRedis:
    """Minimal stand-in for the Redis client NonceGuard needs (incr + expire)."""

    def __init__(self):
        self.store: dict[str, int] = {}

    def incr(self, key):
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    def expire(self, key, ttl):
        return True


class _FakeVendor:
    def __init__(self, success=True):
        self.success = success
        self.applied: list = []
        self.removed: list = []

    def apply_rules(self, rules):
        self.applied.append(rules)
        if self.success:
            return {"success": True, "applied": len(rules), "errors": []}
        return {"success": False, "message": "adapter down", "errors": ["x"]}

    def remove_rules(self, rules):
        self.removed.append(rules)
        return {"success": True, "removed": len(rules), "errors": []}


class _FakeVendorFactory:
    def __init__(self, vendor):
        self._vendor = vendor
        self.requested: list[str] = []

    def get_vendor(self, name):
        self.requested.append(name)
        return self._vendor


class _FakeStore:
    def __init__(self):
        self.created: list[dict] = []

    def create_active_record(self, **kwargs):
        self.created.append(kwargs)
        return {
            "action_id": "enf_test123",
            "expires_at": kwargs["expires_at"],
            "policy_id": kwargs["policy_id"],
            "vendor_name": kwargs["vendor_name"],
            "rollback_state": "active",
        }


@pytest.fixture
def admin_user(monkeypatch):
    monkeypatch.setattr(
        auth_middleware,
        "_verify_token",
        lambda token: {"username": "mir", "role": "admin", "tenant_id": None},
    )


@pytest.fixture
def signing_env(monkeypatch):
    monkeypatch.setenv("COPILOT_PROPOSAL_SIGNING_KEY", KEY.decode())


@pytest.fixture
def fakes(monkeypatch):
    redis_fake = _FakeRedis()
    vendor = _FakeVendor()
    factory = _FakeVendorFactory(vendor)
    store = _FakeStore()
    audited: list = []
    monkeypatch.setattr(app_module, "redis_client", redis_fake)
    monkeypatch.setattr(app_module, "vendor_factory", factory)
    monkeypatch.setattr(app_module, "enforcement_store", store)
    monkeypatch.setattr(app_module, "audit_log", lambda *a, **k: audited.append((a, k)))
    return types.SimpleNamespace(
        redis=redis_fake,
        vendor=vendor,
        factory=factory,
        store=store,
        audited=audited,
    )


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def _signed_proposal(now=None, **over):
    draft = {
        "proposal_id": "proposal:abc123",
        "executed": False,
        "reversible": True,
        "ttl_seconds": 900,
        "entity_id": "203.0.113.5",
        "action_type": "block",
        "rationale": "reverse shell egress observed",
    }
    draft.update(over)
    return ProposalSigner(KEY).issue(draft, now=now)


def _post(client, proposal, token="t"):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/enforcement", json={"proposal": proposal}, headers=headers)


def _audit_detail(fakes, event):
    for args, kwargs in fakes.audited:
        if len(args) >= 2 and args[1] == event:
            return kwargs.get("detail", {})
    return None


def test_valid_proposal_is_enforced_and_recorded(
    client, admin_user, signing_env, fakes
):
    resp = _post(client, _signed_proposal())

    assert resp.status_code == 201
    body = resp.get_json()
    assert body["enforcement_action"]["action_id"] == "enf_test123"

    # applied to the firewall adapter exactly once
    assert fakes.factory.requested == ["iptables"]
    assert len(fakes.vendor.applied) == 1

    # a durable, reversible record was created, keyed to the proposal, with a TTL
    assert len(fakes.store.created) == 1
    rec = fakes.store.created[0]
    assert rec["policy_id"] == "proposal:abc123"
    assert rec["vendor_name"] == "iptables"
    assert rec["expires_at"] is not None
    # the recorded rules are what was applied -> the reaper can invert them
    assert rec["rules"] == fakes.vendor.applied[0]

    # the audit trail names the HUMAN approver, not the LLM
    detail = _audit_detail(fakes, "enforcement_applied")
    assert detail is not None
    assert detail["approver"] == "mir"
    assert detail["proposal_id"] == "proposal:abc123"


def test_forged_proposal_is_refused_and_nothing_enforced(
    client, admin_user, signing_env, fakes
):
    p = _signed_proposal()
    p["action_type"] = "quarantine"  # escalate the action AFTER signing

    resp = _post(client, p)

    assert resp.status_code == 403
    assert fakes.vendor.applied == []
    assert fakes.store.created == []
    # signature is checked before the nonce is spent: a forgery can't burn a
    # victim's nonce (a denial-of-service on a legitimate future proposal).
    assert f"copilot:nonce:{p['nonce']}" not in fakes.redis.store


def test_replay_of_a_used_proposal_is_refused(client, admin_user, signing_env, fakes):
    p = _signed_proposal()

    assert _post(client, p).status_code == 201
    assert _post(client, p).status_code == 403

    # enforced exactly once despite two identical, validly-signed submissions
    assert len(fakes.store.created) == 1


def test_unauthenticated_request_is_rejected(client, signing_env, fakes):
    resp = _post(client, _signed_proposal(), token=None)

    assert resp.status_code == 401
    assert fakes.vendor.applied == []
    assert fakes.store.created == []


def test_non_admin_principal_is_forbidden(client, monkeypatch, signing_env, fakes):
    # An authenticated non-admin (or a service identity) is not a human approver.
    monkeypatch.setattr(
        auth_middleware,
        "_verify_token",
        lambda token: {
            "username": "analyst",
            "role": "security_analyst",
            "tenant_id": None,
        },
    )

    resp = _post(client, _signed_proposal())

    assert resp.status_code == 403
    assert fakes.vendor.applied == []
    assert fakes.store.created == []


def test_expired_proposal_is_refused(client, admin_user, signing_env, fakes):
    # issued_at=1000, ttl=900 -> long expired by real wall-clock time
    resp = _post(client, _signed_proposal(now=1000))

    assert resp.status_code == 403
    assert fakes.vendor.applied == []
    assert fakes.store.created == []


def test_adapter_failure_records_no_reversible_action(
    client, admin_user, signing_env, fakes
):
    fakes.vendor.success = False

    resp = _post(client, _signed_proposal())

    assert resp.status_code == 502
    # nothing to roll back, so no reversible record is created
    assert fakes.store.created == []


def test_unenforceable_entity_id_is_rejected(client, admin_user, signing_env, fakes):
    # A validly-signed proposal whose entity isn't a network identifier the
    # firewall adapter can act on must fail closed, not enforce something wrong.
    resp = _post(client, _signed_proposal(entity_id="not-an-ip"))

    assert resp.status_code == 422
    assert fakes.vendor.applied == []
    assert fakes.store.created == []


def test_record_failure_rolls_back_the_applied_rule(
    client, admin_user, signing_env, fakes, monkeypatch
):
    # If the durable record can't be written after the rule is applied, the
    # applied rule must be rolled back immediately -- never leave an
    # un-revertible firewall change. The reaper only reverts *recorded* actions,
    # so an un-recorded applied rule would silently break the reversibility the
    # proposal promised.
    def _boom(**kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(fakes.store, "create_active_record", _boom)

    resp = _post(client, _signed_proposal())

    assert resp.status_code == 500
    # the rule was applied, then compensated (removed) because it couldn't be
    # recorded as reversible
    assert len(fakes.vendor.applied) == 1
    assert fakes.vendor.removed == [fakes.vendor.applied[0]]


def test_missing_proposal_body_is_rejected(client, admin_user, fakes):
    resp = client.post("/enforcement", json={}, headers={"Authorization": "Bearer t"})

    assert resp.status_code == 400
    assert fakes.store.created == []
