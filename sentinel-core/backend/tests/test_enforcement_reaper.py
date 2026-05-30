"""Tests for the reversible-enforcement expiry reaper."""

from datetime import datetime, timezone
from pathlib import Path
import sys


POLICY_ORCH_DIR = Path(__file__).resolve().parents[1] / "policy-orchestrator"
if str(POLICY_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(POLICY_ORCH_DIR))


class FakeStore:
    def __init__(self, actions):
        self.actions = actions
        self.reverted = []
        self.failed = []

    def claim_expired_actions(self, *, limit):
        self.limit = limit
        return list(self.actions)

    def mark_reverted(self, action_id, *, reason):
        self.reverted.append({"action_id": action_id, "reason": reason})

    def mark_revert_failed(self, action_id, *, reason):
        self.failed.append({"action_id": action_id, "reason": reason})


class FakeVendorFactory:
    def __init__(self, vendor):
        self.vendor = vendor
        self.requested = []

    def get_vendor(self, name):
        self.requested.append(name)
        return self.vendor


class FakeVendor:
    def __init__(self, result):
        self.result = result
        self.removed = []

    def remove_rules(self, rules):
        self.removed.append(rules)
        return self.result


def _action(**overrides):
    base = {
        "action_id": "enf_1",
        "vendor_name": "iptables",
        "rules": [{"id": "r1", "action": "DENY"}],
        "expires_at": datetime.now(timezone.utc),
    }
    base.update(overrides)
    return base


def test_reaper_reverts_expired_active_action_and_marks_reverted():
    from enforcement_reaper import EnforcementReaper

    store = FakeStore([_action()])
    vendor = FakeVendor({"success": True})
    audits = []
    reaper = EnforcementReaper(
        store=store,
        vendor_factory=FakeVendorFactory(vendor),
        audit_log=lambda *a, **k: audits.append({"args": a, "kwargs": k}),
    )

    result = reaper.run_once(limit=25)

    assert result == {"reverted": 1, "failed": 0, "claimed": 1}
    assert vendor.removed == [[{"id": "r1", "action": "DENY"}]]
    assert store.reverted == [
        {"action_id": "enf_1", "reason": "ttl_expired_auto_rollback"}
    ]
    assert audits


def test_reaper_marks_revert_failed_and_alerts_when_inverse_fails():
    from enforcement_reaper import EnforcementReaper

    alerts = []
    store = FakeStore([_action()])
    vendor = FakeVendor({"success": False, "message": "iptables refused delete"})
    reaper = EnforcementReaper(
        store=store,
        vendor_factory=FakeVendorFactory(vendor),
        audit_log=lambda *a, **k: None,
        alert_callback=alerts.append,
    )

    result = reaper.run_once()

    assert result == {"reverted": 0, "failed": 1, "claimed": 1}
    assert store.failed[0]["action_id"] == "enf_1"
    assert "iptables refused delete" in store.failed[0]["reason"]
    assert alerts[0]["action_id"] == "enf_1"


def test_store_expiry_claim_uses_skip_locked_and_excludes_confirmed_actions():
    from enforcement_actions import EnforcementActionStore

    class FakeCursor:
        def __init__(self):
            self.sql = ""
            self.params = None

        def execute(self, sql, params=None):
            self.sql = sql
            self.params = params

        def fetchall(self):
            return []

        def close(self):
            pass

    class FakeConnection:
        def __init__(self):
            self.cursor_obj = FakeCursor()
            self.committed = False

        def cursor(self, *args, **kwargs):
            return self.cursor_obj

        def commit(self):
            self.committed = True

        def rollback(self):
            pass

        def close(self):
            pass

    conn = FakeConnection()
    store = EnforcementActionStore(connect=lambda: conn)

    store.claim_expired_actions(limit=25)

    assert "FOR UPDATE SKIP LOCKED" in conn.cursor_obj.sql
    assert "confirmed_permanent = false" in conn.cursor_obj.sql
    assert "rollback_state = 'active'" in conn.cursor_obj.sql
    assert conn.cursor_obj.params == {"limit": 25}
