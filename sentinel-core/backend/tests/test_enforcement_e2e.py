"""Full reversible-enforcement e2e: detect -> analyst reads -> propose ->
human-approve -> enforce -> read-back -> TTL-expire -> reaper auto-revert.

Stitches the unit-proven pieces into ONE flow against a REAL Redis (event
stream + single-use nonce) and a REAL PostgreSQL (node_alerts +
enforcement_actions), exactly as wired in production:

  auditd line -> NodeCollector -> Redis stream -> NodeConsumer -> node_alerts
  -> get_node_alerts (analyst reads the detector's output)
  -> propose_reversible_action (signed, advisory, no HTTP)
  -> POST /enforcement (admin approval; HMAC verify + single-use nonce in Redis)
  -> enforcement_actions row (TTL-bound) + firewall adapter apply
  -> GET /enforcement/<entity> reports "blocked"
  -> expiry -> EnforcementReaper.run_once() -> adapter inverse + reverted
  -> GET /enforcement/<entity> reports "none"

Only the firewall vendor is faked (no iptables/NET_ADMIN on dev/CI hosts) and
admin JWT verification is stubbed (no auth-service). Everything else is the
production code path. Skips cleanly when Redis/PostgreSQL are unreachable,
like test_node_pipeline.py.
"""

import importlib.util
import os
import sys
import uuid

import pytest

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# Only dirs whose module names are unique across services; the ambiguous
# `app` module is NOT resolved via sys.path (see _load_policy_orchestrator).
for _svc in ("data-collector", "ai-engine", "llm-gateway"):
    sys.path.insert(0, os.path.join(_BACKEND, _svc))
sys.path.insert(0, _BACKEND)  # _lib


def _load_policy_orchestrator():
    """Import policy-orchestrator's app + collaborators without the `app`
    name race: sibling test modules (e.g. test_node_pipeline.py) prepend other
    service dirs to sys.path at collection time, so a bare ``import app`` can
    land on ai-engine/app.py depending on which tests were collected. Loading
    by file path under a unique module name is collection-order-proof.
    """
    podir = os.path.join(_BACKEND, "policy-orchestrator")
    sys.path.insert(0, podir)
    try:
        spec = importlib.util.spec_from_file_location(
            "policy_orch_app", os.path.join(podir, "app.py")
        )
        policy_app = importlib.util.module_from_spec(spec)
        sys.modules["policy_orch_app"] = policy_app
        spec.loader.exec_module(policy_app)
        # These names are unique to policy-orchestrator; importing them while
        # its dir is at sys.path[0] binds them (and their sys.modules entries,
        # which app.py's decorators share) to the right service.
        import auth_middleware
        import enforcement_actions
        import enforcement_reaper

        return policy_app, auth_middleware, enforcement_actions, enforcement_reaper
    finally:
        sys.path.remove(podir)


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel"
)
KEY = "e2e-enforce-loop-key"
ATTACKER_IP = "203.0.113.77"


@pytest.fixture(scope="module")
def redis_client():
    redis = pytest.importorskip("redis")
    client = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        client.ping()
    except Exception:
        pytest.skip(f"Redis not reachable at {REDIS_URL}")
    return client


@pytest.fixture(scope="module")
def pg_conn():
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        conn = psycopg2.connect(DATABASE_URL)
    except Exception:
        pytest.skip(f"PostgreSQL not reachable at {DATABASE_URL}")
        return  # unreachable (skip raises); proves conn is bound at yield below
    yield conn
    conn.close()


class _FakeVendor:
    """Records apply/remove calls; no host firewall is touched."""

    def __init__(self):
        self.applied: list = []
        self.removed: list = []

    def apply_rules(self, rules):
        self.applied.append(rules)
        return {"success": True, "applied": len(rules), "errors": []}

    def remove_rules(self, rules):
        self.removed.append(rules)
        return {"success": True, "removed": len(rules), "errors": []}


class _FakeVendorFactory:
    def __init__(self, vendor):
        self._vendor = vendor

    def get_vendor(self, name):
        return self._vendor


class _NoHTTP:
    """The analyst path used here must not need sibling services over HTTP."""

    def get(self, *a, **k):
        raise AssertionError("e2e loop must not call sibling services over HTTP")

    post = get


def test_full_reversible_enforcement_loop(redis_client, pg_conn, monkeypatch):
    psycopg2 = pytest.importorskip("psycopg2")
    monkeypatch.setenv("COPILOT_PROPOSAL_SIGNING_KEY", KEY)
    monkeypatch.setenv("INTERNAL_SERVICE_TOKEN", "svc-secret")

    from node_collector import NodeCollector
    from node_consumer import NodeConsumer
    from node_scoring import RuleScorer
    from tools import ToolRegistry

    policy_app, auth_middleware, _actions, _reaper = _load_policy_orchestrator()
    EnforcementActionStore = _actions.EnforcementActionStore
    EnforcementReaper = _reaper.EnforcementReaper

    marker = uuid.uuid4().hex
    stream = f"node:events:e2e:{marker}"
    group = f"node-detector-e2e-{marker}"
    action_id = None
    nonce = None

    try:
        # --- 1) detect: a real execve event becomes a stored node alert -------
        collector = NodeCollector(redis_client, stream=stream)
        audit_lines = [
            f"type=SYSCALL msg=audit(1700000000.1:1): syscall=59 pid=4242 uid=0 "
            f'comm="nc" exe="/usr/bin/nc" key="exec-{marker}"',
            'type=EXECVE msg=audit(1700000000.1:1): argc=3 a0="nc" a1="-e" a2="/bin/sh"',
        ]
        assert collector.feed_lines(audit_lines) == 1

        consumer = NodeConsumer(
            redis_client, RuleScorer(), stream=stream, group=group, consumer="e2e"
        )
        consumer.ensure_group()
        assert consumer.process_once(pg_conn, block_ms=1000, count=10) == 1

        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM node_alerts WHERE detail->>'raw' LIKE %s "
                "ORDER BY id DESC LIMIT 1",
                (f"%{marker}%",),
            )
            row = cur.fetchone()
        assert row is not None
        alert_pk = row[0]

        # --- 2) the analyst reads the detector's output (production tool,
        #        direct real-PG read, no HTTP) --------------------------------
        registry = ToolRegistry(
            config={"ai_engine_url": "x", "api_gateway_url": "x", "policy_url": "x"},
            session=_NoHTTP(),
            service_token="t",
            db_connect=lambda: psycopg2.connect(DATABASE_URL),
        )
        alerts_out = registry.execute("get_node_alerts", {"limit": 10})
        assert alerts_out["ok"] is True
        assert f"node_alert:{alert_pk}" in alerts_out["record_ids"]

        # --- 3) the analyst proposes a reversible block (signed, advisory) ---
        prop_out = registry.execute(
            "propose_reversible_action",
            {
                "entity_id": ATTACKER_IP,
                "action_type": "block",
                "ttl_seconds": 900,
                "rationale": f"nc reverse shell (node_alert:{alert_pk})",
            },
        )
        proposal = prop_out["result"]
        nonce = proposal["nonce"]
        assert proposal["executed"] is False
        assert proposal["reversible"] is True
        assert proposal["signature"]

        # --- 4) human approval enforces it: real route, real Redis nonce,
        #        real PG store, fake firewall adapter -------------------------
        real_store = EnforcementActionStore(
            connect=lambda: psycopg2.connect(DATABASE_URL)
        )
        vendor = _FakeVendor()
        audited: list = []
        monkeypatch.setattr(
            auth_middleware,
            "_verify_token",
            lambda token: {"username": "mir", "role": "admin", "tenant_id": None},
        )
        monkeypatch.setattr(policy_app, "redis_client", redis_client)
        monkeypatch.setattr(policy_app, "enforcement_store", real_store)
        monkeypatch.setattr(policy_app, "vendor_factory", _FakeVendorFactory(vendor))
        monkeypatch.setattr(
            policy_app, "audit_log", lambda *a, **k: audited.append((a, k))
        )
        policy_app.app.config["TESTING"] = True
        client = policy_app.app.test_client()

        resp = client.post(
            "/enforcement",
            json={"proposal": proposal},
            headers={"Authorization": "Bearer t"},
        )
        assert resp.status_code == 201, resp.get_data(as_text=True)
        action_id = resp.get_json()["enforcement_action"]["action_id"]
        assert len(vendor.applied) == 1
        assert vendor.applied[0][0]["source_ip"] == ATTACKER_IP
        # audit trail names the human approver, and authorization was audited
        assert any(a[1] == "enforcement_authorized" for a, _ in audited)

        # single-use for real: an identical, validly-signed replay is refused
        # by the REAL Redis nonce (SET NX EX), and nothing is enforced twice.
        assert (
            client.post(
                "/enforcement",
                json={"proposal": proposal},
                headers={"Authorization": "Bearer t"},
            ).status_code
            == 403
        )
        assert len(vendor.applied) == 1

        # --- 5) the copilot's read-back sees the active block ----------------
        state = client.get(
            f"/enforcement/{ATTACKER_IP}",
            headers={"X-Internal-Service-Token": "svc-secret"},
        )
        assert state.status_code == 200
        body = state.get_json()
        assert body["state"] == "blocked"
        assert body["active"] is True
        assert body["actions"][0]["ttl_seconds_remaining"] > 0

        # --- 6) TTL expiry -> the reaper auto-reverts (real claim + real
        #        state transition; adapter inverse recorded on the fake) ------
        with pg_conn.cursor() as cur:
            cur.execute(
                "UPDATE enforcement_actions "
                "SET expires_at = NOW() - INTERVAL '1 second' "
                "WHERE action_id = %s",
                (action_id,),
            )
        pg_conn.commit()

        reaper = EnforcementReaper(
            store=real_store,
            vendor_factory=_FakeVendorFactory(vendor),
            audit_log=lambda *a, **k: audited.append((a, k)),
            alert_callback=lambda alert: None,
        )
        result = reaper.run_once()
        assert result["reverted"] >= 1
        assert any(
            rules and rules[0].get("source_ip") == ATTACKER_IP
            for rules in vendor.removed
        )
        assert any(a[1] == "enforcement_reverted" for a, _ in audited)

        # --- 7) the loop is closed: read-back reports nothing active ---------
        state = client.get(
            f"/enforcement/{ATTACKER_IP}",
            headers={"X-Internal-Service-Token": "svc-secret"},
        )
        assert state.status_code == 200
        body = state.get_json()
        assert body["state"] == "none"
        assert body["active"] is False

        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT rollback_state FROM enforcement_actions WHERE action_id = %s",
                (action_id,),
            )
            assert cur.fetchone()[0] == "reverted"
    finally:
        with pg_conn.cursor() as cur:
            cur.execute(
                "DELETE FROM node_alerts WHERE detail->>'raw' LIKE %s",
                (f"%{marker}%",),
            )
            if action_id:
                cur.execute(
                    "DELETE FROM enforcement_actions WHERE action_id = %s",
                    (action_id,),
                )
        pg_conn.commit()
        redis_client.delete(stream)
        if nonce:
            redis_client.delete(f"copilot:nonce:{nonce}")
