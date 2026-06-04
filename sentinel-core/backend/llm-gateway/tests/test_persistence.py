"""Tests for the Redis-backed copilot session store.

PG persistence (copilot_sessions/messages/proposals tables) is intentionally
deferred to a follow-up PR that carries a real audit-schema review stamp; this
store keeps ephemeral, TTL'd session state in Redis (already a dependency).
"""

from persistence import SessionStore


def test_create_and_get_session(fake_redis):
    store = SessionStore(fake_redis)
    sid = store.create_session(entity_id="host-1")
    assert sid
    session = store.get_session(sid)
    assert session["entity_id"] == "host-1"
    assert store.exists(sid) is True


def test_get_missing_session_returns_none(fake_redis):
    store = SessionStore(fake_redis)
    assert store.get_session("copilot:session:missing") is None
    assert store.exists("nope") is False


def test_append_and_get_messages_preserves_order(fake_redis):
    store = SessionStore(fake_redis)
    sid = store.create_session(entity_id="h1")
    store.append_message(sid, "user", "summarize h1")
    store.append_message(sid, "assistant", "elevated [score:s1]")
    msgs = store.get_messages(sid)
    assert [m["role"] for m in msgs] == ["user", "assistant"]
    assert msgs[1]["content"] == "elevated [score:s1]"


def test_save_and_get_proposals(fake_redis):
    store = SessionStore(fake_redis)
    sid = store.create_session(entity_id="h1")
    store.save_proposal(sid, {"proposal_id": "proposal:p1", "executed": False})
    proposals = store.get_proposals(sid)
    assert len(proposals) == 1
    assert proposals[0]["executed"] is False


def test_sessions_are_tenant_isolated(fake_redis):
    # C3: a session minted under tenant-a is invisible to tenant-b even with the
    # exact token — the tenant is bound to the store, never read from the id.
    a = SessionStore(fake_redis, tenant_id="tenant-a")
    b = SessionStore(fake_redis, tenant_id="tenant-b")
    sid = a.create_session(entity_id="host-1")

    assert a.get_session(sid)["entity_id"] == "host-1"
    assert a.exists(sid) is True
    assert b.get_session(sid) is None
    assert b.exists(sid) is False


def test_messages_and_proposals_are_tenant_isolated(fake_redis):
    a = SessionStore(fake_redis, tenant_id="tenant-a")
    b = SessionStore(fake_redis, tenant_id="tenant-b")
    sid = a.create_session("h1")
    a.append_message(sid, "user", "secret")
    a.save_proposal(sid, {"executed": False})

    # Cross-tenant reads see nothing.
    assert b.get_messages(sid) == []
    assert b.get_proposals(sid) == []
    # Cross-tenant writes cannot leak into tenant-a's namespace.
    b.append_message(sid, "user", "intruder")
    assert [m["content"] for m in a.get_messages(sid)] == ["secret"]


def test_token_extraction_ignores_embedded_tenant(fake_redis):
    # Handing tenant-b a fully-qualified tenant-a key still resolves into
    # tenant-b's own namespace and misses.
    a = SessionStore(fake_redis, tenant_id="tenant-a")
    token = a.create_session("h1")
    forged = f"copilot:t:tenant-a:session:{token}"
    b = SessionStore(fake_redis, tenant_id="tenant-b")
    assert b.get_session(forged) is None
