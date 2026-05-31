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
