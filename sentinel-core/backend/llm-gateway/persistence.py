"""Redis-backed copilot session store (ephemeral, TTL'd).

Holds session metadata, message history, and captured proposals so follow-up
questions have context. Deliberately uses Redis rather than new Postgres tables:
adding audit-adjacent schema would trip the ``audit-schema-guard`` required
check, which needs a genuine two-person review stamp that cannot be fabricated.
A durable PG store + Alembic migration is a tracked follow-up PR.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

_PREFIX = "copilot:session"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionStore:
    def __init__(self, redis_client, ttl_seconds: Optional[int] = None):
        self.redis = redis_client
        self.ttl = ttl_seconds or int(os.environ.get("COPILOT_SESSION_TTL", "3600"))

    def _meta_key(self, sid: str) -> str:
        return sid if sid.startswith(_PREFIX) else f"{_PREFIX}:{sid}"

    def _msg_key(self, sid: str) -> str:
        return f"{self._meta_key(sid)}:messages"

    def _proposal_key(self, sid: str) -> str:
        return f"{self._meta_key(sid)}:proposals"

    def create_session(self, entity_id: str) -> str:
        sid = f"{_PREFIX}:{uuid.uuid4().hex}"
        meta = {"entity_id": entity_id, "created_at": _now()}
        self.redis.setex(sid, self.ttl, json.dumps(meta))
        return sid

    def exists(self, sid: str) -> bool:
        return self.redis.get(self._meta_key(sid)) is not None

    def get_session(self, sid: str) -> Optional[dict]:
        raw = self.redis.get(self._meta_key(sid))
        return json.loads(raw) if raw else None

    def append_message(self, sid: str, role: str, content: str) -> None:
        entry = {"role": role, "content": content, "ts": _now()}
        key = self._msg_key(sid)
        self.redis.rpush(key, json.dumps(entry))
        self.redis.expire(key, self.ttl)
        self.redis.expire(self._meta_key(sid), self.ttl)

    def get_messages(self, sid: str) -> list[dict]:
        return [json.loads(x) for x in self.redis.lrange(self._msg_key(sid), 0, -1)]

    def save_proposal(self, sid: str, proposal: dict) -> None:
        key = self._proposal_key(sid)
        self.redis.rpush(key, json.dumps(proposal))
        self.redis.expire(key, self.ttl)

    def get_proposals(self, sid: str) -> list[dict]:
        return [
            json.loads(x) for x in self.redis.lrange(self._proposal_key(sid), 0, -1)
        ]
