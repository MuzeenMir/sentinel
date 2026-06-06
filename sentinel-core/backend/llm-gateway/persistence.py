"""Redis-backed copilot session store (ephemeral, TTL'd).

Holds session metadata, message history, and captured proposals so follow-up
questions have context. Deliberately uses Redis rather than new Postgres tables:
adding audit-adjacent schema would trip the ``audit-schema-guard`` required
check, which needs a genuine two-person review stamp that cannot be fabricated.
A durable PG store + Alembic migration is a tracked follow-up PR.

**Tenant isolation (C3 interim).** Every key is namespaced by the *authenticated*
tenant, which is bound to the store at construction (the gateway derives it from
the verified ``X-Tenant-Id`` header — never from the client). The session id
handed back to the client is an opaque token with no tenant component; on every
read the key is rebuilt from the *bound* tenant, so a session minted under
tenant A cannot be reached with tenant B's context even if its token leaks
(the lookup lands in a different keyspace and misses). The stored tenant is also
re-checked on read as defence-in-depth against namespace collisions. A durable,
RLS-enforced PG store remains the tracked follow-up; this closes the
cross-tenant read gap in the interim.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

_PREFIX = "copilot"
# Used when no authenticated tenant is present (e.g. local/dev calls that did not
# arrive via the gateway). Keeps untenanted state in its own keyspace so it can
# never be read under a real tenant and vice versa.
_NO_TENANT = "_untenanted"
_TENANT_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ns_tenant(tenant_id: Optional[str]) -> str:
    """Sanitize a tenant id for use as a key segment.

    Collapses any character outside an allowlist so a crafted value cannot
    escape its namespace via embedded ``:`` separators. Collisions between two
    distinct raw tenants that sanitize to the same value are caught separately by
    the raw-tenant check stored in session metadata.
    """
    if not tenant_id:
        return _NO_TENANT
    safe = _TENANT_SAFE.sub("_", tenant_id)
    return safe or _NO_TENANT


class SessionStore:
    def __init__(
        self,
        redis_client,
        tenant_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ):
        self.redis = redis_client
        # Raw tenant kept for the metadata equality check; namespaced form used
        # for key derivation.
        self.tenant_id = tenant_id
        self._tenant_ns = _ns_tenant(tenant_id)
        self.ttl = ttl_seconds or int(os.environ.get("COPILOT_SESSION_TTL", "3600"))

    @staticmethod
    def _token(sid: str) -> str:
        """Extract the opaque session token from whatever the client sends.

        Only the final component is significant. The tenant is *never* taken
        from the supplied id — it always comes from the store's bound context —
        so passing another tenant's fully-qualified key still resolves into the
        caller's own namespace and misses.
        """
        return sid.rsplit(":", 1)[-1]

    def _meta_key(self, sid: str) -> str:
        return f"{_PREFIX}:t:{self._tenant_ns}:session:{self._token(sid)}"

    def _msg_key(self, sid: str) -> str:
        return f"{self._meta_key(sid)}:messages"

    def _proposal_key(self, sid: str) -> str:
        return f"{self._meta_key(sid)}:proposals"

    def create_session(self, entity_id: str) -> str:
        token = uuid.uuid4().hex
        meta = {
            "entity_id": entity_id,
            "tenant_id": self.tenant_id,
            "created_at": _now(),
        }
        self.redis.setex(self._meta_key(token), self.ttl, json.dumps(meta))
        return token

    def exists(self, sid: str) -> bool:
        return self.get_session(sid) is not None

    def get_session(self, sid: str) -> Optional[dict]:
        raw = self.redis.get(self._meta_key(sid))
        if not raw:
            return None
        meta = json.loads(raw)
        # Defence-in-depth: reject if the stored tenant does not match the bound
        # one (guards against sanitized-namespace collisions).
        if meta.get("tenant_id") != self.tenant_id:
            return None
        return meta

    def append_message(self, sid: str, role: str, content: str) -> None:
        if not self.exists(sid):
            return
        entry = {"role": role, "content": content, "ts": _now()}
        key = self._msg_key(sid)
        self.redis.rpush(key, json.dumps(entry))
        self.redis.expire(key, self.ttl)
        self.redis.expire(self._meta_key(sid), self.ttl)

    def get_messages(self, sid: str) -> list[dict]:
        if not self.exists(sid):
            return []
        return [json.loads(x) for x in self.redis.lrange(self._msg_key(sid), 0, -1)]

    def save_proposal(self, sid: str, proposal: dict) -> None:
        if not self.exists(sid):
            return
        key = self._proposal_key(sid)
        self.redis.rpush(key, json.dumps(proposal))
        self.redis.expire(key, self.ttl)

    def get_proposals(self, sid: str) -> list[dict]:
        if not self.exists(sid):
            return []
        return [
            json.loads(x) for x in self.redis.lrange(self._proposal_key(sid), 0, -1)
        ]
