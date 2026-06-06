"""Tamper-evident signing for the propose -> human-confirm flow.

A proposal is advisory: the copilot drafts it, a human confirms it, and only
then does the frontend forward it to the existing policy-orchestrator enforce
endpoint. The copilot never executes enforcement itself. To stop a tampered or
replayed draft from being confirmed, each draft carries:

* an HMAC-SHA256 ``signature`` over its canonical security-relevant fields,
* a single-use ``nonce`` (consumed at confirm time via Redis), and
* an ``issued_at`` timestamp checked against ``ttl_seconds``.

Confirmation re-verifies all three. None of this executes anything — it only
proves a draft is authentic, unexpired, and not already used.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Optional

# Fields bound by the signature. ``rationale`` and other display-only fields are
# intentionally excluded so UI text tweaks don't invalidate a signature, but
# anything that changes the *effect* of the action is covered.
_SIGNED_FIELDS = (
    "proposal_id",
    "entity_id",
    "action_type",
    "ttl_seconds",
    "nonce",
    "issued_at",
)


class ProposalError(ValueError):
    """Raised when a proposal fails signature / TTL / replay verification."""


def signing_key() -> bytes:
    key = os.environ.get("COPILOT_PROPOSAL_SIGNING_KEY") or os.environ.get(
        "INTERNAL_SERVICE_TOKEN", ""
    )
    return key.encode()


def _canonical(proposal: dict) -> bytes:
    missing = [f for f in _SIGNED_FIELDS if proposal.get(f) is None]
    if missing:
        raise ProposalError(f"proposal missing signed fields: {missing}")
    payload = {f: proposal[f] for f in _SIGNED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign(proposal: dict, key: Optional[bytes] = None) -> str:
    key = signing_key() if key is None else key
    return hmac.new(key, _canonical(proposal), hashlib.sha256).hexdigest()


class ProposalSigner:
    def __init__(self, key: Optional[bytes] = None):
        self._key = signing_key() if key is None else key

    def issue(self, draft: dict, *, now: Optional[float] = None) -> dict:
        now = time.time() if now is None else now
        signed = dict(draft)
        signed["nonce"] = signed.get("nonce") or uuid.uuid4().hex
        signed["issued_at"] = int(now)
        signed["signature"] = sign(signed, self._key)
        return signed

    def verify(self, proposal: dict, *, now: Optional[float] = None) -> None:
        if not self._key:
            raise ProposalError("no signing key configured")
        provided = proposal.get("signature")
        if not provided:
            raise ProposalError("missing signature")
        expected = sign(proposal, self._key)  # raises if signed fields missing
        if not hmac.compare_digest(provided, expected):
            raise ProposalError("signature mismatch")
        now = time.time() if now is None else now
        issued = int(proposal.get("issued_at", 0))
        ttl = int(proposal.get("ttl_seconds", 0))
        if ttl <= 0 or now > issued + ttl:
            raise ProposalError("proposal expired")


class NonceGuard:
    """Single-use nonce store. ``consume`` returns True on first use only."""

    def __init__(self, redis_client, ttl: Optional[int] = None):
        self.redis = redis_client
        self.ttl = ttl or int(os.environ.get("COPILOT_PROPOSAL_TTL", "3600"))

    def consume(self, nonce: str) -> bool:
        key = f"copilot:nonce:{nonce}"
        count = self.redis.incr(key)
        if count == 1:
            self.redis.expire(key, self.ttl)
        return count == 1
