"""Shared tamper-evident signing for the propose -> human-confirm -> enforce flow.

A proposal is advisory: the copilot (llm-gateway) drafts and SIGNS it, a human
confirms it, and only then may the enforcement side (policy-orchestrator) VERIFY
and act on it. Keeping sign and verify in one shared primitive — with one
HMAC secret — is what lets the enforcement boundary cryptographically prove that
an action it is asked to apply came from an authentic, unexpired, single-use
human-confirmed proposal, not from raw LLM output.

Each draft carries:

* an HMAC-SHA256 ``signature`` over its canonical security-relevant fields,
* a single-use ``nonce`` (consumed once, at enforcement time, via Redis), and
* an ``issued_at`` timestamp checked against ``ttl_seconds``.

Verification re-checks all three. None of this executes anything — it only
proves a draft is authentic, unexpired, and not already used.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Optional

logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1)
def _warn_signing_key_fallback() -> None:
    """Log the shared-token signing-key fallback once per process."""
    logger.warning(
        "COPILOT_PROPOSAL_SIGNING_KEY is not set; falling back to the shared "
        "INTERNAL_SERVICE_TOKEN as the proposal-signing key. Any holder of that "
        "token could forge a proposal signature -- provision a distinct "
        "COPILOT_PROPOSAL_SIGNING_KEY."
    )


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
    """Return the HMAC key for proposal signing/verification.

    Prefers a dedicated ``COPILOT_PROPOSAL_SIGNING_KEY``. Falling back to the
    broadly-shared ``INTERNAL_SERVICE_TOKEN`` means any holder of that token
    (ai-engine, api-gateway, the enforcement read route) could forge a proposal
    signature, so the fallback is warned about (once) rather than silent. Deploy
    a distinct ``COPILOT_PROPOSAL_SIGNING_KEY`` in multi-service environments.
    """
    explicit = os.environ.get("COPILOT_PROPOSAL_SIGNING_KEY")
    if explicit:
        return explicit.encode()
    fallback = os.environ.get("INTERNAL_SERVICE_TOKEN", "")
    if fallback:
        _warn_signing_key_fallback()
    return fallback.encode()


def _canonical(proposal: dict) -> bytes:
    missing = [f for f in _SIGNED_FIELDS if proposal.get(f) is None]
    if missing:
        raise ProposalError(f"proposal missing signed fields: {missing}")
    payload = {f: proposal[f] for f in _SIGNED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign(proposal: dict, key: Optional[bytes] = None) -> str:
    key = signing_key() if key is None else key
    if not key:
        raise ProposalError("no signing key configured")
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
        # Atomic set-if-absent with TTL: returns True only on first use. A single
        # SET NX EX avoids the prior incr-then-expire race, which could leave a
        # nonce key with no expiry if the process died between the two calls.
        return bool(self.redis.set(key, "1", nx=True, ex=self.ttl))
