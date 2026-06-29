"""The verified human-approval bridge.

Only an authentic, unexpired, single-use, HUMAN-approved proposal may cross into
enforcement. Everything else fails closed. This is where the project's #1 hard
constraint — *no LLM output reaches enforcement; a human approves* — is
cryptographically enforced at the policy boundary.
"""

import pytest

from _lib.proposal_sig import ProposalError, ProposalSigner
from proposal_approval import ApprovalError, verify_approved_proposal

KEY = b"enforce-secret"


class _FakeNonce:
    """In-memory single-use nonce store (stand-in for the Redis NonceGuard)."""

    def __init__(self):
        self.seen: set[str] = set()

    def consume(self, nonce: str) -> bool:
        if nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True


def _signed(now: float = 1000, **over):
    draft = {
        "proposal_id": "proposal:1",
        "entity_id": "h1",
        "action_type": "block",
        "ttl_seconds": 900,
    }
    draft.update(over)
    return ProposalSigner(KEY).issue(draft, now=now)


def test_valid_signed_and_approved_proposal_passes():
    out = verify_approved_proposal(_signed(), approver="mir", key=KEY, now=1000)
    assert out["approved"] is True
    assert out["approver"] == "mir"
    assert out["proposal_id"] == "proposal:1"


def test_missing_human_approver_is_rejected():
    # The copilot/LLM cannot self-approve enforcement.
    with pytest.raises(ApprovalError):
        verify_approved_proposal(_signed(), approver="", key=KEY, now=1000)


def test_forged_proposal_is_rejected_and_nonce_not_consumed():
    p = _signed()
    p["action_type"] = "quarantine"  # escalate after signing
    guard = _FakeNonce()
    with pytest.raises(ProposalError):
        verify_approved_proposal(
            p, approver="mir", key=KEY, nonce_guard=guard, now=1000
        )
    # signature is checked BEFORE the nonce is consumed, so a forged proposal
    # cannot burn a victim's nonce.
    assert p["nonce"] not in guard.seen


def test_replay_is_rejected():
    p = _signed()
    guard = _FakeNonce()
    verify_approved_proposal(p, approver="mir", key=KEY, nonce_guard=guard, now=1000)
    with pytest.raises(ApprovalError):
        verify_approved_proposal(
            p, approver="mir", key=KEY, nonce_guard=guard, now=1000
        )


def test_expired_proposal_is_rejected():
    with pytest.raises(ProposalError):
        verify_approved_proposal(_signed(now=1000), approver="mir", key=KEY, now=1901)
