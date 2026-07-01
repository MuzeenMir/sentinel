"""Verified human-approval bridge: the only path from a signed proposal to enforcement.

The copilot (llm-gateway) SIGNS an advisory proposal. Before any enforcement
adapter runs, this re-verifies — at the policy boundary — that the proposal is:

  * accompanied by an explicit HUMAN approver (no LLM self-approval),
  * cryptographically authentic and unexpired (the shared HMAC primitive), and
  * single-use (its nonce has not already been consumed).

Anything else fails closed: it raises, and the caller must create no enforcement.
This is where the project's #1 hard constraint is enforced in code.
"""

from __future__ import annotations

from typing import Any, Optional

from _lib.proposal_sig import ProposalError, ProposalSigner


class ApprovalError(ProposalError):
    """Raised when the human-approval or single-use checks fail.

    Subclasses ``ProposalError`` so a caller can catch every "do not enforce"
    outcome with one ``except`` while still distinguishing approval/replay
    failures from raw cryptographic ones.
    """


def verify_approved_proposal(
    proposal: dict,
    *,
    approver: Any,
    nonce_guard: Any,
    key: Optional[bytes] = None,
    now: Optional[float] = None,
) -> dict:
    """Return an approval record, or raise ``ProposalError``/``ApprovalError``.

    A return value is the *only* signal a caller may treat as "safe to enforce".
    """
    # 1. Hard constraint: a human must approve. LLM output cannot self-enforce.
    if not isinstance(approver, str) or not approver.strip():
        raise ApprovalError(
            "human approver required; LLM output cannot self-approve enforcement"
        )
    # 2. Authenticity + freshness. Raises on tamper / expiry / wrong key /
    #    missing signature — BEFORE any nonce is spent.
    ProposalSigner(key).verify(proposal, now=now)
    # 3. Single-use, and MANDATORY. Replay protection is a fail-closed guarantee,
    #    not an opt-in, so the guard is required rather than defaulted -- a caller
    #    cannot skip it. Reached only once the signature is proven, so a forged
    #    proposal can never burn a victim's nonce.
    if nonce_guard is None:
        raise ApprovalError(
            "nonce_guard is required; replay protection cannot be skipped"
        )
    if not nonce_guard.consume(proposal.get("nonce", "")):
        raise ApprovalError("proposal already used (replay)")
    return {
        "approved": True,
        "approver": approver.strip(),
        "proposal_id": proposal.get("proposal_id"),
    }
