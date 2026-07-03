"""Tests for tamper-evident proposal signing (propose -> human-confirm).

A drafted proposal must be unforgeable, single-use, and time-bound so a
tampered or replayed draft can never be confirmed into enforcement.
"""

import pytest

from proposals import NonceGuard, ProposalError, ProposalSigner, sign


KEY = b"test-signing-key"


def _draft():
    return {
        "proposal_id": "proposal:abc123",
        "entity_id": "h1",
        "action_type": "block",
        "ttl_seconds": 900,
        "rationale": "brute force",
    }


def test_issue_adds_nonce_issued_at_and_signature():
    signed = ProposalSigner(KEY).issue(_draft(), now=1000)
    assert signed["nonce"]
    assert signed["issued_at"] == 1000
    assert signed["signature"] == sign(signed, KEY)


def test_verify_accepts_untampered_within_ttl():
    signer = ProposalSigner(KEY)
    signed = signer.issue(_draft(), now=1000)
    signer.verify(signed, now=1000 + 899)  # no raise


def test_verify_rejects_field_tampering():
    signer = ProposalSigner(KEY)
    signed = signer.issue(_draft(), now=1000)
    signed["action_type"] = "quarantine"  # escalate after signing
    with pytest.raises(ProposalError):
        signer.verify(signed, now=1000)


def test_verify_rejects_expired():
    signer = ProposalSigner(KEY)
    signed = signer.issue(_draft(), now=1000)
    with pytest.raises(ProposalError):
        signer.verify(signed, now=1000 + 901)  # past issued_at + ttl


def test_verify_rejects_wrong_key():
    signed = ProposalSigner(KEY).issue(_draft(), now=1000)
    with pytest.raises(ProposalError):
        ProposalSigner(b"other-key").verify(signed, now=1000)


def test_verify_rejects_missing_signature():
    draft = _draft()
    with pytest.raises(ProposalError):
        ProposalSigner(KEY).verify(draft, now=1000)


def test_verify_rejects_empty_key():
    signed = ProposalSigner(KEY).issue(_draft(), now=1000)
    with pytest.raises(ProposalError):
        ProposalSigner(b"").verify(signed, now=1000)


def test_sign_rejects_empty_key():
    # An empty key must fail at signing time too, not just at verify —
    # otherwise a misconfigured issuer mints signatures nobody can verify.
    with pytest.raises(ProposalError):
        sign(_draft() | {"nonce": "n", "issued_at": 1000}, b"")


def test_issue_rejects_empty_key():
    with pytest.raises(ProposalError):
        ProposalSigner(b"").issue(_draft(), now=1000)


def test_nonce_guard_is_single_use(fake_redis):
    guard = NonceGuard(fake_redis)
    assert guard.consume("n1") is True
    assert guard.consume("n1") is False  # replay rejected
    assert guard.consume("n2") is True
