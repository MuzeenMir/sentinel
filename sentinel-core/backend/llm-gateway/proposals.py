"""Backward-compatible re-export of the shared proposal-signature primitive.

The implementation moved to ``_lib.proposal_sig`` so the enforcement side
(policy-orchestrator) can VERIFY exactly what the copilot SIGNS — one HMAC
implementation, one shared secret. Existing ``from proposals import ...`` sites
in this service are unchanged.
"""

from __future__ import annotations

from _lib.proposal_sig import (  # noqa: F401
    NonceGuard,
    ProposalError,
    ProposalSigner,
    sign,
    signing_key,
)

__all__ = ["NonceGuard", "ProposalError", "ProposalSigner", "sign", "signing_key"]
