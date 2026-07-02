"""Backward-compatible re-export of the shared proposal-signature primitive.

The implementation moved to ``_lib.proposal_sig`` so the enforcement side
(policy-orchestrator) can VERIFY exactly what the copilot SIGNS — one HMAC
implementation, one shared secret. Existing ``from proposals import ...`` sites
in this service are unchanged.
"""

from __future__ import annotations

import os
import sys

# The implementation now lives in the shared backend/_lib package. When this
# service is imported via app.py the backend root is already on sys.path, but
# standalone entry points (e.g. `python redteam.py`) import proposals -> _lib
# directly, so make this re-export shim self-sufficient rather than assume the
# caller set the path up.
_BACKEND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)

from _lib.proposal_sig import (  # noqa: E402,F401
    NonceGuard,
    ProposalError,
    ProposalSigner,
    sign,
    signing_key,
)

__all__ = ["NonceGuard", "ProposalError", "ProposalSigner", "sign", "signing_key"]
