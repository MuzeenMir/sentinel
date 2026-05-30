"""Idempotency of the MFA-secret backfill predicate (T-027)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

from encrypt_auth_secrets import needs_encryption  # noqa: E402


def test_plaintext_needs_encryption():
    assert needs_encryption("JBSWY3DPEHPK3PXP") is True


def test_already_enveloped_is_skipped():
    assert needs_encryption("v1:abc:def") is False


def test_null_is_skipped():
    assert needs_encryption(None) is False
