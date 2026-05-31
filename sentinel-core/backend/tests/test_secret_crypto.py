"""Tests for the AES-256-GCM envelope encryption primitive (T-027).

The foot-gun-dense core: nonce uniqueness, authenticated decryption (tamper /
wrong-key must RAISE, never silently return), versioned format, and a
transitional plaintext passthrough for the pre-backfill window.
"""

import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secret_crypto import encrypt, decrypt, SecretCryptoError  # noqa: E402

_KEK_A = base64.b64encode(bytes(range(32))).decode()
_KEK_B = base64.b64encode(bytes(range(32, 64))).decode()


@pytest.fixture(autouse=True)
def _kek(monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_KEK", _KEK_A)


def test_round_trip():
    assert decrypt(encrypt("super-secret-totp-seed")) == "super-secret-totp-seed"


def test_round_trip_empty_string():
    assert decrypt(encrypt("")) == ""


def test_ciphertext_is_versioned_and_not_plaintext():
    ct = encrypt("hunter2")
    assert ct.startswith("v1:")
    assert "hunter2" not in ct


def test_nonce_is_unique_per_call():
    # Same plaintext must not produce the same ciphertext (random nonce).
    assert encrypt("same") != encrypt("same")


def test_transitional_plaintext_passthrough():
    # A value without the v1: prefix is legacy plaintext — returned as-is.
    assert decrypt("legacy-plaintext-value") == "legacy-plaintext-value"


def test_tamper_raises():
    ct = encrypt("sensitive")
    # flip a byte in the ciphertext segment
    prefix, nonce_b64, ct_b64 = ct.split(":", 2)
    raw = bytearray(base64.b64decode(ct_b64))
    raw[0] ^= 0xFF
    tampered = f"{prefix}:{nonce_b64}:{base64.b64encode(bytes(raw)).decode()}"
    with pytest.raises(SecretCryptoError):
        decrypt(tampered)


def test_wrong_key_raises(monkeypatch):
    ct = encrypt("sensitive")
    monkeypatch.setenv("SENTINEL_SECRET_KEK", _KEK_B)
    with pytest.raises(SecretCryptoError):
        decrypt(ct)


def test_missing_kek_raises(monkeypatch):
    monkeypatch.delenv("SENTINEL_SECRET_KEK", raising=False)
    with pytest.raises(SecretCryptoError):
        encrypt("x")
    with pytest.raises(SecretCryptoError):
        decrypt("v1:AAAA:AAAA")


def test_malformed_ciphertext_raises():
    with pytest.raises(SecretCryptoError):
        decrypt("v1:not-valid-base64!!!")
