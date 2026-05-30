"""AES-256-GCM envelope encryption for secrets at rest (T-027).

Versioned, authenticated, app-layer field encryption. Ciphertext format:

    v1:<nonce_b64>:<ciphertext+tag_b64>

- KEK (32 raw bytes) is loaded from ``SENTINEL_SECRET_KEK`` (base64). In prod it
  comes from the secret manager; KMS / per-tenant DEK is a documented follow-up.
- Each ``encrypt`` uses a fresh random 96-bit nonce (never reused).
- ``decrypt`` is authenticated: tampering or a wrong key RAISES — it never
  silently returns ciphertext or the wrong plaintext.
- A value WITHOUT the ``v1:`` prefix is treated as legacy plaintext and returned
  unchanged (transitional window before the one-shot backfill runs).
"""

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "v1"
_AAD = b"sentinel.secret.v1"
_NONCE_BYTES = 12
_KEK_BYTES = 32


class SecretCryptoError(RuntimeError):
    """Raised when encryption/decryption cannot be performed or authenticated."""


def _load_kek() -> bytes:
    raw = os.environ.get("SENTINEL_SECRET_KEK")
    if not raw:
        raise SecretCryptoError("SENTINEL_SECRET_KEK is required for secret encryption")
    try:
        kek = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecretCryptoError("SENTINEL_SECRET_KEK is not valid base64") from exc
    if len(kek) != _KEK_BYTES:
        raise SecretCryptoError(
            f"SENTINEL_SECRET_KEK must decode to {_KEK_BYTES} bytes, got {len(kek)}"
        )
    return kek


def encrypt(plaintext: str) -> str:
    """Encrypt ``plaintext`` into a versioned ``v1:nonce:ct`` token."""
    kek = _load_kek()
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(kek).encrypt(nonce, plaintext.encode("utf-8"), _AAD)
    return (
        f"{_PREFIX}:{base64.b64encode(nonce).decode()}:{base64.b64encode(ct).decode()}"
    )


def decrypt(value: str) -> str:
    """Decrypt a ``v1:`` token; pass through legacy plaintext unchanged.

    Raises ``SecretCryptoError`` on a tampered token, wrong key, missing KEK, or
    a malformed ``v1:`` token.
    """
    if not value.startswith(_PREFIX + ":"):
        return value  # transitional: legacy plaintext
    kek = _load_kek()
    try:
        _, nonce_b64, ct_b64 = value.split(":", 2)
        nonce = base64.b64decode(nonce_b64, validate=True)
        ct = base64.b64decode(ct_b64, validate=True)
        plaintext = AESGCM(kek).decrypt(nonce, ct, _AAD)
    except (InvalidTag, binascii.Error, ValueError) as exc:
        raise SecretCryptoError(
            "failed to decrypt secret (tampered or wrong key)"
        ) from exc
    return plaintext.decode("utf-8")
