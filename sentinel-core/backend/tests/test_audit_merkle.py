"""Tests for the RFC 6962 Merkle tree used by the SENTINEL audit ledger (wedge #3).

The expected values are computed inline from the RFC 6962 definition so the
tests pin the construction independently of the implementation:

    leaf_hash(d) = SHA-256(0x00 || d)
    node_hash(l, r) = SHA-256(0x01 || l || r)
    MTH([])      = SHA-256("")
    MTH([d0])    = leaf_hash(d0)
    MTH(D), n>1  = node_hash(MTH(D[:k]), MTH(D[k:])),  k = largest power of 2 < n
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_merkle import (  # noqa: E402
    merkle_root,
    inclusion_proof,
    verify_proof,
    canonical_event_digest,
    chained_daily_root,
)


def _leaf(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def test_empty_tree_is_sha256_of_empty_string():
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_single_leaf_is_leaf_hash():
    d0 = b"event-0"
    assert merkle_root([d0]) == _leaf(d0)


def test_two_leaves_rfc6962():
    d0, d1 = b"event-0", b"event-1"
    expected = _node(_leaf(d0), _leaf(d1))
    assert merkle_root([d0, d1]) == expected


def test_three_leaves_rfc6962_split():
    # n=3 -> k=2: node( node(leaf0, leaf1), leaf2 )
    d0, d1, d2 = b"a", b"b", b"c"
    expected = _node(_node(_leaf(d0), _leaf(d1)), _leaf(d2))
    assert merkle_root([d0, d1, d2]) == expected


def test_root_is_order_sensitive():
    a, b = b"a", b"b"
    assert merkle_root([a, b]) != merkle_root([b, a])


def test_second_preimage_resistance_leaf_vs_node():
    # A two-leaf tree must not collide with a single leaf whose data is the
    # concatenation of the child leaf hashes — domain separation (0x00/0x01)
    # is what prevents this classic Merkle second-preimage attack.
    a, b = b"a", b"b"
    two_leaf = merkle_root([a, b])
    forged = merkle_root([_leaf(a) + _leaf(b)])
    assert two_leaf != forged


def test_determinism():
    leaves = [b"x", b"y", b"z", b"w"]
    assert merkle_root(leaves) == merkle_root(leaves)


def test_inclusion_proof_roundtrip_all_sizes_and_indices():
    for n in range(1, 9):
        leaves = [f"event-{i}".encode() for i in range(n)]
        root = merkle_root(leaves)
        for m in range(n):
            proof = inclusion_proof(leaves, m)
            assert verify_proof(root, leaves[m], m, n, proof) is True


def test_verify_proof_rejects_wrong_leaf():
    leaves = [b"a", b"b", b"c"]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 1)
    assert verify_proof(root, b"WRONG", 1, 3, proof) is False


def test_verify_proof_rejects_tampered_proof():
    leaves = [b"a", b"b", b"c", b"d"]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 0)
    bad = list(proof)
    bad[0] = bytes([bad[0][0] ^ 0xFF]) + bad[0][1:]
    assert verify_proof(root, b"a", 0, 4, bad) is False


def test_verify_proof_rejects_wrong_length():
    leaves = [b"a", b"b", b"c", b"d"]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 0)
    assert verify_proof(root, b"a", 0, 4, proof + [b"\x00" * 32]) is False
    assert verify_proof(root, b"a", 0, 4, proof[:-1]) is False


# ---------------------------------------------------------------------------
# canonical_event_digest — column-derivable per-row hash (write == verify)
# ---------------------------------------------------------------------------

_ROW = dict(
    tenant_id=7,
    category="auth",
    action="login_success",
    resource_id="auth-service",
    user_id=42,
    timestamp="2026-05-30T00:00:00Z",
    details={"actor": "user:42", "service": "auth-service", "detail": {"ip": "10.0.0.1"}},
)


def test_canonical_event_digest_is_deterministic_hex_sha256():
    d = canonical_event_digest(**_ROW)
    assert d == canonical_event_digest(**_ROW)
    assert len(d) == 64 and all(c in "0123456789abcdef" for c in d)


def test_canonical_event_digest_independent_of_details_key_order():
    a = canonical_event_digest(**{**_ROW, "details": {"x": 1, "y": 2}})
    b = canonical_event_digest(**{**_ROW, "details": {"y": 2, "x": 1}})
    assert a == b


def test_canonical_event_digest_changes_when_any_field_changes():
    base = canonical_event_digest(**_ROW)
    for field, newval in [
        ("tenant_id", 8),
        ("category", "policy"),
        ("action", "logout"),
        ("resource_id", "api-gateway"),
        ("user_id", 99),
        ("timestamp", "2026-05-30T00:00:01Z"),
        ("details", {"actor": "user:99"}),
    ]:
        assert canonical_event_digest(**{**_ROW, field: newval}) != base


# ---------------------------------------------------------------------------
# chained_daily_root — root_N = H(domain || merkle_day || prev_root)
# ---------------------------------------------------------------------------


def test_chained_daily_root_genesis_differs_from_linked():
    day = merkle_root([b"a", b"b"])
    genesis = chained_daily_root(day, None)
    linked = chained_daily_root(day, b"\x11" * 32)
    assert genesis != linked


def test_chained_daily_root_depends_on_prev():
    day = merkle_root([b"a", b"b"])
    assert chained_daily_root(day, b"\x11" * 32) != chained_daily_root(day, b"\x22" * 32)


def test_chained_daily_root_deterministic():
    day = merkle_root([b"a", b"b"])
    assert chained_daily_root(day, b"\x33" * 32) == chained_daily_root(day, b"\x33" * 32)


def test_canonical_event_digest_invariant_across_timestamp_representations():
    # Write stores "...Z"; the DB returns a datetime whose isoformat() is
    # "...+00:00". The verifier must recompute the same digest from either.
    from datetime import datetime, timezone

    base = canonical_event_digest(**{**_ROW, "timestamp": "2026-05-30T12:00:00.000000Z"})
    plus = canonical_event_digest(**{**_ROW, "timestamp": "2026-05-30T12:00:00+00:00"})
    dt = canonical_event_digest(
        **{**_ROW, "timestamp": datetime(2026, 5, 30, 12, 0, 0, tzinfo=timezone.utc)}
    )
    naive = canonical_event_digest(
        **{**_ROW, "timestamp": datetime(2026, 5, 30, 12, 0, 0)}
    )
    assert base == plus == dt == naive
