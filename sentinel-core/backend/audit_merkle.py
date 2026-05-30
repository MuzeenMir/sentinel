"""RFC 6962 Merkle tree for the SENTINEL audit ledger (wedge #3).

Pure, deterministic, dependency-free so it can be unit-tested in isolation and
re-run by an independent auditor. Domain separation (``0x00`` for leaves,
``0x01`` for interior nodes) follows RFC 6962 and is what gives the tree
second-preimage resistance.

    leaf_hash(d)   = SHA-256(0x00 || d)
    node_hash(l,r) = SHA-256(0x01 || l || r)
    MTH([])        = SHA-256("")
    MTH([d0])      = leaf_hash(d0)
    MTH(D), n>1    = node_hash(MTH(D[:k]), MTH(D[k:])), k = largest 2^x < n
"""

import hashlib
from typing import List

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest 2^x strictly less than n (n >= 2)."""
    return 2 ** ((n - 1).bit_length() - 1)


def merkle_root(leaves: List[bytes]) -> bytes:
    """Compute the RFC 6962 Merkle Tree Hash over ``leaves`` (raw leaf data)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _largest_power_of_two_below(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: List[bytes], m: int) -> List[bytes]:
    """RFC 6962 audit path for leaf index ``m`` — sibling hashes leaf->root."""
    n = len(leaves)
    if not 0 <= m < n:
        raise IndexError(f"leaf index {m} out of range for {n} leaves")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if m < k:
        return inclusion_proof(leaves[:k], m) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], m - k) + [merkle_root(leaves[:k])]


def _proof_len(n: int, m: int) -> int:
    if n == 1:
        return 0
    k = _largest_power_of_two_below(n)
    return 1 + (_proof_len(k, m) if m < k else _proof_len(n - k, m - k))


def _root_from_proof(n: int, m: int, leaf_data: bytes, proof: List[bytes]) -> bytes:
    if n == 1:
        return _leaf_hash(leaf_data)
    k = _largest_power_of_two_below(n)
    top_sibling = proof[-1]
    rest = proof[:-1]
    if m < k:
        return _node_hash(_root_from_proof(k, m, leaf_data, rest), top_sibling)
    return _node_hash(top_sibling, _root_from_proof(n - k, m - k, leaf_data, rest))


def verify_proof(
    root: bytes, leaf_data: bytes, m: int, n: int, proof: List[bytes]
) -> bool:
    """Verify ``leaf_data`` at index ``m`` is included in the tree of size ``n``."""
    if not 0 <= m < n:
        return False
    if len(proof) != _proof_len(n, m):
        return False
    return _root_from_proof(n, m, leaf_data, list(proof)) == root
