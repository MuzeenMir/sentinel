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
import json
from datetime import datetime, timezone
from typing import Any, List, Optional

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

# Domain separators keep the per-row digest and the daily-root digest in
# disjoint hash spaces (defence against cross-protocol hash reuse).
_EVENT_DOMAIN = b"sentinel.audit.event.v1\x00"
_DAILY_ROOT_DOMAIN = b"sentinel.audit.dailyroot.v1\x00"


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


def canonical_timestamp(value: Any) -> Optional[str]:
    """Normalise a timestamp (str ``...Z`` / ``+00:00`` or datetime) to a single
    canonical UTC string, so the write side and the verifier agree regardless of
    how PostgreSQL round-trips the column."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return value  # unparseable: hash verbatim (still deterministic)
    else:
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def canonical_event_digest(
    *,
    tenant_id: Optional[int],
    category: Optional[str],
    action: Optional[str],
    resource_id: Optional[str],
    user_id: Optional[int],
    timestamp: Any,
    details: Any,
) -> str:
    """Hex SHA-256 over the column-derivable, stable projection of an audit row.

    Computed identically at write time (``audit_logger``) and verify time
    (``verify_audit_chain``). ``details`` is canonicalised with sorted keys so
    JSONB round-tripping (which does not preserve key order) is irrelevant. The
    volatile ``epoch`` float and the random ``record_id`` are intentionally
    excluded — they are not reproducible from columns and not security-relevant.
    """
    projection = {
        "tenant_id": tenant_id,
        "category": category,
        "action": action,
        "resource_id": resource_id,
        "user_id": user_id,
        "timestamp": canonical_timestamp(timestamp),
        "details": details,
    }
    canonical = json.dumps(
        projection, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return hashlib.sha256(_EVENT_DOMAIN + canonical).hexdigest()


def chained_daily_root(merkle_day: bytes, prev_root: Optional[bytes]) -> bytes:
    """root_N = SHA-256(domain || merkle_root(day_N) || root_{N-1}).

    ``prev_root=None`` is the genesis day (empty predecessor). Chaining the
    daily roots makes deletion of an entire day detectable.
    """
    prev = prev_root if prev_root else b""
    return hashlib.sha256(_DAILY_ROOT_DOMAIN + merkle_day + prev).digest()
