"""Citation provenance.

The base grounding check (``grounding.py``) proves a cited ``[type:id]`` is an id
some tool returned this session. Provenance strengthens that into: the cited id
maps to a **real, recent, unaltered source record**. For every tool result we
capture ``record_id -> sha256(source_payload)`` plus the fetch time, so a
citation can be:

* **verified** — bound to an actual fetched payload (not a plausible-looking id),
* **fingerprinted** — the source hash is recorded with the answer + audit event,
  so a later verifier can detect if the cited source was changed, and
* **freshness-checked** — citations to records fetched outside the window are
  rejected (force a re-fetch rather than reason over stale data).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

DEFAULT_FRESHNESS_SECONDS = 86_400  # 24h


def source_hash(content: object) -> str:
    """Stable sha256 over canonical JSON of the source payload."""
    canon = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


@dataclass(frozen=True)
class ProvenanceEntry:
    record_id: str
    hash: str
    issued_at: int


def provenance_from_results(
    results: Iterable[dict], *, now: Optional[float] = None
) -> dict[str, ProvenanceEntry]:
    """Map each record id returned by the tools to a hash of its source payload
    and the capture time. Failed (``ok == False``) tool results are skipped."""
    ts = int(time.time() if now is None else now)
    prov: dict[str, ProvenanceEntry] = {}
    for tr in results:
        if not tr.get("ok"):
            continue
        h = source_hash(tr.get("result"))
        for rid in tr.get("record_ids", []) or []:
            prov[rid] = ProvenanceEntry(record_id=rid, hash=h, issued_at=ts)
    return prov


@dataclass
class ProvenanceResult:
    ok: bool
    cited_ids: list[str] = field(default_factory=list)
    unverifiable_ids: list[str] = field(default_factory=list)
    stale_ids: list[str] = field(default_factory=list)
    reason: Optional[str] = None
    mutated_ids: list[str] = field(default_factory=list)


def verify_citations(
    cited_ids: Iterable[str],
    provenance: dict[str, ProvenanceEntry],
    *,
    now: Optional[float] = None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    current_hashes: Optional[dict[str, str]] = None,
) -> ProvenanceResult:
    """Verify cited ids against captured provenance.

    Rejects, in order: ids with no captured source (forged/unverifiable);
    ids whose source content hash *changed* since capture when ``current_hashes``
    is supplied (mutation/tamper — opt-in re-fetch check); and ids fetched
    outside the freshness window (stale by age).
    """
    ts = int(time.time() if now is None else now)
    cited = list(cited_ids)
    unverifiable = [c for c in cited if c not in provenance]
    mutated = (
        [
            c
            for c in cited
            if c in provenance
            and c in current_hashes
            and current_hashes[c] != provenance[c].hash
        ]
        if current_hashes is not None
        else []
    )
    stale = [
        c
        for c in cited
        if c in provenance and ts - provenance[c].issued_at > freshness_seconds
    ]
    if unverifiable:
        return ProvenanceResult(
            False,
            cited,
            unverifiable,
            stale,
            f"citations without a verifiable source record: {', '.join(unverifiable)}",
            mutated_ids=mutated,
        )
    if mutated:
        return ProvenanceResult(
            False,
            cited,
            unverifiable,
            stale,
            f"citations whose source content was mutated since capture: {', '.join(mutated)}",
            mutated_ids=mutated,
        )
    if stale:
        return ProvenanceResult(
            False,
            cited,
            unverifiable,
            stale,
            f"citations beyond the freshness window: {', '.join(stale)}",
            mutated_ids=mutated,
        )
    return ProvenanceResult(True, cited, [], [], mutated_ids=mutated)


def citation_hashes(
    cited_ids: Iterable[str], provenance: dict[str, ProvenanceEntry]
) -> dict[str, str]:
    """The id -> source-hash map for the cited ids (recorded with the answer)."""
    return {c: provenance[c].hash for c in cited_ids if c in provenance}
