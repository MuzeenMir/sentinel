"""Citation/grounding enforcement.

Grounded output cites source records inline as ``[type:id]`` (e.g.
``[audit:evt-1]``). This module enforces two checkable invariants:

1. **No hallucinated ids** — every cited id must be one the tools actually
   returned this session.
2. **Cite when data exists** — if grounded data is available, the response must
   contain at least one citation (no ungrounded narration).

It does not attempt to detect "claims" via NLP; it enforces the verifiable
contract above. The orchestration loop uses :func:`repair_instruction` to ask
the model to correct an ungrounded response.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

_CITATION_RE = re.compile(r"\[([a-z_]+:[A-Za-z0-9._:\-]+)\]")


class GroundingError(Exception):
    """Raised when output fails grounding enforcement."""


@dataclass
class GroundingResult:
    ok: bool
    cited_ids: list[str] = field(default_factory=list)
    hallucinated_ids: list[str] = field(default_factory=list)
    reason: Optional[str] = None


def extract_citations(text: str) -> list[str]:
    """Return cited record ids in order of first appearance (deduplicated)."""
    seen: list[str] = []
    for match in _CITATION_RE.finditer(text):
        cid = match.group(1)
        if cid not in seen:
            seen.append(cid)
    return seen


def validate_grounding(
    text: str, valid_ids: Iterable[str], require_citation: bool = True
) -> GroundingResult:
    valid = set(valid_ids)
    cited = extract_citations(text)
    hallucinated = [c for c in cited if c not in valid]

    if hallucinated:
        return GroundingResult(
            ok=False,
            cited_ids=cited,
            hallucinated_ids=hallucinated,
            reason=f"cited unknown record ids: {', '.join(hallucinated)}",
        )

    if require_citation and valid and not cited:
        return GroundingResult(
            ok=False,
            cited_ids=cited,
            hallucinated_ids=[],
            reason="no citation provided despite available grounded data",
        )

    return GroundingResult(ok=True, cited_ids=cited, hallucinated_ids=[])


def enforce_grounding(text: str, valid_ids: Iterable[str]) -> GroundingResult:
    result = validate_grounding(text, valid_ids)
    if not result.ok:
        raise GroundingError(result.reason)
    return result


def repair_instruction(result: GroundingResult) -> str:
    if result.hallucinated_ids:
        return (
            "Your previous answer cited record ids that were never returned by a "
            f"tool: {', '.join(result.hallucinated_ids)}. Remove or correct them. "
            "Cite only ids present in tool results, or say 'no data available'."
        )
    return (
        "Your previous answer made claims without citing any source record. "
        "Re-answer and cite each fact with its [type:id], or state that no data "
        "is available."
    )
