"""Common detector protocol types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Finding:
    """A detector result returned for a suspicious event."""

    detection_id: str
    title: str
    severity: str
    message: str
    event: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


class Detector(Protocol):
    """Protocol implemented by custom Python detectors."""

    id: str

    def evaluate(self, event: dict[str, Any]) -> Finding | None:
        """Return a finding for matching events, otherwise ``None``."""
