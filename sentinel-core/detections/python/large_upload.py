"""Custom detector for large outbound uploads."""

from __future__ import annotations

from typing import Any

from detection_engine import Finding


class LargeOutboundUploadDetector:
    """Detect outbound transfers above a fixed byte threshold."""

    id = "sentinel.python.large_outbound_upload"
    title = "Large outbound upload"
    severity = "medium"
    threshold_bytes = 500_000_000

    def evaluate(self, event: dict[str, Any]) -> Finding | None:
        if event.get("event_type") != "network":
            return None
        if event.get("network.direction") != "outbound":
            return None
        bytes_out = int(event.get("network.bytes_out") or 0)
        if bytes_out < self.threshold_bytes:
            return None

        return Finding(
            detection_id=self.id,
            title=self.title,
            severity=self.severity,
            message=f"Outbound transfer exceeded {self.threshold_bytes} bytes",
            event=event,
            metadata={"bytes_out": bytes_out},
        )


DETECTORS = [LargeOutboundUploadDetector()]
