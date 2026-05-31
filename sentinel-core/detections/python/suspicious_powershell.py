"""Custom detector for suspicious PowerShell usage."""

from __future__ import annotations

from typing import Any

from detection_engine import Finding


class SuspiciousPowerShellDetector:
    """Detect encoded or hidden PowerShell execution."""

    id = "sentinel.python.suspicious_powershell"
    title = "Suspicious PowerShell execution"
    severity = "high"

    def evaluate(self, event: dict[str, Any]) -> Finding | None:
        process_name = str(event.get("process_name", "")).lower()
        command_line = str(event.get("command_line", ""))
        lowered = command_line.lower()

        if "powershell" not in process_name and "pwsh" not in process_name:
            return None
        if "-encodedcommand" not in lowered and " -enc " not in lowered:
            return None

        return Finding(
            detection_id=self.id,
            title=self.title,
            severity=self.severity,
            message=f"PowerShell used EncodedCommand: {command_line}",
            event=event,
            metadata={"technique": "T1059.001"},
        )


DETECTORS = [SuspiciousPowerShellDetector()]
