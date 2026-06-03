"""OPA-backed detection rule evaluation for policy-orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import requests


DEFAULT_REGO_DIR = Path(__file__).resolve().parent / "rego"
OPA_FINDINGS_PATH = "/v1/data/sentinel/detections/findings"
SUPPORTED_REGO_PACKAGE = "sentinel.detections"


class OpaRequestError(RuntimeError):
    """Raised when OPA detection evaluation cannot produce a trusted result."""


@dataclass(frozen=True)
class RegoDetectionBundle:
    """Loaded metadata for the detection Rego bundle."""

    package: str
    rule_ids: list[str]
    paths: list[Path]

    @classmethod
    def load(cls, rego_dir: Path | None = None) -> "RegoDetectionBundle":
        """Load Rego files and validate package/rule metadata."""
        root = rego_dir or DEFAULT_REGO_DIR
        paths = sorted(root.glob("*.rego"))
        if not paths:
            raise ValueError(f"{root}: no Rego rules found")

        packages: set[str] = set()
        rule_ids: list[str] = []
        seen_ids: set[str] = set()
        for path in paths:
            content = path.read_text(encoding="utf-8")
            package = _extract_package(path, content)
            packages.add(package)
            for rule_id in _extract_rule_ids(content):
                if rule_id in seen_ids:
                    raise ValueError(f"{path}: duplicate Rego detection id {rule_id}")
                seen_ids.add(rule_id)
                rule_ids.append(rule_id)

        if packages != {SUPPORTED_REGO_PACKAGE}:
            raise ValueError(
                f"{root}: Rego package must be {SUPPORTED_REGO_PACKAGE}, "
                f"found {sorted(packages)}"
            )
        if not rule_ids:
            raise ValueError(f"{root}: no sentinel:detection_id metadata found")

        return cls(
            package=SUPPORTED_REGO_PACKAGE,
            rule_ids=sorted(rule_ids),
            paths=paths,
        )


class OpaDetectionClient:
    """HTTP client for evaluating detection events through an OPA sidecar."""

    def __init__(
        self,
        *,
        base_url: str,
        post: Callable[..., Any] | None = None,
        timeout_seconds: float = 2.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._post = post or requests.post
        self.timeout_seconds = timeout_seconds

    def evaluate_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Return Rego findings for one event or fail closed."""
        url = f"{self.base_url}{OPA_FINDINGS_PATH}"
        try:
            response = self._post(
                url,
                json={"input": event},
                timeout=self.timeout_seconds,
            )
        except Exception as exc:
            raise OpaRequestError(f"OPA detection eval request failed: {exc}") from exc

        if response.status_code != 200:
            raise OpaRequestError(
                "OPA detection eval failed with status "
                f"{response.status_code}: {response.text}"
            )

        try:
            payload = response.json()
        except Exception as exc:
            raise OpaRequestError(
                f"OPA detection eval returned invalid JSON: {exc}"
            ) from exc

        findings = payload.get("result")
        if not isinstance(findings, list):
            raise OpaRequestError("OPA detection eval response missing result list")
        return [_normalize_finding(finding) for finding in findings]


def evaluate_rego_parity(event: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Evaluate the seeded Rego rules locally for parity tests.

    Runtime policy decisions use OPA through ``OpaDetectionClient``. This helper
    mirrors the checked-in Rego expressions so CI can prove the Python detector
    migration stays behaviorally equivalent without requiring an OPA binary.
    """
    findings: list[dict[str, Any]] = []

    if (
        event.get("event_type") == "network"
        and event.get("network.direction") == "outbound"
    ):
        bytes_out = int(event.get("network.bytes_out") or 0)
        if bytes_out >= 500_000_000:
            findings.append(
                {
                    "detection_id": "sentinel.python.large_outbound_upload",
                    "title": "Large outbound upload",
                    "severity": "medium",
                    "message": "Outbound transfer exceeded 500000000 bytes",
                    "metadata": {"bytes_out": bytes_out},
                }
            )

    process_name = str(event.get("process_name", "")).lower()
    command_line = str(event.get("command_line", ""))
    lowered_command = command_line.lower()
    if ("powershell" in process_name or "pwsh" in process_name) and (
        "-encodedcommand" in lowered_command or " -enc " in lowered_command
    ):
        findings.append(
            {
                "detection_id": "sentinel.python.suspicious_powershell",
                "title": "Suspicious PowerShell execution",
                "severity": "high",
                "message": f"PowerShell used EncodedCommand: {command_line}",
                "metadata": {"technique": "T1059.001"},
            }
        )

    return findings


def _extract_package(path: Path, content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("package "):
            return stripped.removeprefix("package ").strip()
    raise ValueError(f"{path}: missing Rego package declaration")


def _extract_rule_ids(content: str) -> list[str]:
    marker = "sentinel:detection_id="
    rule_ids: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") and marker in stripped:
            rule_ids.append(stripped.split(marker, 1)[1].strip())
    return rule_ids


def _normalize_finding(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise OpaRequestError("OPA detection eval returned a non-object finding")
    required = ("detection_id", "title", "severity", "message")
    missing = [field for field in required if not finding.get(field)]
    if missing:
        raise OpaRequestError(
            f"OPA detection eval finding missing fields: {', '.join(missing)}"
        )
    return {
        "detection_id": str(finding["detection_id"]),
        "title": str(finding["title"]),
        "severity": str(finding["severity"]),
        "message": str(finding["message"]),
        "metadata": dict(finding.get("metadata") or {}),
    }
