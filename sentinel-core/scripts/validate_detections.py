#!/usr/bin/env python3
"""Validate detection-as-code content."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from detection_engine import DetectionValidationError, load_registry  # noqa: E402


class ValidationResult:
    """Pure validation result used by tests and CLI."""

    def __init__(
        self,
        *,
        ok: bool,
        messages: list[str],
        sigma_count: int = 0,
        python_detector_count: int = 0,
    ):
        self.ok = ok
        self.messages = messages
        self.sigma_count = sigma_count
        self.python_detector_count = python_detector_count


def validate_detection_tree(detections_root: Path) -> ValidationResult:
    """Validate a detections tree and return structured errors."""
    try:
        registry = load_registry(detections_root)
    except DetectionValidationError as exc:
        return ValidationResult(ok=False, messages=str(exc).split("; "))
    return ValidationResult(
        ok=True,
        messages=[],
        sigma_count=len(registry.sigma_rules),
        python_detector_count=len(registry.python_detectors),
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    args = argv or sys.argv[1:]
    detections_root = Path(args[0]) if args else ROOT / "detections"
    result = validate_detection_tree(detections_root)

    if not result.ok:
        for message in result.messages:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1

    print(
        "detections validation passed "
        f"({result.sigma_count} Sigma rules, "
        f"{result.python_detector_count} Python detectors)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
