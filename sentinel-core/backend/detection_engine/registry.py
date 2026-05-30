"""Load and validate file-based detections."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

from detection_engine.types import Detector, Finding


REQUIRED_SIGMA_FIELDS = ("id", "title", "logsource", "detection", "level")
SUPPORTED_SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
SUPPORTED_LOGSOURCES = {
    ("linux", "authentication"),
    ("linux", "process_creation"),
    ("network", "network_connection"),
    ("windows", "process_creation"),
    ("cloud", "cloudtrail"),
    ("application", "webserver"),
}


class DetectionValidationError(ValueError):
    """Raised when detection content cannot be loaded safely."""


@dataclass(frozen=True)
class SigmaRule:
    """Loaded Sigma YAML rule."""

    id: str
    title: str
    logsource: dict[str, Any]
    detection: dict[str, Any]
    level: str
    path: Path
    raw: dict[str, Any]


@dataclass(frozen=True)
class DetectionRegistry:
    """All loaded detection content."""

    sigma_rules: list[SigmaRule]
    python_detectors: dict[str, Detector]

    @property
    def registry(self) -> dict[str, Any]:
        """Flat lookup of every detection by id."""
        combined: dict[str, Any] = {rule.id: rule for rule in self.sigma_rules}
        combined.update(self.python_detectors)
        return combined


def default_detections_root() -> Path:
    """Return the repo's default detections root."""
    return Path(__file__).resolve().parents[2] / "detections"


def load_registry(detections_root: Path | None = None) -> DetectionRegistry:
    """Load and validate Sigma rules plus Python detectors."""
    root = detections_root or default_detections_root()
    messages: list[str] = []

    _validate_config(root, messages)
    sigma_rules = _load_sigma_rules(root / "sigma", messages)
    python_detectors = _load_python_detectors(root / "python", messages)

    duplicate_ids = set(rule.id for rule in sigma_rules) & set(python_detectors)
    for detection_id in sorted(duplicate_ids):
        messages.append(f"duplicate detection id across registries: {detection_id}")

    if messages:
        raise DetectionValidationError("; ".join(messages))

    return DetectionRegistry(
        sigma_rules=sorted(sigma_rules, key=lambda rule: rule.id),
        python_detectors=dict(sorted(python_detectors.items())),
    )


def validate_sigma_tree(sigma_dir: Path) -> tuple[list[SigmaRule], list[str]]:
    """Validate Sigma rules without loading Python detectors."""
    messages: list[str] = []
    rules = _load_sigma_rules(sigma_dir, messages)
    return rules, messages


def validate_python_detectors(
    python_dir: Path,
) -> tuple[dict[str, Detector], list[str]]:
    """Validate Python detectors without loading Sigma rules."""
    messages: list[str] = []
    detectors = _load_python_detectors(python_dir, messages)
    return detectors, messages


def _validate_config(root: Path, messages: list[str]) -> None:
    config_path = root / "detections.config.yaml"
    if not config_path.exists():
        messages.append(f"{config_path}: missing detections.config.yaml")
        return
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        messages.append(f"{config_path}: invalid YAML: {exc}")
        return
    enabled = config.get("enabled_rule_sets")
    if not isinstance(enabled, list) or not enabled:
        messages.append(f"{config_path}: enabled_rule_sets must be a non-empty list")
        return
    unsupported = sorted(set(enabled) - {"sigma", "python"})
    if unsupported:
        messages.append(
            f"{config_path}: unsupported rule sets: {', '.join(unsupported)}"
        )


def _load_sigma_rules(sigma_dir: Path, messages: list[str]) -> list[SigmaRule]:
    if not sigma_dir.exists():
        messages.append(f"{sigma_dir}: missing Sigma rules directory")
        return []

    rules: list[SigmaRule] = []
    seen_ids: dict[str, Path] = {}
    for path in sorted(sigma_dir.rglob("*.yml")) + sorted(sigma_dir.rglob("*.yaml")):
        rule = _parse_sigma_rule(path, messages)
        if rule is None:
            continue
        if rule.id in seen_ids:
            messages.append(
                f"{path}: duplicate Sigma id {rule.id} also defined in {seen_ids[rule.id]}"
            )
            continue
        seen_ids[rule.id] = path
        rules.append(rule)

    return rules


def _parse_sigma_rule(path: Path, messages: list[str]) -> SigmaRule | None:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        messages.append(f"{path}: invalid YAML: {exc}")
        return None

    if not isinstance(raw, dict):
        messages.append(f"{path}: Sigma rule must be a mapping")
        return None

    for field in REQUIRED_SIGMA_FIELDS:
        if field not in raw or raw[field] in ("", None):
            messages.append(f"{path}: missing required field: {field}")
            return None

    logsource = raw["logsource"]
    if not isinstance(logsource, dict):
        messages.append(f"{path}: logsource must be a mapping")
        return None

    product = str(logsource.get("product", "")).strip()
    category = str(logsource.get("category", "")).strip()
    service = str(logsource.get("service", "")).strip()
    source_key = (product, category or service)
    if source_key not in SUPPORTED_LOGSOURCES:
        messages.append(f"{path}: unsupported logsource {source_key}")
        return None

    detection = raw["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        messages.append(f"{path}: detection must be a mapping with condition")
        return None

    level = str(raw["level"]).lower()
    if level not in SUPPORTED_SIGMA_LEVELS:
        messages.append(f"{path}: unsupported level {raw['level']}")
        return None

    return SigmaRule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        logsource=logsource,
        detection=detection,
        level=level,
        path=path,
        raw=raw,
    )


def _load_python_detectors(
    python_dir: Path,
    messages: list[str],
) -> dict[str, Detector]:
    if not python_dir.exists():
        messages.append(f"{python_dir}: missing Python detectors directory")
        return {}

    detectors: dict[str, Detector] = {}
    for path in sorted(python_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module = _import_detector_module(path, messages)
        if module is None:
            continue

        exported = getattr(module, "DETECTORS", None)
        if not isinstance(exported, list):
            messages.append(f"{path}: DETECTORS must be a list")
            continue

        for detector in exported:
            detector_id = getattr(detector, "id", None)
            if not _conforms_to_detector(detector):
                messages.append(
                    f"{path}: {detector!r} does not conform to Detector protocol"
                )
                continue
            if detector_id in detectors:
                messages.append(f"{path}: duplicate Python detector id {detector_id}")
                continue
            detectors[str(detector_id)] = detector

    return detectors


def _import_detector_module(path: Path, messages: list[str]) -> ModuleType | None:
    module_name = f"_sentinel_detection_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        messages.append(f"{path}: cannot create import spec")
        return None

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        messages.append(f"{path}: import failed: {exc}")
        return None
    return module


def _conforms_to_detector(detector: object) -> bool:
    detector_id = getattr(detector, "id", None)
    evaluate = getattr(detector, "evaluate", None)
    if not isinstance(detector_id, str) or not detector_id.strip():
        return False
    if not callable(evaluate):
        return False
    try:
        result = evaluate({})
    except Exception:
        return False
    return result is None or isinstance(result, Finding)
