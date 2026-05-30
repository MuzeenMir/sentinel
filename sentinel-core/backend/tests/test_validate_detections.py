"""Tests for the detection-as-code validator script."""

import importlib.util
from pathlib import Path


REPO_CORE = Path(__file__).resolve().parents[2]
DETECTIONS_ROOT = REPO_CORE / "detections"
VALIDATOR_PATH = REPO_CORE / "scripts" / "validate_detections.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_detections", VALIDATOR_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_valid_sigma(path: Path, rule_id: str) -> None:
    path.write_text(
        f"""
id: {rule_id}
title: Valid test rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /bin/bash
  condition: selection
level: medium
""".lstrip(),
        encoding="utf-8",
    )


def test_validator_accepts_seeded_detection_tree():
    validator = _load_validator()

    result = validator.validate_detection_tree(DETECTIONS_ROOT)

    assert result.ok, result.messages
    assert result.sigma_count >= 4
    assert result.python_detector_count >= 1


def test_validator_rejects_sigma_rule_missing_id(tmp_path):
    validator = _load_validator()
    root = tmp_path / "detections"
    sigma = root / "sigma"
    python_dir = root / "python"
    sigma.mkdir(parents=True)
    python_dir.mkdir()
    (root / "detections.config.yaml").write_text("enabled_rule_sets: [sigma]\n")
    (sigma / "missing_id.yml").write_text(
        """
title: Missing id
logsource:
  product: linux
detection:
  selection:
    EventID: 1
  condition: selection
level: low
""".lstrip(),
        encoding="utf-8",
    )

    result = validator.validate_detection_tree(root)

    assert not result.ok
    assert any(
        "missing_id.yml" in msg and "missing required field: id" in msg
        for msg in result.messages
    )


def test_validator_rejects_duplicate_sigma_ids(tmp_path):
    validator = _load_validator()
    root = tmp_path / "detections"
    sigma = root / "sigma"
    python_dir = root / "python"
    sigma.mkdir(parents=True)
    python_dir.mkdir()
    (root / "detections.config.yaml").write_text("enabled_rule_sets: [sigma]\n")
    _write_valid_sigma(sigma / "first.yml", "sentinel.test.duplicate")
    _write_valid_sigma(sigma / "second.yml", "sentinel.test.duplicate")

    result = validator.validate_detection_tree(root)

    assert not result.ok
    assert any(
        "duplicate Sigma id sentinel.test.duplicate" in msg for msg in result.messages
    )


def test_validator_rejects_unsupported_logsource(tmp_path):
    validator = _load_validator()
    root = tmp_path / "detections"
    sigma = root / "sigma"
    python_dir = root / "python"
    sigma.mkdir(parents=True)
    python_dir.mkdir()
    (root / "detections.config.yaml").write_text("enabled_rule_sets: [sigma]\n")
    (sigma / "bad_logsource.yml").write_text(
        """
id: sentinel.test.bad_logsource
title: Unsupported logsource
logsource:
  product: unknown_edr
detection:
  selection:
    EventID: 1
  condition: selection
level: low
""".lstrip(),
        encoding="utf-8",
    )

    result = validator.validate_detection_tree(root)

    assert not result.ok
    assert any("unsupported logsource" in msg for msg in result.messages)
