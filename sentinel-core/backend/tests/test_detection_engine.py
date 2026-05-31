"""Detection-as-code registry tests."""

from pathlib import Path


DETECTIONS_ROOT = Path(__file__).resolve().parents[2] / "detections"


def test_registry_loads_seeded_sigma_rules_in_deterministic_order():
    from detection_engine import load_registry

    registry = load_registry(DETECTIONS_ROOT)

    sigma_ids = [rule.id for rule in registry.sigma_rules]
    assert len(sigma_ids) >= 4
    assert sigma_ids == sorted(sigma_ids)
    assert {
        "sentinel.sigma.auth.bruteforce",
        "sentinel.sigma.auth.privilege_escalation",
        "sentinel.sigma.process.suspicious_shell",
        "sentinel.sigma.network.data_exfiltration",
    }.issubset(set(sigma_ids))


def test_registry_loads_python_detectors_and_sample_detector_fires():
    from detection_engine import load_registry

    registry = load_registry(DETECTIONS_ROOT)
    detector = registry.python_detectors["sentinel.python.suspicious_powershell"]

    finding = detector.evaluate(
        {
            "event_type": "process",
            "process_name": "powershell.exe",
            "command_line": "powershell -NoProfile -EncodedCommand SQBFAFgA",
            "host": "workstation-7",
        }
    )

    assert finding is not None
    assert finding.detection_id == "sentinel.python.suspicious_powershell"
    assert finding.severity == "high"
    assert "EncodedCommand" in finding.message


def test_python_detector_stays_silent_for_benign_event():
    from detection_engine import load_registry

    registry = load_registry(DETECTIONS_ROOT)
    detector = registry.python_detectors["sentinel.python.suspicious_powershell"]

    assert (
        detector.evaluate(
            {
                "event_type": "process",
                "process_name": "powershell.exe",
                "command_line": "powershell Get-Process",
            }
        )
        is None
    )


def test_registry_rejects_python_detector_without_protocol(tmp_path):
    from detection_engine import DetectionValidationError, load_registry

    root = tmp_path / "detections"
    sigma = root / "sigma"
    python_dir = root / "python"
    sigma.mkdir(parents=True)
    python_dir.mkdir()
    (root / "detections.config.yaml").write_text(
        "enabled_rule_sets:\n  - sigma\n  - python\n",
        encoding="utf-8",
    )
    (python_dir / "bad_detector.py").write_text(
        "DETECTORS = [object()]\n",
        encoding="utf-8",
    )

    try:
        load_registry(root)
    except DetectionValidationError as exc:
        assert "bad_detector.py" in str(exc)
        assert "does not conform to Detector protocol" in str(exc)
    else:
        raise AssertionError("bad Python detector should fail validation")
