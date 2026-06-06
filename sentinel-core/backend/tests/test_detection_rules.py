"""Tests for OPA-backed detection rule evaluation."""

from __future__ import annotations

import json
import sys
from pathlib import Path


BACKEND = Path(__file__).resolve().parents[1]
POLICY_ORCHESTRATOR = BACKEND / "policy-orchestrator"
DETECTIONS = BACKEND.parent / "detections"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(POLICY_ORCHESTRATOR) not in sys.path:
    sys.path.insert(0, str(POLICY_ORCHESTRATOR))

from detection_engine import load_registry  # noqa: E402
from detection_rules import (  # noqa: E402
    OpaDetectionClient,
    OpaRequestError,
    RegoDetectionBundle,
    evaluate_rego_parity,
)


def test_rego_loader_discovers_seeded_detection_rules():
    bundle = RegoDetectionBundle.load()

    assert bundle.package == "sentinel.detections"
    assert bundle.rule_ids == [
        "sentinel.python.large_outbound_upload",
        "sentinel.python.suspicious_powershell",
    ]
    assert all(path.suffix == ".rego" for path in bundle.paths)


def test_opa_eval_posts_event_to_sidecar_and_returns_findings():
    calls: list[tuple[str, dict, float]] = []

    def post(url, *, json, timeout):  # noqa: A002
        calls.append((url, json, timeout))
        return _Response(
            200,
            {
                "result": [
                    {
                        "detection_id": "sentinel.python.large_outbound_upload",
                        "title": "Large outbound upload",
                        "severity": "medium",
                        "message": "Outbound transfer exceeded 500000000 bytes",
                        "metadata": {"bytes_out": 700_000_000},
                    }
                ]
            },
        )

    client = OpaDetectionClient(
        base_url="http://opa:8181/",
        post=post,
        timeout_seconds=1.5,
    )

    findings = client.evaluate_event({"event_type": "network"})

    assert findings == [
        {
            "detection_id": "sentinel.python.large_outbound_upload",
            "title": "Large outbound upload",
            "severity": "medium",
            "message": "Outbound transfer exceeded 500000000 bytes",
            "metadata": {"bytes_out": 700_000_000},
        }
    ]
    assert calls == [
        (
            "http://opa:8181/v1/data/sentinel/detections/findings",
            {"input": {"event_type": "network"}},
            1.5,
        )
    ]


def test_opa_eval_fails_closed_on_sidecar_error():
    def post(_url, *, json, timeout):  # noqa: A002
        return _Response(503, {"error": "not ready"})

    client = OpaDetectionClient(base_url="http://opa:8181", post=post)

    try:
        client.evaluate_event({"event_type": "network"})
    except OpaRequestError as exc:
        assert "OPA detection eval failed with status 503" in str(exc)
    else:
        raise AssertionError("OPA sidecar errors must fail closed")


def test_opa_eval_fails_closed_on_transport_error():
    def post(_url, *, json, timeout):  # noqa: A002
        raise TimeoutError("sidecar timed out")

    client = OpaDetectionClient(base_url="http://opa:8181", post=post)

    try:
        client.evaluate_event({"event_type": "network"})
    except OpaRequestError as exc:
        assert "OPA detection eval request failed" in str(exc)
    else:
        raise AssertionError("OPA transport errors must fail closed")


def test_opa_eval_fails_closed_on_malformed_json():
    class MalformedResponse:
        status_code = 200
        text = "not-json"

        def json(self):
            raise ValueError("invalid json")

    def post(_url, *, json, timeout):  # noqa: A002
        return MalformedResponse()

    client = OpaDetectionClient(base_url="http://opa:8181", post=post)

    try:
        client.evaluate_event({"event_type": "network"})
    except OpaRequestError as exc:
        assert "OPA detection eval returned invalid JSON" in str(exc)
    else:
        raise AssertionError("OPA malformed responses must fail closed")


def test_rego_eval_matches_existing_python_detectors_for_seed_events():
    registry = load_registry(DETECTIONS)
    events = [
        {
            "event_type": "network",
            "network.direction": "outbound",
            "network.bytes_out": 700_000_000,
        },
        {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
        },
        {"event_type": "network", "network.direction": "inbound"},
        {"process_name": "bash", "command_line": "bash -lc id"},
    ]

    for event in events:
        python_ids = sorted(
            finding.detection_id
            for detector in registry.python_detectors.values()
            if (finding := detector.evaluate(event)) is not None
        )
        rego_ids = sorted(
            finding["detection_id"] for finding in evaluate_rego_parity(event)
        )
        assert rego_ids == python_ids


class _Response:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self.text = json.dumps(payload)
        self._payload = payload

    def json(self):
        return self._payload
