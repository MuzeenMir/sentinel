"""End-to-end validation: AI engine loads trained models and /api/v1/detect returns valid result."""
import os
import pytest
from pathlib import Path

# Ensure MODEL_PATH is set before app import (conftest sets it)
from app import app, initialize_models


@pytest.fixture(scope="module")
def client():
    """Flask test client with models initialized and auth header."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        success = initialize_models()
        assert success, "initialize_models() should succeed with trained_models"
        yield c


# Minimal traffic payload that feature extractors can handle
SAMPLE_TRAFFIC = {
    "src_ip": "192.168.1.10",
    "dst_ip": "10.0.0.5",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "tcp",
    "bytes_sent": 1500,
    "bytes_recv": 800,
    "packets_sent": 10,
    "packets_recv": 8,
    "duration_sec": 2.5,
}


def test_detect_returns_200_and_has_expected_fields(client):
    """POST /api/v1/detect with sample traffic returns 200 and result has is_threat, confidence."""
    r = client.post(
        "/api/v1/detect",
        json={"traffic_data": SAMPLE_TRAFFIC, "context": {}},
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200, r.get_json()
    data = r.get_json()
    assert "is_threat" in data
    assert "confidence" in data
    assert isinstance(data["is_threat"], bool)
    assert isinstance(data["confidence"], (int, float))


def test_models_status_shows_ensemble_loaded(client):
    """GET /api/v1/models/status shows ensemble and detectors ready."""
    r = client.get(
        "/api/v1/models/status",
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200, r.get_json()
    data = r.get_json()
    assert "ensemble" in data
    assert data.get("ensemble", {}).get("ready") is True
