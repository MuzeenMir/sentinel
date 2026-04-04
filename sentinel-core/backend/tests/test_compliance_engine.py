"""
Comprehensive pytest unit tests for the SENTINEL Compliance Engine.

Covers all Flask routes: health, frameworks, framework details, assess,
gap-analysis, reports, report history, map-policy.
Redis and auth_middleware are mocked — no real Redis connection.
"""

import json
import os
import sys
import importlib.util
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fake Redis for Compliance Engine (lpush, ltrim, lrange, scan_iter)
# ---------------------------------------------------------------------------

_fake_lists: dict = {}   # key -> list  (for lpush/ltrim/lrange)
_fake_store: dict = {}   # key -> value (for setex/get)


class _FakeRedis:
    """In-memory Redis stand-in for compliance-engine tests."""

    def __init__(self, *args, **kwargs):
        pass

    # ── string ops ──────────────────────────────────────────────────
    def setex(self, key, ttl, value):
        _fake_store[key] = value

    def set(self, key, value, *args, **kwargs):
        _fake_store[key] = value

    def get(self, key):
        return _fake_store.get(key)

    # ── list ops ─────────────────────────────────────────────────────
    def lpush(self, key, *values):
        if key not in _fake_lists:
            _fake_lists[key] = []
        for v in reversed(values):
            _fake_lists[key].insert(0, v)

    def ltrim(self, key, start, end):
        if key in _fake_lists:
            _fake_lists[key] = _fake_lists[key][start : end + 1]

    def lrange(self, key, start, end):
        lst = _fake_lists.get(key, [])
        return lst[start : end + 1]

    def scan_iter(self, match="*"):
        """Yield keys matching pattern (prefix match for compliance:reports:*)."""
        prefix = match.replace("*", "")
        if prefix:
            for k in list(_fake_lists) + list(_fake_store):
                if k.startswith(prefix):
                    yield k
        else:
            for k in list(_fake_lists) + list(_fake_store):
                yield k


def _noop_auth(fn):
    """Pass-through replacement for require_auth."""
    return fn


# ---------------------------------------------------------------------------
# Patch Redis and auth_middleware BEFORE importing the compliance-engine app
# ---------------------------------------------------------------------------

_backend_root = os.path.join(os.path.dirname(__file__), "..")
_compliance_dir = os.path.join(_backend_root, "compliance-engine")

_fake_redis_instance = _FakeRedis()

sys.path.insert(0, _compliance_dir)
sys.path.insert(0, _backend_root)

with patch("redis.from_url", return_value=_fake_redis_instance), \
     patch.dict("sys.modules", {"auth_middleware": MagicMock(require_auth=_noop_auth)}):
    _spec = importlib.util.spec_from_file_location(
        "compliance_engine_app",
        os.path.join(_compliance_dir, "app.py"),
    )
    _ce_mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_ce_mod)

app = _ce_mod.app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_fake_redis():
    """Clear fake Redis state before each test."""
    _fake_lists.clear()
    _fake_store.clear()
    yield
    _fake_lists.clear()
    _fake_store.clear()


@pytest.fixture
def client():
    """Flask test client."""
    app.config["TESTING"] = True
    return app.test_client()


# ---------------------------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------------------------


def test_health_check_returns_200(client):
    """Health check endpoint returns 200 with status healthy."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "frameworks" in data
    assert set(data["frameworks"]) == {"GDPR", "HIPAA", "PCI-DSS", "NIST", "SOC2"}


def test_health_check_no_auth_required(client):
    """Health check does not require authentication."""
    resp = client.get("/health")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# List Frameworks Endpoint
# ---------------------------------------------------------------------------


def test_list_frameworks_returns_200(client):
    """List frameworks endpoint returns all available frameworks."""
    resp = client.get("/api/v1/frameworks")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "frameworks" in data
    frameworks = data["frameworks"]
    assert len(frameworks) == 5
    ids = {f["id"] for f in frameworks}
    assert ids == {"GDPR", "HIPAA", "PCI-DSS", "NIST", "SOC2"}
    for f in frameworks:
        assert "id" in f
        assert "name" in f
        assert "description" in f
        assert "control_count" in f
        assert isinstance(f["control_count"], int)


def test_list_frameworks_structure(client):
    """Each framework has required fields."""
    resp = client.get("/api/v1/frameworks")
    data = resp.get_json()
    for fw in data["frameworks"]:
        assert fw["id"] in ("GDPR", "HIPAA", "PCI-DSS", "NIST", "SOC2")
        assert len(fw["name"]) > 0
        assert len(fw["description"]) > 0
        assert fw["control_count"] >= 0


# ---------------------------------------------------------------------------
# Get Specific Framework Endpoint
# ---------------------------------------------------------------------------


def test_get_framework_nist_returns_200(client):
    """Get NIST framework details returns 200."""
    resp = client.get("/api/v1/frameworks/NIST")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == "NIST"
    assert "NIST" in data["name"]
    assert "controls" in data
    assert "categories" in data


def test_get_framework_gdpr_returns_200(client):
    """Get GDPR framework details returns 200."""
    resp = client.get("/api/v1/frameworks/GDPR")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == "GDPR"
    assert "controls" in data


def test_get_framework_case_insensitive(client):
    """Framework ID is case-insensitive."""
    resp = client.get("/api/v1/frameworks/nist")
    assert resp.status_code == 200
    assert resp.get_json()["id"] == "NIST"


def test_get_framework_not_found_returns_404(client):
    """Unknown framework returns 404."""
    resp = client.get("/api/v1/frameworks/UNKNOWN")
    assert resp.status_code == 404
    data = resp.get_json()
    assert "error" in data
    assert "not found" in data["error"].lower()


# ---------------------------------------------------------------------------
# Compliance Assessment Endpoint
# ---------------------------------------------------------------------------


def test_assess_compliance_returns_200(client):
    """Assess compliance endpoint returns assessment result."""
    resp = client.post(
        "/api/v1/assess",
        json={
            "framework": "NIST",
            "policies": [{"id": "p1", "action": "DENY"}],
            "configurations": {},
        },
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["framework"] == "NIST"
    assert "assessment_id" in data
    assert data["assessment_id"].startswith("assess_")
    assert "overall_score" in data
    assert data["overall_score"] >= 0
    assert data["overall_score"] <= 100
    assert data["status"] in ("compliant", "partially_compliant", "non_compliant")
    assert "control_assessments" in data
    assert "policy_mappings" in data
    assert "gaps" in data
    assert "recommendations" in data
    assert "timestamp" in data


def test_assess_compliance_default_framework(client):
    """Assess uses NIST when framework not specified."""
    resp = client.post(
        "/api/v1/assess",
        json={"policies": [], "configurations": {}},
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.get_json()["framework"] == "NIST"


def test_assess_compliance_unknown_framework_returns_400(client):
    """Assess with unknown framework returns 400."""
    resp = client.post(
        "/api/v1/assess",
        json={"framework": "INVALID", "policies": [], "configurations": {}},
        content_type="application/json",
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data
    assert "Unknown framework" in data["error"]


def test_assess_compliance_stores_in_redis(client):
    """Assessment is stored via reporter (uses fake Redis)."""
    client.post(
        "/api/v1/assess",
        json={"framework": "GDPR", "policies": [], "configurations": {}},
        content_type="application/json",
    )
    # Reporter stores to compliance:assessments:{framework}
    assert any("compliance:assessments" in k for k in _fake_lists)


# ---------------------------------------------------------------------------
# Gap Analysis Endpoint
# ---------------------------------------------------------------------------


def test_gap_analysis_returns_200(client):
    """Gap analysis endpoint returns gaps and remediation data."""
    resp = client.post(
        "/api/v1/gap-analysis",
        json={"framework": "NIST", "current_controls": {}},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["framework"] == "NIST"
    assert "gaps" in data
    assert "remediation_priority" in data
    assert "estimated_effort" in data
    assert "timestamp" in data


def test_gap_analysis_default_framework(client):
    """Gap analysis uses NIST when framework not specified."""
    resp = client.post(
        "/api/v1/gap-analysis",
        json={"current_controls": {}},
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.get_json()["framework"] == "NIST"


def test_gap_analysis_unknown_framework_returns_400(client):
    """Gap analysis with unknown framework returns 400."""
    resp = client.post(
        "/api/v1/gap-analysis",
        json={"framework": "INVALID", "current_controls": {}},
        content_type="application/json",
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data
    assert "Unknown framework" in data["error"]


# ---------------------------------------------------------------------------
# Report Generation Endpoint
# ---------------------------------------------------------------------------


def test_generate_report_returns_200(client):
    """Generate report endpoint returns report."""
    resp = client.post(
        "/api/v1/reports",
        json={"framework": "NIST", "type": "summary"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "report_id" in data
    assert data["report_id"].startswith("rpt_")
    assert data["framework"] == "NIST"
    assert data["type"] == "summary"
    assert "generated_at" in data
    assert "content" in data
    assert "executive_summary" in data["content"]
    assert "assessment_period" in data["content"]
    assert "sections" in data["content"]


def test_generate_report_with_date_range(client):
    """Generate report with date range."""
    resp = client.post(
        "/api/v1/reports",
        json={
            "framework": "HIPAA",
            "type": "detailed",
            "date_range": {"start": "2025-01-01", "end": "2025-03-13"},
        },
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["framework"] == "HIPAA"
    assert data["content"]["assessment_period"]["start"] == "2025-01-01"
    assert data["content"]["assessment_period"]["end"] == "2025-03-13"


def test_generate_report_default_params(client):
    """Generate report uses NIST and summary when not specified."""
    resp = client.post(
        "/api/v1/reports",
        json={},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["framework"] == "NIST"
    assert data["type"] == "summary"


# ---------------------------------------------------------------------------
# Report History Endpoint
# ---------------------------------------------------------------------------


def test_report_history_returns_200(client):
    """Report history endpoint returns list."""
    resp = client.get("/api/v1/reports/history")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "reports" in data
    assert isinstance(data["reports"], list)


def test_report_history_with_framework_filter(client):
    """Report history accepts framework query param."""
    resp = client.get("/api/v1/reports/history?framework=GDPR")
    assert resp.status_code == 200
    assert "reports" in resp.get_json()


def test_report_history_with_limit(client):
    """Report history accepts limit query param."""
    resp = client.get("/api/v1/reports/history?limit=5")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "reports" in data
    assert len(data["reports"]) <= 5


def test_report_history_after_generate(client):
    """Report history includes previously generated report."""
    # Generate a report first
    client.post(
        "/api/v1/reports",
        json={"framework": "NIST", "type": "summary"},
        content_type="application/json",
    )
    resp = client.get("/api/v1/reports/history?framework=NIST&limit=10")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["reports"]) >= 1
    report = data["reports"][0]
    assert report["framework"] == "NIST"
    assert "report_id" in report


# ---------------------------------------------------------------------------
# Policy Mapping Endpoint
# ---------------------------------------------------------------------------


def test_map_policy_returns_200(client):
    """Map policy endpoint returns mappings for each framework."""
    resp = client.post(
        "/api/v1/map-policy",
        json={"policy": {"id": "pol-1", "action": "DENY"}},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "policy_id" in data
    assert data["policy_id"] == "pol-1"
    assert "mappings" in data
    assert isinstance(data["mappings"], dict)


def test_map_policy_specific_frameworks(client):
    """Map policy to specific frameworks only."""
    resp = client.post(
        "/api/v1/map-policy",
        json={
            "policy": {"id": "pol-2"},
            "frameworks": ["NIST", "GDPR"],
        },
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    mappings = data["mappings"]
    assert "NIST" in mappings or "nist" in str(mappings).lower()
    assert "GDPR" in mappings or "gdpr" in str(mappings).lower()


def test_map_policy_mappings_structure(client):
    """Mappings contain policy_type and controls."""
    resp = client.post(
        "/api/v1/map-policy",
        json={"policy": {"id": "p1", "action": "DENY"}},
        content_type="application/json",
    )
    data = resp.get_json()
    for fw_id, mapping in data["mappings"].items():
        assert "policy_type" in mapping
        assert "controls" in mapping
        assert isinstance(mapping["controls"], list)


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------


def test_assess_compliance_error_handling(client):
    """Assess endpoint returns 500 on internal error."""
    with patch.object(_ce_mod.policy_mapper, "map_policies", side_effect=RuntimeError("boom")):
        resp = client.post(
            "/api/v1/assess",
            json={"framework": "NIST", "policies": [], "configurations": {}},
            content_type="application/json",
        )
    assert resp.status_code == 500
    data = resp.get_json()
    assert "error" in data
    assert "Assessment failed" in data["error"]


def test_gap_analysis_error_handling(client):
    """Gap analysis endpoint returns 500 on internal error."""
    with patch.object(_ce_mod.frameworks["NIST"], "detailed_gap_analysis", side_effect=ValueError("err")):
        resp = client.post(
            "/api/v1/gap-analysis",
            json={"framework": "NIST", "current_controls": {}},
            content_type="application/json",
        )
    assert resp.status_code == 500
    data = resp.get_json()
    assert "error" in data
    assert "Gap analysis failed" in data["error"]


def test_generate_report_error_handling(client):
    """Report generation returns 500 on internal error."""
    with patch.object(_ce_mod.reporter, "generate", side_effect=OSError("disk full")):
        resp = client.post(
            "/api/v1/reports",
            json={"framework": "NIST", "type": "summary"},
            content_type="application/json",
        )
    assert resp.status_code == 500
    data = resp.get_json()
    assert "error" in data
    assert "Report generation failed" in data["error"]


def test_map_policy_error_handling(client):
    """Policy mapping returns 500 on internal error."""
    with patch.object(_ce_mod.policy_mapper, "map_single_policy", side_effect=KeyError("bad")):
        resp = client.post(
            "/api/v1/map-policy",
            json={"policy": {"id": "p1"}, "frameworks": ["NIST"]},
            content_type="application/json",
        )
    assert resp.status_code == 500
    data = resp.get_json()
    assert "error" in data
    assert "Policy mapping failed" in data["error"]


def test_get_framework_details_error_on_empty_id(client):
    """Framework details with empty-ish path still routed; invalid returns 404."""
    resp = client.get("/api/v1/frameworks/")
    # Flask may return 404 for trailing slash or redirect
    assert resp.status_code in (404, 308, 301)


def test_report_history_invalid_limit(client):
    """Report history with invalid limit returns 500 or raises (no graceful handling)."""
    # App uses int(request.args.get('limit', 10)) - int('invalid') raises ValueError.
    # In testing mode Flask may propagate exceptions; otherwise returns 500.
    try:
        resp = client.get("/api/v1/reports/history?limit=invalid")
        assert resp.status_code == 500
    except ValueError:
        # Exception propagates when propagate_exceptions is True
        pass


def test_assess_compliance_malformed_json(client):
    """Assess with malformed JSON returns 400 (Flask default)."""
    resp = client.post(
        "/api/v1/assess",
        data="not json",
        content_type="application/json",
    )
    # Flask returns 400 for get_json() parsing failure
    assert resp.status_code in (400, 500)
