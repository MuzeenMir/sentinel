"""
Comprehensive pytest tests for the SENTINEL Explainable AI (XAI) Service.

Covers every public endpoint and internal helper functions with all
external dependencies (Redis, SHAP, explainer modules) mocked out.
"""

import importlib.util
import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_tests_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.join(_tests_dir, "..")
_xai_dir = os.path.join(_backend_dir, "xai-service")
sys.path.insert(0, _xai_dir)
sys.path.insert(0, _backend_dir)

# ---------------------------------------------------------------------------
# Pre-import mocks — Redis and domain components are stubbed before the
# module-level code in app.py executes.
# ---------------------------------------------------------------------------


# Uses the real auth_middleware; _bypass_auth fixture patches per-test.
# Global sys.modules replacement removed to prevent leakage.

_mock_redis_client = MagicMock()
_redis_patcher = patch("redis.from_url", return_value=_mock_redis_client)
_redis_patcher.start()

_mock_shap_explainer = MagicMock()
_mock_shap_explainer.is_ready.return_value = True
_mock_shap_explainer.explain_detection.return_value = {
    "feature_importance": [
        {"feature": "byte_rate", "shap_value": 0.42, "direction": "increases_threat"},
        {"feature": "syn_ratio", "shap_value": 0.31, "direction": "increases_threat"},
    ],
    "top_factors": [
        {"feature": "byte_rate", "shap_value": 0.42, "direction": "increases_threat"},
    ],
    "method": "SHAP",
}

_mock_text_explainer = MagicMock()
_mock_text_explainer.explain_detection.return_value = {
    "summary": "High-confidence brute force detected.",
    "detailed": "Detailed detection report...",
    "threat_level": "high_threat",
    "key_factors": ["elevated byte rate"],
}
_mock_text_explainer.explain_policy_decision.return_value = {
    "summary": "Traffic blocked due to elevated threat indicators.",
    "reasoning": "High threat score indicates significant risk.",
    "basis": "Decision based on: High threat score: 0.95",
    "action": "DENY",
}

_mock_audit_trail = MagicMock()
_mock_audit_trail.record_explanation.return_value = True
_mock_audit_trail.get_trail.return_value = []
_mock_audit_trail.get_recent_trails.return_value = []
_mock_audit_trail.get_statistics.return_value = {
    "total_explanations": 150,
    "total_detection": 100,
    "total_policy": 50,
}

_mock_compliance_reporter = MagicMock()
_mock_compliance_reporter.generate.return_value = {
    "report_id": "report_20260313120000",
    "generated_at": datetime.utcnow().isoformat(),
    "framework": {"code": "GDPR", "name": "General Data Protection Regulation"},
    "summary": {"total_decisions": 3},
    "decisions_analyzed": 3,
    "compliance_assessment": {"status": "compliant", "score": 95},
    "recommendations": [],
    "detailed_findings": [],
}

with (
    patch("explainers.shap_explainer.SHAPExplainer", return_value=_mock_shap_explainer),
    patch("explainers.text_explainer.TextExplainer", return_value=_mock_text_explainer),
    patch("reports.audit_trail.AuditTrail", return_value=_mock_audit_trail),
    patch(
        "reports.compliance_report.ComplianceReportGenerator",
        return_value=_mock_compliance_reporter,
    ),
):
    _spec = importlib.util.spec_from_file_location(
        "sentinel_xai_app",
        os.path.join(_xai_dir, "app.py"),
        submodule_search_locations=[],
    )
    xai_app = importlib.util.module_from_spec(_spec)
    sys.modules["sentinel_xai_app"] = xai_app
    _spec.loader.exec_module(xai_app)

# Stop patcher so it doesn't leak into other test modules' sessions.
_redis_patcher.stop()


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture()
def mock_redis():
    _mock_redis_client.reset_mock(side_effect=True)
    _mock_redis_client.get.side_effect = None
    _mock_redis_client.get.return_value = None
    _mock_redis_client.hgetall.side_effect = None
    _mock_redis_client.hgetall.return_value = {}
    return _mock_redis_client


@pytest.fixture()
def shap_explainer():
    _mock_shap_explainer.reset_mock(side_effect=True)
    _mock_shap_explainer.is_ready.return_value = True
    _mock_shap_explainer.explain_detection.return_value = {
        "feature_importance": [
            {
                "feature": "byte_rate",
                "shap_value": 0.42,
                "direction": "increases_threat",
            },
            {
                "feature": "syn_ratio",
                "shap_value": 0.31,
                "direction": "increases_threat",
            },
        ],
        "top_factors": [
            {
                "feature": "byte_rate",
                "shap_value": 0.42,
                "direction": "increases_threat",
            },
        ],
        "method": "SHAP",
    }
    return _mock_shap_explainer


@pytest.fixture()
def text_explainer():
    _mock_text_explainer.reset_mock(side_effect=True)
    _mock_text_explainer.explain_detection.return_value = {
        "summary": "High-confidence brute force detected.",
        "detailed": "Detailed detection report...",
        "threat_level": "high_threat",
        "key_factors": ["elevated byte rate"],
    }
    _mock_text_explainer.explain_policy_decision.return_value = {
        "summary": "Traffic blocked due to elevated threat indicators.",
        "reasoning": "High threat score indicates significant risk.",
        "basis": "Decision based on: High threat score: 0.95",
        "action": "DENY",
    }
    return _mock_text_explainer


@pytest.fixture()
def audit_trail():
    _mock_audit_trail.reset_mock(side_effect=True)
    _mock_audit_trail.record_explanation.return_value = True
    _mock_audit_trail.get_trail.return_value = []
    _mock_audit_trail.get_recent_trails.return_value = []
    _mock_audit_trail.get_statistics.return_value = {
        "total_explanations": 150,
        "total_detection": 100,
        "total_policy": 50,
    }
    return _mock_audit_trail


@pytest.fixture()
def compliance_reporter():
    _mock_compliance_reporter.reset_mock(side_effect=True)
    _mock_compliance_reporter.generate.return_value = {
        "report_id": "report_20260313120000",
        "generated_at": datetime.utcnow().isoformat(),
        "framework": {"code": "GDPR", "name": "General Data Protection Regulation"},
        "summary": {"total_decisions": 3},
        "decisions_analyzed": 3,
        "compliance_assessment": {"status": "compliant", "score": 95},
        "recommendations": [],
        "detailed_findings": [],
    }
    return _mock_compliance_reporter


@pytest.fixture(autouse=True)
def _bypass_auth():
    with patch("auth_middleware._verify_token") as mock_verify:
        mock_verify.return_value = {
            "user_id": "test-user-1",
            "username": "test_admin",
            "role": "admin",
            "email": "admin@sentinel.test",
        }
        yield mock_verify


@pytest.fixture()
def auth_headers():
    return {
        "Authorization": "Bearer test-valid-token",
        "Content-Type": "application/json",
    }


@pytest.fixture()
def client(
    mock_redis, shap_explainer, text_explainer, audit_trail, compliance_reporter
):
    xai_app.app.config["TESTING"] = True
    with xai_app.app.test_client() as c:
        yield c


@pytest.fixture()
def bare_client(mock_redis):
    xai_app.app.config["TESTING"] = True
    with xai_app.app.test_client() as c:
        yield c


# ===================================================================
# Health check — GET /health
# ===================================================================


class TestHealthCheck:
    def test_returns_200_with_healthy_status(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"

    def test_includes_timestamp(self, client):
        resp = client.get("/health")
        data = resp.get_json()
        assert "timestamp" in data
        datetime.fromisoformat(data["timestamp"])

    def test_includes_component_readiness(self, client, shap_explainer):
        resp = client.get("/health")
        data = resp.get_json()
        assert "components" in data
        assert data["components"]["shap_explainer"] is True
        assert data["components"]["text_explainer"] is True
        assert data["components"]["audit_trail"] is True

    def test_reflects_shap_not_ready(self, client, shap_explainer):
        shap_explainer.is_ready.return_value = False
        resp = client.get("/health")
        data = resp.get_json()
        assert data["components"]["shap_explainer"] is False

    def test_does_not_require_auth(self, bare_client):
        with patch("auth_middleware._verify_token", return_value=None):
            resp = bare_client.get("/health")
            assert resp.status_code == 200


# ===================================================================
# Explain detection — POST /api/v1/explain/detection
# ===================================================================


class TestExplainDetection:
    @staticmethod
    def _payload(**overrides):
        base = {
            "detection_id": "det_test_001",
            "features": {
                "network": {"byte_rate": 5000.0, "syn_ratio": 0.85},
                "geo_risk": 0.7,
            },
            "prediction": {
                "is_threat": True,
                "confidence": 0.92,
                "threat_type": "brute_force",
            },
            "model_verdicts": {
                "xgboost": {"is_threat": True, "confidence": 0.95},
                "lstm": {"is_threat": True, "confidence": 0.88},
            },
        }
        base.update(overrides)
        return base

    def test_successful_explanation(
        self, client, auth_headers, shap_explainer, text_explainer
    ):
        resp = client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=self._payload()
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["detection_id"] == "det_test_001"
        assert "summary" in data
        assert "feature_contributions" in data
        assert "top_factors" in data
        assert "provenance" in data

    def test_calls_shap_and_text_explainers(
        self, client, auth_headers, shap_explainer, text_explainer
    ):
        client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=self._payload()
        )
        shap_explainer.explain_detection.assert_called_once()
        text_explainer.explain_detection.assert_called_once()

    def test_records_audit_trail(self, client, auth_headers, audit_trail):
        client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=self._payload()
        )
        audit_trail.record_explanation.assert_called_once()
        call_args = audit_trail.record_explanation.call_args
        assert call_args[0][0] == "detection"
        assert call_args[0][1] == "det_test_001"

    def test_includes_model_contributions(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=self._payload()
        )
        data = resp.get_json()
        contributions = data["model_contributions"]
        assert len(contributions) == 2
        models = {c["model"] for c in contributions}
        assert models == {"xgboost", "lstm"}

    def test_includes_confidence_breakdown(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=self._payload()
        )
        data = resp.get_json()
        breakdown = data["confidence_breakdown"]
        assert breakdown["overall"] == 0.92
        assert breakdown["threshold_comparison"]["high_confidence"] is True

    def test_includes_provenance(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=self._payload()
        )
        data = resp.get_json()
        provenance = data["provenance"]
        assert set(provenance["models_used"]) == {"xgboost", "lstm"}
        assert provenance["explanation_method"] == "SHAP + NLG"

    def test_includes_timestamp(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=self._payload()
        )
        data = resp.get_json()
        assert "timestamp" in data
        datetime.fromisoformat(data["timestamp"])

    def test_null_body_returns_400(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/detection",
            headers=auth_headers,
            data=b"null",
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_malformed_body_returns_500(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/detection",
            headers=auth_headers,
            data="",
            content_type="application/json",
        )
        assert resp.status_code == 500

    def test_defaults_detection_id_to_unknown(self, client, auth_headers):
        payload = self._payload()
        del payload["detection_id"]
        resp = client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=payload
        )
        assert resp.status_code == 200
        assert resp.get_json()["detection_id"] == "unknown"

    def test_empty_features_still_succeeds(self, client, auth_headers):
        payload = self._payload(features={}, model_verdicts={})
        resp = client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=payload
        )
        assert resp.status_code == 200

    def test_shap_failure_returns_500(self, client, auth_headers, shap_explainer):
        shap_explainer.explain_detection.side_effect = RuntimeError("SHAP crash")
        resp = client.post(
            "/api/v1/explain/detection", headers=auth_headers, json=self._payload()
        )
        assert resp.status_code == 500
        assert "Failed to generate explanation" in resp.get_json()["error"]

    def test_requires_auth(self, bare_client):
        resp = bare_client.post("/api/v1/explain/detection", json=self._payload())
        assert resp.status_code == 401


# ===================================================================
# Explain policy — POST /api/v1/explain/policy
# ===================================================================


class TestExplainPolicy:
    @staticmethod
    def _payload(**overrides):
        base = {
            "decision_id": "drl_test_001",
            "action": "DENY",
            "state_features": {
                "threat_score": 0.95,
                "asset_criticality": 0.8,
                "src_reputation": 0.2,
                "time_risk": 0.6,
                "geo_risk": 0.7,
                "source_ip": "10.0.0.99",
            },
            "confidence": 0.92,
        }
        base.update(overrides)
        return base

    def test_successful_policy_explanation(self, client, auth_headers, text_explainer):
        resp = client.post(
            "/api/v1/explain/policy", headers=auth_headers, json=self._payload()
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["decision_id"] == "drl_test_001"
        assert data["action"] == "DENY"
        assert data["confidence"] == 0.92
        assert "summary" in data
        assert "reasoning" in data
        assert "key_factors" in data

    def test_calls_text_explainer(self, client, auth_headers, text_explainer):
        client.post(
            "/api/v1/explain/policy", headers=auth_headers, json=self._payload()
        )
        text_explainer.explain_policy_decision.assert_called_once_with(
            "DENY",
            self._payload()["state_features"],
            0.92,
        )

    def test_records_audit_trail(self, client, auth_headers, audit_trail):
        client.post(
            "/api/v1/explain/policy", headers=auth_headers, json=self._payload()
        )
        audit_trail.record_explanation.assert_called_once()
        call_args = audit_trail.record_explanation.call_args
        assert call_args[0][0] == "policy"
        assert call_args[0][1] == "drl_test_001"

    def test_key_factors_limited_to_five(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/policy", headers=auth_headers, json=self._payload()
        )
        data = resp.get_json()
        assert len(data["key_factors"]) <= 5

    def test_deny_action_includes_alternatives(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/policy", headers=auth_headers, json=self._payload()
        )
        data = resp.get_json()
        alt_actions = {a["action"] for a in data["alternative_actions"]}
        assert "RATE_LIMIT" in alt_actions
        assert "MONITOR" in alt_actions

    def test_allow_action_with_high_threat_suggests_monitor(self, client, auth_headers):
        payload = self._payload(action="ALLOW")
        payload["state_features"]["threat_score"] = 0.5
        resp = client.post("/api/v1/explain/policy", headers=auth_headers, json=payload)
        data = resp.get_json()
        alt_actions = {a["action"] for a in data["alternative_actions"]}
        assert "MONITOR" in alt_actions

    def test_allow_action_low_threat_no_alternatives(self, client, auth_headers):
        payload = self._payload(action="ALLOW")
        payload["state_features"]["threat_score"] = 0.1
        resp = client.post("/api/v1/explain/policy", headers=auth_headers, json=payload)
        data = resp.get_json()
        assert data["alternative_actions"] == []

    def test_monitor_action_high_threat_suggests_rate_limit(self, client, auth_headers):
        payload = self._payload(action="MONITOR")
        payload["state_features"]["threat_score"] = 0.8
        resp = client.post("/api/v1/explain/policy", headers=auth_headers, json=payload)
        data = resp.get_json()
        alt_actions = {a["action"] for a in data["alternative_actions"]}
        assert "RATE_LIMIT" in alt_actions

    def test_null_body_returns_400(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/policy",
            headers=auth_headers,
            data=b"null",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_malformed_body_returns_500(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/policy",
            headers=auth_headers,
            data="",
            content_type="application/json",
        )
        assert resp.status_code == 500

    def test_defaults_action_to_monitor(self, client, auth_headers):
        payload = self._payload()
        del payload["action"]
        resp = client.post("/api/v1/explain/policy", headers=auth_headers, json=payload)
        assert resp.status_code == 200
        assert resp.get_json()["action"] == "MONITOR"

    def test_text_explainer_failure_returns_500(
        self, client, auth_headers, text_explainer
    ):
        text_explainer.explain_policy_decision.side_effect = RuntimeError("NLG failed")
        resp = client.post(
            "/api/v1/explain/policy", headers=auth_headers, json=self._payload()
        )
        assert resp.status_code == 500

    def test_includes_recommendation_basis(self, client, auth_headers):
        resp = client.post(
            "/api/v1/explain/policy", headers=auth_headers, json=self._payload()
        )
        data = resp.get_json()
        assert "recommendation_basis" in data

    def test_requires_auth(self, bare_client):
        resp = bare_client.post("/api/v1/explain/policy", json=self._payload())
        assert resp.status_code == 401


# ===================================================================
# Audit trail — GET /api/v1/audit-trail
# ===================================================================


class TestAuditTrail:
    def test_get_trail_by_id(self, client, auth_headers, audit_trail):
        trail_record = {
            "entity_type": "detection",
            "entity_id": "det_001",
            "timestamp": datetime.utcnow().isoformat(),
            "data": {"summary": "test"},
        }
        audit_trail.get_trail.return_value = [trail_record]

        resp = client.get(
            "/api/v1/audit-trail?type=detection&id=det_001", headers=auth_headers
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1
        assert data["trails"][0]["entity_id"] == "det_001"

    def test_get_trail_calls_get_trail_with_params(
        self, client, auth_headers, audit_trail
    ):
        client.get(
            "/api/v1/audit-trail?type=detection&id=det_001", headers=auth_headers
        )
        audit_trail.get_trail.assert_called_once_with("detection", "det_001")

    def test_get_recent_trails_without_id(self, client, auth_headers, audit_trail):
        audit_trail.get_recent_trails.return_value = [
            {"entity_type": "detection", "entity_id": "det_recent_1"},
            {"entity_type": "policy", "entity_id": "drl_recent_1"},
        ]
        resp = client.get("/api/v1/audit-trail?type=detection", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 2
        audit_trail.get_recent_trails.assert_called_once_with("detection", 100)

    def test_default_limit_is_100(self, client, auth_headers, audit_trail):
        client.get("/api/v1/audit-trail", headers=auth_headers)
        audit_trail.get_recent_trails.assert_called_once_with(None, 100)

    def test_custom_limit(self, client, auth_headers, audit_trail):
        client.get("/api/v1/audit-trail?limit=25", headers=auth_headers)
        audit_trail.get_recent_trails.assert_called_once_with(None, 25)

    def test_empty_trail_returns_zero_total(self, client, auth_headers, audit_trail):
        audit_trail.get_recent_trails.return_value = []
        resp = client.get("/api/v1/audit-trail", headers=auth_headers)
        data = resp.get_json()
        assert data["total"] == 0
        assert data["trails"] == []

    def test_audit_trail_error_returns_500(self, client, auth_headers, audit_trail):
        audit_trail.get_recent_trails.side_effect = RuntimeError("Redis down")
        resp = client.get("/api/v1/audit-trail", headers=auth_headers)
        assert resp.status_code == 500
        assert "Failed to retrieve audit trail" in resp.get_json()["error"]

    def test_requires_auth(self, bare_client):
        resp = bare_client.get("/api/v1/audit-trail")
        assert resp.status_code == 401


# ===================================================================
# Compliance report — POST /api/v1/report/compliance
# ===================================================================


class TestComplianceReport:
    @staticmethod
    def _payload(**overrides):
        base = {
            "detection_ids": ["det_001", "det_002"],
            "decision_ids": ["drl_001"],
            "framework": "GDPR",
            "date_range": {"start": "2026-03-01", "end": "2026-03-13"},
        }
        base.update(overrides)
        return base

    def test_successful_report_generation(
        self, client, auth_headers, compliance_reporter
    ):
        resp = client.post(
            "/api/v1/report/compliance", headers=auth_headers, json=self._payload()
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "report_id" in data
        assert "framework" in data
        assert "compliance_assessment" in data

    def test_gathers_trails_for_all_ids(self, client, auth_headers, audit_trail):
        trail_det = {"entity_type": "detection", "entity_id": "det_001"}
        trail_drl = {"entity_type": "policy", "entity_id": "drl_001"}
        audit_trail.get_trail.side_effect = lambda t, eid: {
            ("detection", "det_001"): [trail_det],
            ("detection", "det_002"): [],
            ("policy", "drl_001"): [trail_drl],
        }.get((t, eid), [])

        client.post(
            "/api/v1/report/compliance", headers=auth_headers, json=self._payload()
        )

        assert audit_trail.get_trail.call_count == 3

    def test_passes_framework_to_generator(
        self, client, auth_headers, audit_trail, compliance_reporter
    ):
        client.post(
            "/api/v1/report/compliance", headers=auth_headers, json=self._payload()
        )
        call_kwargs = compliance_reporter.generate.call_args[1]
        assert call_kwargs["framework"] == "GDPR"

    def test_passes_date_range_to_generator(
        self, client, auth_headers, audit_trail, compliance_reporter
    ):
        client.post(
            "/api/v1/report/compliance", headers=auth_headers, json=self._payload()
        )
        call_kwargs = compliance_reporter.generate.call_args[1]
        assert call_kwargs["date_range"] == {"start": "2026-03-01", "end": "2026-03-13"}

    def test_empty_ids_generates_empty_report(
        self, client, auth_headers, compliance_reporter
    ):
        payload = self._payload(detection_ids=[], decision_ids=[])
        resp = client.post(
            "/api/v1/report/compliance", headers=auth_headers, json=payload
        )
        assert resp.status_code == 200
        call_args = compliance_reporter.generate.call_args[0]
        assert call_args[0] == []

    def test_defaults_framework_to_general(
        self, client, auth_headers, compliance_reporter
    ):
        payload = self._payload()
        del payload["framework"]
        client.post("/api/v1/report/compliance", headers=auth_headers, json=payload)
        call_kwargs = compliance_reporter.generate.call_args[1]
        assert call_kwargs["framework"] == "general"

    def test_generator_failure_returns_500(
        self, client, auth_headers, compliance_reporter
    ):
        compliance_reporter.generate.side_effect = RuntimeError("report crash")
        resp = client.post(
            "/api/v1/report/compliance", headers=auth_headers, json=self._payload()
        )
        assert resp.status_code == 500
        assert "Failed to generate report" in resp.get_json()["error"]

    def test_requires_auth(self, bare_client):
        resp = bare_client.post("/api/v1/report/compliance", json=self._payload())
        assert resp.status_code == 401


# ===================================================================
# Statistics — GET /api/v1/statistics
# ===================================================================


class TestStatistics:
    def test_returns_statistics(self, client, auth_headers, audit_trail):
        resp = client.get("/api/v1/statistics", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_explanations"] == 150
        assert data["total_detection"] == 100
        assert data["total_policy"] == 50

    def test_empty_statistics(self, client, auth_headers, audit_trail):
        audit_trail.get_statistics.return_value = {}
        resp = client.get("/api/v1/statistics", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json() == {}

    def test_statistics_failure_returns_500(self, client, auth_headers, audit_trail):
        audit_trail.get_statistics.side_effect = RuntimeError("stats error")
        resp = client.get("/api/v1/statistics", headers=auth_headers)
        assert resp.status_code == 500
        assert "Failed to get statistics" in resp.get_json()["error"]

    def test_requires_auth(self, bare_client):
        resp = bare_client.get("/api/v1/statistics")
        assert resp.status_code == 401


# ===================================================================
# Helper function unit tests
# ===================================================================


class TestExplainModelVerdicts:
    def test_multiple_model_verdicts(self):
        verdicts = {
            "xgboost": {"is_threat": True, "confidence": 0.95},
            "lstm": {"is_threat": False, "confidence": 0.85},
        }
        result = xai_app._explain_model_verdicts(verdicts)
        assert len(result) == 2

        xgb = next(r for r in result if r["model"] == "xgboost")
        assert xgb["verdict"] == "threat"
        assert xgb["contribution"] == "positive"
        assert xgb["confidence"] == 0.95

        lstm = next(r for r in result if r["model"] == "lstm")
        assert lstm["verdict"] == "benign"
        assert lstm["contribution"] == "negative"

    def test_empty_verdicts(self):
        assert xai_app._explain_model_verdicts({}) == []

    def test_known_model_weights(self):
        verdicts = {"xgboost": {"is_threat": True, "confidence": 0.9}}
        result = xai_app._explain_model_verdicts(verdicts)
        assert result[0]["weight"] == 0.35

    def test_unknown_model_gets_default_weight(self):
        verdicts = {"custom_model": {"is_threat": True, "confidence": 0.8}}
        result = xai_app._explain_model_verdicts(verdicts)
        assert result[0]["weight"] == 0.25


class TestGetModelWeight:
    def test_known_models(self):
        assert xai_app._get_model_weight("xgboost") == 0.35
        assert xai_app._get_model_weight("lstm") == 0.25
        assert xai_app._get_model_weight("isolation_forest") == 0.20
        assert xai_app._get_model_weight("autoencoder") == 0.20

    def test_case_insensitive(self):
        assert xai_app._get_model_weight("XGBoost") == 0.35
        assert xai_app._get_model_weight("LSTM") == 0.25

    def test_unknown_returns_default(self):
        assert xai_app._get_model_weight("unknown_model") == 0.25


class TestGetConfidenceBreakdown:
    def test_high_confidence(self):
        result = xai_app._get_confidence_breakdown({"confidence": 0.95})
        assert result["overall"] == 0.95
        assert result["threshold_comparison"]["high_confidence"] is True
        assert result["threshold_comparison"]["medium_confidence"] is False
        assert result["threshold_comparison"]["low_confidence"] is False

    def test_medium_confidence(self):
        result = xai_app._get_confidence_breakdown({"confidence": 0.80})
        assert result["threshold_comparison"]["high_confidence"] is False
        assert result["threshold_comparison"]["medium_confidence"] is True

    def test_low_confidence(self):
        result = xai_app._get_confidence_breakdown({"confidence": 0.50})
        assert result["threshold_comparison"]["low_confidence"] is True
        assert result["threshold_comparison"]["high_confidence"] is False
        assert result["threshold_comparison"]["medium_confidence"] is False

    def test_missing_confidence_defaults_to_zero(self):
        result = xai_app._get_confidence_breakdown({})
        assert result["overall"] == 0.0
        assert result["threshold_comparison"]["low_confidence"] is True


class TestInterpretConfidence:
    def test_very_high(self):
        assert "Very high" in xai_app._interpret_confidence(0.97)

    def test_high(self):
        assert "High confidence" in xai_app._interpret_confidence(0.88)

    def test_moderate(self):
        assert "Moderate" in xai_app._interpret_confidence(0.72)

    def test_low(self):
        assert "Low confidence" in xai_app._interpret_confidence(0.55)

    def test_very_low(self):
        assert "Very low" in xai_app._interpret_confidence(0.30)

    def test_boundary_values(self):
        assert "Very high" in xai_app._interpret_confidence(0.95)
        assert "High" in xai_app._interpret_confidence(0.85)
        assert "Moderate" in xai_app._interpret_confidence(0.70)
        assert "Low" in xai_app._interpret_confidence(0.50)
        assert "Very low" in xai_app._interpret_confidence(0.49)


class TestCalculatePolicyFeatureImportance:
    def test_returns_sorted_by_contribution(self):
        features = {
            "threat_score": 0.9,
            "asset_criticality": 0.8,
            "src_reputation": 0.3,
        }
        result = xai_app._calculate_policy_feature_importance(features, "DENY")
        contributions = [r["contribution"] for r in result]
        assert contributions == sorted(contributions, reverse=True)

    def test_known_features_have_correct_weights(self):
        features = {"threat_score": 1.0}
        result = xai_app._calculate_policy_feature_importance(features, "DENY")
        threat_entry = next(r for r in result if r["feature"] == "threat_score")
        assert threat_entry["weight"] == 0.3
        assert threat_entry["contribution"] == pytest.approx(0.3)

    def test_missing_features_default_to_zero(self):
        result = xai_app._calculate_policy_feature_importance({}, "DENY")
        for entry in result:
            assert entry["value"] == 0
            assert entry["contribution"] == 0

    def test_direction_flag(self):
        features = {"threat_score": 0.9, "src_reputation": 0.01}
        result = xai_app._calculate_policy_feature_importance(features, "DENY")
        threat_entry = next(r for r in result if r["feature"] == "threat_score")
        assert threat_entry["direction"] == "supports_action"

        low_entry = next(r for r in result if r["feature"] == "src_reputation")
        assert low_entry["direction"] == "neutral"

    def test_non_numeric_features_contribute_zero(self):
        features = {"threat_score": "high"}
        result = xai_app._calculate_policy_feature_importance(features, "DENY")
        threat_entry = next(r for r in result if r["feature"] == "threat_score")
        assert threat_entry["contribution"] == 0


class TestGetAlternativeActions:
    def test_deny_suggests_rate_limit_and_monitor(self):
        alts = xai_app._get_alternative_actions("DENY", {"threat_score": 0.9})
        actions = {a["action"] for a in alts}
        assert "RATE_LIMIT" in actions
        assert "MONITOR" in actions

    def test_allow_with_elevated_threat_suggests_monitor(self):
        alts = xai_app._get_alternative_actions("ALLOW", {"threat_score": 0.5})
        assert any(a["action"] == "MONITOR" for a in alts)

    def test_allow_with_low_threat_no_alternatives(self):
        alts = xai_app._get_alternative_actions("ALLOW", {"threat_score": 0.1})
        assert alts == []

    def test_monitor_with_high_threat_suggests_rate_limit(self):
        alts = xai_app._get_alternative_actions("MONITOR", {"threat_score": 0.8})
        assert any(a["action"] == "RATE_LIMIT" for a in alts)

    def test_monitor_with_low_threat_no_alternatives(self):
        alts = xai_app._get_alternative_actions("MONITOR", {"threat_score": 0.3})
        assert alts == []

    def test_unknown_action_returns_empty(self):
        alts = xai_app._get_alternative_actions("CUSTOM", {"threat_score": 0.9})
        assert alts == []
