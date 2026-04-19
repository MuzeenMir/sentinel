"""
Comprehensive pytest tests for the SENTINEL AI Detection Engine.

Covers every public endpoint and the ensemble scoring logic with all
external dependencies (Redis, Kafka, model files) mocked out.
"""

import os
import sys
import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
import numpy as np

# ---------------------------------------------------------------------------
# Path setup – add service dirs before the app module is imported
# ---------------------------------------------------------------------------
_tests_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.join(_tests_dir, "..")
_ai_engine_dir = os.path.join(_backend_dir, "ai-engine")
sys.path.insert(0, _ai_engine_dir)
sys.path.insert(0, _backend_dir)

# ---------------------------------------------------------------------------
# Pre-import mocks.
#
# Several detector modules (LSTM, Autoencoder) define classes that inherit
# from ``torch.nn.Module`` at the module level.  When PyTorch is absent the
# import would fail.  We install a lightweight *real-class* stub (not
# MagicMock) so ``class Foo(nn.Module)`` succeeds and scipy/sklearn are not
# confused by ``issubclass()`` calls.  Redis is patched before the app's
# module-level ``redis.from_url()`` executes.
# ---------------------------------------------------------------------------
import types as _types

_TORCH_IS_REAL = False


def _install_torch_stub():
    """Inject a minimal torch stub into sys.modules when torch is absent."""
    global _TORCH_IS_REAL
    try:
        import torch

        torch.zeros(1)
        _TORCH_IS_REAL = True
        return
    except Exception:
        pass

    # --- torch.nn ---
    class _Module:
        def __init_subclass__(cls, **kw):
            super().__init_subclass__(**kw)

        def __init__(self, *a, **kw):
            pass

        def parameters(self):
            return []

        def to(self, *a, **kw):
            return self

        def eval(self):
            return self

        def train(self, mode=True):
            return self

        def state_dict(self):
            return {}

        def load_state_dict(self, d, **kw):
            pass

    class _Tensor:
        pass

    _nn = _types.ModuleType("torch.nn")
    _nn.Module = _Module
    _nn.Sequential = lambda *a: _Module()
    _nn.Linear = lambda *a, **kw: _Module()
    _nn.ReLU = lambda *a, **kw: _Module()
    _nn.Softmax = lambda *a, **kw: _Module()
    _nn.LSTM = lambda *a, **kw: _Module()
    _nn.MSELoss = lambda: (
        lambda x, y: type(
            "L", (), {"item": lambda s: 0.0, "backward": lambda s: None}
        )()
    )
    _nn_utils = _types.ModuleType("torch.nn.utils")
    _nn_utils.clip_grad_norm_ = lambda *a, **kw: None
    _nn.utils = _nn_utils

    _optim = _types.ModuleType("torch.optim")
    _optim.Adam = lambda *a, **kw: type(
        "O", (), {"zero_grad": lambda s: None, "step": lambda s: None}
    )()

    _dist = _types.ModuleType("torch.distributions")
    _dist.Categorical = lambda *a, **kw: None

    _data = _types.ModuleType("torch.utils.data")
    _data.DataLoader = lambda *a, **kw: iter([])
    _data.TensorDataset = lambda *a, **kw: None
    _utils = _types.ModuleType("torch.utils")
    _utils.data = _data

    _cuda = _types.ModuleType("torch.cuda")
    _cuda.is_available = lambda: False

    _torch = _types.ModuleType("torch")
    _torch.Tensor = _Tensor
    _torch.nn = _nn
    _torch.optim = _optim
    _torch.distributions = _dist
    _torch.utils = _utils
    _torch.cuda = _cuda
    _torch.device = lambda x: x
    _torch.FloatTensor = lambda *a: None
    _torch.LongTensor = lambda *a: None
    _torch.save = lambda *a, **kw: None
    _torch.load = lambda *a, **kw: {}
    _torch.no_grad = lambda: type(
        "C", (), {"__enter__": lambda s: None, "__exit__": lambda s, *a: None}
    )()
    _torch.exp = lambda x: x
    _torch.clamp = lambda *a, **kw: None
    _torch.min = lambda *a: (None,)

    for name, mod in [
        ("torch", _torch),
        ("torch.nn", _nn),
        ("torch.nn.utils", _nn_utils),
        ("torch.optim", _optim),
        ("torch.distributions", _dist),
        ("torch.utils", _utils),
        ("torch.utils.data", _data),
        ("torch.cuda", _cuda),
    ]:
        sys.modules.setdefault(name, mod)


_install_torch_stub()

# Use the real auth_middleware; the _bypass_auth autouse fixture below
# patches _verify_token per-test to return a fake admin user. Previously
# this module replaced sys.modules["auth_middleware"] with a stub, which
# leaked into other test modules (hardening-service, hids-agent) that
# capture require_auth at import time → spurious 401 responses.

_mock_redis_client = MagicMock()
_redis_patcher = patch("redis.from_url", return_value=_mock_redis_client)
_redis_patcher.start()

# Use a unique module name so running alongside test_drl_engine doesn't clash.
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "sentinel_ai_engine_app",
    os.path.join(_ai_engine_dir, "app.py"),
    submodule_search_locations=[],
)
ai_app = _ilu.module_from_spec(_spec)
sys.modules["sentinel_ai_engine_app"] = ai_app
_spec.loader.exec_module(ai_app)

# Stop the patcher now that the app has captured its redis_client;
# leaving it active across the full pytest session overrides other
# test modules' redis patches and causes cross-file pollution.
_redis_patcher.stop()

import redis as _redis_mod  # noqa: E402


# ===================================================================
# Helpers
# ===================================================================


def _make_detector(*, ready=True, version="1.0.0"):
    """Return a MagicMock that satisfies the BaseDetector interface."""
    det = MagicMock()
    det.is_ready.return_value = ready
    det.get_version.return_value = version
    det.get_metrics.return_value = {"accuracy": 0.95, "f1": 0.93}
    det.get_last_updated.return_value = datetime.utcnow().isoformat()
    det.predict.return_value = {
        "is_threat": True,
        "confidence": 0.92,
        "threat_type": "brute_force",
        "details": {},
    }
    det.predict_batch.return_value = [det.predict.return_value]
    return det


_THREAT_RESULT = {
    "detection_id": "det_20260313120000_abc12345",
    "is_threat": True,
    "confidence": 0.91,
    "threat_score": 0.91,
    "threat_type": "brute_force",
    "timestamp": datetime.utcnow().isoformat(),
    "model_verdicts": {"xgboost": {"is_threat": True, "confidence": 0.92}},
    "latency_ms": 12.5,
}

_BENIGN_RESULT = {
    "detection_id": "det_20260313120001_def67890",
    "is_threat": False,
    "confidence": 0.15,
    "threat_score": 0.15,
    "threat_type": "benign",
    "timestamp": datetime.utcnow().isoformat(),
    "model_verdicts": {},
    "latency_ms": 8.0,
}


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture()
def mock_redis():
    """Reset and return the pre-created Redis mock."""
    _mock_redis_client.reset_mock(side_effect=True)
    _mock_redis_client.get.side_effect = None
    _mock_redis_client.get.return_value = None
    _mock_redis_client.keys.side_effect = None
    _mock_redis_client.keys.return_value = []
    _mock_redis_client.incr.side_effect = None
    _mock_redis_client.incr.return_value = 1
    return _mock_redis_client


@pytest.fixture(autouse=True)
def _bypass_auth():
    """Bypass JWT verification for every test."""
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
def mock_detectors():
    """Inject four mocked detectors into the app module."""
    detectors = {
        "xgboost": _make_detector(),
        "lstm": _make_detector(),
        "isolation_forest": _make_detector(),
        "autoencoder": _make_detector(),
    }
    original = ai_app.detectors
    ai_app.detectors = detectors
    yield detectors
    ai_app.detectors = original


@pytest.fixture()
def mock_ensemble():
    """Inject a mocked ensemble into the app module."""
    ens = MagicMock()
    ens.is_ready.return_value = True
    ens.predict.return_value = dict(_THREAT_RESULT)
    ens.predict_batch.return_value = [dict(_THREAT_RESULT)]
    original = ai_app.ensemble
    ai_app.ensemble = ens
    yield ens
    ai_app.ensemble = original


@pytest.fixture()
def mock_prediction_service():
    """Inject a mocked PredictionService into the app module."""
    svc = MagicMock()
    svc.predict.return_value = dict(_THREAT_RESULT)
    svc.predict_batch.return_value = [
        {
            "detection_id": f"det_batch_{i}",
            "is_threat": i % 2 == 0,
            "confidence": 0.8 + 0.05 * i,
            "threat_type": "port_scan" if i % 2 == 0 else "benign",
        }
        for i in range(3)
    ]
    original = ai_app.prediction_service
    ai_app.prediction_service = svc
    yield svc
    ai_app.prediction_service = original


@pytest.fixture()
def mock_feature_extractors():
    """Replace module-level feature extractors with lightweight mocks."""
    extractors = {}
    for name in ("statistical", "behavioral", "contextual"):
        ext = MagicMock()
        ext.extract.return_value = {"feat_a": 0.1, "feat_b": 0.5}
        ext.get_feature_names.return_value = ["feat_a", "feat_b"]
        extractors[name] = ext
    original = ai_app.feature_extractors
    ai_app.feature_extractors = extractors
    yield extractors
    ai_app.feature_extractors = original


@pytest.fixture()
def client(mock_redis, mock_detectors, mock_ensemble, mock_prediction_service):
    """Flask test client with all external deps mocked."""
    ai_app.app.config["TESTING"] = True
    # Prevent before_request hook from re-initializing models and clobbering mocks.
    ai_app._models_initialized = True
    with ai_app.app.test_client() as c:
        yield c


@pytest.fixture()
def bare_client(mock_redis):
    """Test client with only Redis mocked (no model stubs)."""
    ai_app.app.config["TESTING"] = True
    ai_app._models_initialized = True
    with ai_app.app.test_client() as c:
        yield c


# ===================================================================
# Health check
# ===================================================================


class TestHealthCheck:
    def test_healthy_when_all_models_ready(self, client, mock_detectors, mock_ensemble):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert data["ensemble_ready"] is True
        assert data["version"] == "1.0.0"
        assert all(v is True for v in data["models"].values())

    def test_degraded_when_detector_not_ready(
        self, client, mock_detectors, mock_ensemble
    ):
        mock_detectors["lstm"].is_ready.return_value = False
        resp = client.get("/health")
        data = resp.get_json()
        assert data["status"] == "degraded"
        assert data["models"]["lstm"] is False
        assert data["models"]["xgboost"] is True

    def test_ensemble_not_ready_when_none(self, client, mock_detectors):
        original = ai_app.ensemble
        ai_app.ensemble = None
        try:
            resp = client.get("/health")
            data = resp.get_json()
            assert data["ensemble_ready"] is False
        finally:
            ai_app.ensemble = original

    def test_health_does_not_require_auth(
        self, bare_client, mock_detectors, mock_ensemble
    ):
        """Health endpoint must be public for load-balancer probes."""
        with patch("auth_middleware._verify_token", return_value=None):
            resp = bare_client.get("/health")
            assert resp.status_code == 200


# ===================================================================
# Model status
# ===================================================================


class TestModelStatus:
    def test_returns_all_model_details(self, client, auth_headers, mock_detectors):
        resp = client.get("/api/v1/models/status", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert set(data["models"].keys()) == {
            "xgboost",
            "lstm",
            "isolation_forest",
            "autoencoder",
        }
        for name, info in data["models"].items():
            assert "ready" in info
            assert "version" in info
            assert "metrics" in info
            assert "last_updated" in info
            mock_detectors[name].get_metrics.assert_called()

    def test_includes_ensemble_info(self, client, auth_headers, mock_ensemble):
        resp = client.get("/api/v1/models/status", headers=auth_headers)
        data = resp.get_json()
        assert data["ensemble"]["ready"] is True
        assert "threshold" in data["ensemble"]

    def test_requires_auth(self, bare_client):
        resp = bare_client.get("/api/v1/models/status")
        assert resp.status_code == 401


# ===================================================================
# Single detection  (/api/v1/detect)
# ===================================================================


class TestDetect:
    @staticmethod
    def _payload(**overrides):
        base = {
            "traffic_data": {
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "source_port": 54321,
                "dest_port": 22,
                "protocol": "TCP",
                "length": 128,
            }
        }
        base.update(overrides)
        return base

    def test_successful_detection(
        self, client, auth_headers, mock_prediction_service, mock_redis
    ):
        resp = client.post("/api/v1/detect", headers=auth_headers, json=self._payload())
        assert resp.status_code == 200
        mock_prediction_service.predict.assert_called_once()
        data = resp.get_json()
        assert "detection_id" in data
        assert "is_threat" in data

    def test_context_forwarded_to_service(
        self, client, auth_headers, mock_prediction_service
    ):
        ctx = {"asset_criticality": 5, "user_role": "admin"}
        resp = client.post(
            "/api/v1/detect", headers=auth_headers, json=self._payload(context=ctx)
        )
        assert resp.status_code == 200
        call_args = mock_prediction_service.predict.call_args
        assert call_args[0][1] == ctx

    def test_missing_traffic_data_returns_400(self, client, auth_headers):
        resp = client.post("/api/v1/detect", headers=auth_headers, json={"context": {}})
        assert resp.status_code == 400
        assert "traffic_data" in resp.get_json()["error"]

    def test_null_body_returns_400(self, client, auth_headers):
        resp = client.post(
            "/api/v1/detect",
            headers=auth_headers,
            data="null",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_prediction_service_exception_returns_500(
        self, client, auth_headers, mock_prediction_service
    ):
        mock_prediction_service.predict.side_effect = RuntimeError("model crashed")
        resp = client.post("/api/v1/detect", headers=auth_headers, json=self._payload())
        assert resp.status_code == 500
        assert "Detection failed" in resp.get_json()["error"]

    def test_requires_auth(self, bare_client):
        resp = bare_client.post("/api/v1/detect", json=self._payload())
        assert resp.status_code == 401

    def test_detection_is_logged_to_redis(
        self, client, auth_headers, mock_prediction_service, mock_redis
    ):
        client.post("/api/v1/detect", headers=auth_headers, json=self._payload())
        mock_redis.incr.assert_any_call("ai_engine:total_detections")


# ===================================================================
# Batch detection  (/api/v1/detect/batch)
# ===================================================================


class TestDetectBatch:
    @staticmethod
    def _batch_payload(count=3):
        return {
            "traffic_batch": [
                {
                    "source_ip": f"192.168.1.{i}",
                    "dest_ip": "10.0.0.1",
                    "dest_port": 80,
                    "protocol": "TCP",
                }
                for i in range(count)
            ]
        }

    def test_successful_batch(self, client, auth_headers, mock_prediction_service):
        resp = client.post(
            "/api/v1/detect/batch", headers=auth_headers, json=self._batch_payload()
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "results" in data
        assert data["total"] == 3
        assert "threats_detected" in data

    def test_threats_detected_count_accurate(
        self, client, auth_headers, mock_prediction_service
    ):
        resp = client.post(
            "/api/v1/detect/batch", headers=auth_headers, json=self._batch_payload()
        )
        data = resp.get_json()
        expected = sum(1 for r in data["results"] if r["is_threat"])
        assert data["threats_detected"] == expected

    def test_missing_traffic_batch_returns_400(self, client, auth_headers):
        resp = client.post(
            "/api/v1/detect/batch", headers=auth_headers, json={"foo": "bar"}
        )
        assert resp.status_code == 400
        assert "traffic_batch" in resp.get_json()["error"]

    def test_batch_size_limit(self, client, auth_headers):
        original = ai_app.app.config["BATCH_SIZE"]
        ai_app.app.config["BATCH_SIZE"] = 5
        try:
            resp = client.post(
                "/api/v1/detect/batch",
                headers=auth_headers,
                json=self._batch_payload(count=10),
            )
            assert resp.status_code == 400
            assert "Batch size" in resp.get_json()["error"]
        finally:
            ai_app.app.config["BATCH_SIZE"] = original

    def test_single_item_batch(self, client, auth_headers, mock_prediction_service):
        mock_prediction_service.predict_batch.return_value = [dict(_THREAT_RESULT)]
        resp = client.post(
            "/api/v1/detect/batch",
            headers=auth_headers,
            json=self._batch_payload(count=1),
        )
        assert resp.status_code == 200
        assert resp.get_json()["total"] == 1

    def test_prediction_failure_returns_500(
        self, client, auth_headers, mock_prediction_service
    ):
        mock_prediction_service.predict_batch.side_effect = RuntimeError("boom")
        resp = client.post(
            "/api/v1/detect/batch", headers=auth_headers, json=self._batch_payload()
        )
        assert resp.status_code == 500

    def test_requires_auth(self, bare_client):
        resp = bare_client.post("/api/v1/detect/batch", json=self._batch_payload())
        assert resp.status_code == 401


# ===================================================================
# Feature extraction  (/api/v1/features/extract)
# ===================================================================


class TestFeatureExtraction:
    @staticmethod
    def _payload(**overrides):
        base = {
            "raw_data": {
                "source_ip": "10.0.0.5",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP",
                "length": 256,
            }
        }
        base.update(overrides)
        return base

    def test_extract_all_default_types(
        self, bare_client, auth_headers, mock_feature_extractors
    ):
        resp = bare_client.post(
            "/api/v1/features/extract", headers=auth_headers, json=self._payload()
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "features" in data
        assert "timestamp" in data
        for name in ("statistical", "behavioral", "contextual"):
            mock_feature_extractors[name].extract.assert_called_once()

    def test_extract_specific_types(
        self, bare_client, auth_headers, mock_feature_extractors
    ):
        payload = self._payload(feature_types=["statistical"])
        resp = bare_client.post(
            "/api/v1/features/extract", headers=auth_headers, json=payload
        )
        assert resp.status_code == 200
        mock_feature_extractors["statistical"].extract.assert_called_once()
        mock_feature_extractors["behavioral"].extract.assert_not_called()

    def test_missing_raw_data_returns_400(self, bare_client, auth_headers):
        resp = bare_client.post(
            "/api/v1/features/extract", headers=auth_headers, json={"foo": 1}
        )
        assert resp.status_code == 400
        assert "raw_data" in resp.get_json()["error"]

    def test_unknown_feature_type_ignored(
        self, bare_client, auth_headers, mock_feature_extractors
    ):
        payload = self._payload(feature_types=["nonexistent"])
        resp = bare_client.post(
            "/api/v1/features/extract", headers=auth_headers, json=payload
        )
        assert resp.status_code == 200
        assert resp.get_json()["features"] == {}

    def test_extractor_exception_returns_500(
        self, bare_client, auth_headers, mock_feature_extractors
    ):
        mock_feature_extractors["statistical"].extract.side_effect = RuntimeError(
            "fail"
        )
        resp = bare_client.post(
            "/api/v1/features/extract", headers=auth_headers, json=self._payload()
        )
        assert resp.status_code == 500

    def test_requires_auth(self, bare_client):
        resp = bare_client.post("/api/v1/features/extract", json=self._payload())
        assert resp.status_code == 401


# ===================================================================
# Model reload  (/api/v1/models/reload)
# ===================================================================


class TestModelReload:
    @patch.object(ai_app, "initialize_models", return_value=True)
    def test_successful_reload(self, mock_init, client, auth_headers):
        resp = client.post("/api/v1/models/reload", headers=auth_headers)
        assert resp.status_code == 200
        assert "reloaded" in resp.get_json()["message"].lower()
        mock_init.assert_called_once()

    @patch.object(ai_app, "initialize_models", return_value=False)
    def test_reload_failure_returns_500(self, mock_init, client, auth_headers):
        resp = client.post("/api/v1/models/reload", headers=auth_headers)
        assert resp.status_code == 500

    @patch.object(ai_app, "initialize_models", side_effect=RuntimeError("disk error"))
    def test_reload_exception_returns_500(self, mock_init, client, auth_headers):
        resp = client.post("/api/v1/models/reload", headers=auth_headers)
        assert resp.status_code == 500

    def test_requires_auth(self, bare_client):
        resp = bare_client.post("/api/v1/models/reload")
        assert resp.status_code == 401


# ===================================================================
# Statistics  (/api/v1/statistics)
# ===================================================================


class TestStatistics:
    def test_returns_computed_stats(self, client, auth_headers, mock_redis):
        mock_redis.get.side_effect = lambda k: {
            "ai_engine:total_detections": b"200",
            "ai_engine:threats_detected": b"40",
            "ai_engine:false_positives": b"5",
        }.get(k)
        resp = client.get("/api/v1/statistics", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_detections"] == 200
        assert data["threats_detected"] == 40
        assert data["false_positives"] == 5
        assert data["threat_rate"] == pytest.approx(0.2)
        assert data["false_positive_rate"] == pytest.approx(5 / 40)

    def test_handles_zero_detections(self, client, auth_headers, mock_redis):
        mock_redis.get.return_value = None
        resp = client.get("/api/v1/statistics", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_detections"] == 0
        assert data["threat_rate"] == 0.0

    def test_redis_error_returns_500(self, client, auth_headers, mock_redis):
        mock_redis.get.side_effect = _redis_mod.ConnectionError("down")
        resp = client.get("/api/v1/statistics", headers=auth_headers)
        assert resp.status_code == 500

    def test_requires_auth(self, bare_client):
        resp = bare_client.get("/api/v1/statistics")
        assert resp.status_code == 401


# ===================================================================
# Feedback  (/api/v1/feedback, /api/v1/feedback/stats)
# ===================================================================


class TestFeedback:
    def test_submit_correct_detection(self, client, auth_headers, mock_redis):
        payload = {
            "detection_id": "det_123",
            "is_correct": True,
            "actual_label": "malicious",
        }
        resp = client.post("/api/v1/feedback", headers=auth_headers, json=payload)
        assert resp.status_code == 200
        mock_redis.hset.assert_called_once()
        mock_redis.expire.assert_called_once()

    def test_false_positive_increments_counter(self, client, auth_headers, mock_redis):
        payload = {
            "detection_id": "det_456",
            "is_correct": False,
            "actual_label": "benign",
        }
        resp = client.post("/api/v1/feedback", headers=auth_headers, json=payload)
        assert resp.status_code == 200
        mock_redis.incr.assert_any_call("ai_engine:false_positives")

    def test_incorrect_but_not_benign_does_not_increment_fp(
        self, client, auth_headers, mock_redis
    ):
        payload = {
            "detection_id": "det_789",
            "is_correct": False,
            "actual_label": "malicious",
        }
        resp = client.post("/api/v1/feedback", headers=auth_headers, json=payload)
        assert resp.status_code == 200
        fp_calls = [
            c
            for c in mock_redis.incr.call_args_list
            if c[0][0] == "ai_engine:false_positives"
        ]
        assert len(fp_calls) == 0

    def test_includes_features_in_stored_feedback(
        self, client, auth_headers, mock_redis
    ):
        payload = {
            "detection_id": "det_feat",
            "is_correct": True,
            "features": {"f1": 0.1, "f2": 0.9},
        }
        resp = client.post("/api/v1/feedback", headers=auth_headers, json=payload)
        assert resp.status_code == 200
        stored_mapping = mock_redis.hset.call_args[1]["mapping"]
        assert "features" in stored_mapping
        assert json.loads(stored_mapping["features"]) == {"f1": 0.1, "f2": 0.9}

    def test_missing_required_fields_returns_400(self, client, auth_headers):
        resp = client.post(
            "/api/v1/feedback", headers=auth_headers, json={"detection_id": "x"}
        )
        assert resp.status_code == 400

        resp = client.post(
            "/api/v1/feedback", headers=auth_headers, json={"is_correct": True}
        )
        assert resp.status_code == 400

    def test_feedback_stats_below_threshold(self, client, auth_headers, mock_redis):
        mock_redis.keys.return_value = [f"ai_engine:feedback:{i}" for i in range(50)]
        resp = client.get("/api/v1/feedback/stats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["feedback_count"] == 50
        assert data["ready_for_retrain"] is False
        assert data["min_samples_for_retrain"] == 100

    def test_feedback_stats_above_threshold(self, client, auth_headers, mock_redis):
        mock_redis.keys.return_value = [f"ai_engine:feedback:{i}" for i in range(150)]
        resp = client.get("/api/v1/feedback/stats", headers=auth_headers)
        data = resp.get_json()
        assert data["feedback_count"] == 150
        assert data["ready_for_retrain"] is True

    def test_requires_auth(self, bare_client):
        resp = bare_client.post(
            "/api/v1/feedback", json={"detection_id": "x", "is_correct": True}
        )
        assert resp.status_code == 401


# ===================================================================
# Ensemble scoring logic  (unit tests on StackingEnsemble)
# ===================================================================


class TestEnsembleScoring:
    """Direct unit tests on the StackingEnsemble aggregation logic."""

    def _make_ensemble(self, *, threshold=0.5, weights=None):
        detectors = {
            "xgboost": _make_detector(),
            "lstm": _make_detector(),
            "isolation_forest": _make_detector(),
            "autoencoder": _make_detector(),
        }
        from models.ensemble.stacking_classifier import StackingEnsemble

        ens = StackingEnsemble(
            base_detectors=detectors,
            threshold=threshold,
            weights=weights,
            use_meta_learner=False,
        )
        return ens, detectors

    def test_unanimous_threat_verdict(self):
        ens, dets = self._make_ensemble()
        for d in dets.values():
            d.predict.return_value = {
                "is_threat": True,
                "confidence": 0.95,
                "threat_type": "malware",
            }
        result = ens.predict(np.zeros(50))
        assert result["is_threat"] is True
        assert result["threat_score"] >= 0.5
        assert result["threat_type"] == "malware"

    def test_unanimous_benign_verdict(self):
        ens, dets = self._make_ensemble(threshold=0.5)
        for d in dets.values():
            d.predict.return_value = {
                "is_threat": False,
                "confidence": 0.9,
                "threat_type": "benign",
            }
        result = ens.predict(np.zeros(50))
        assert result["is_threat"] is False

    def test_split_verdict_weighted_scoring(self):
        ens, dets = self._make_ensemble(threshold=0.5)
        dets["xgboost"].predict.return_value = {
            "is_threat": True,
            "confidence": 0.9,
            "threat_type": "brute_force",
        }
        dets["lstm"].predict.return_value = {
            "is_threat": True,
            "confidence": 0.85,
            "threat_type": "brute_force",
        }
        dets["isolation_forest"].predict.return_value = {
            "is_threat": False,
            "confidence": 0.8,
            "threat_type": "benign",
        }
        dets["autoencoder"].predict.return_value = {
            "is_threat": False,
            "confidence": 0.7,
            "threat_type": "benign",
        }
        result = ens.predict(np.zeros(50))
        assert "is_threat" in result
        assert 0.0 <= result["threat_score"] <= 1.0

    def test_threat_type_majority_voting(self):
        ens, dets = self._make_ensemble()
        dets["xgboost"].predict.return_value = {
            "is_threat": True,
            "confidence": 0.9,
            "threat_type": "dos_attack",
        }
        dets["lstm"].predict.return_value = {
            "is_threat": True,
            "confidence": 0.8,
            "threat_type": "dos_attack",
        }
        dets["isolation_forest"].predict.return_value = {
            "is_threat": True,
            "confidence": 0.7,
            "threat_type": "port_scan",
        }
        dets["autoencoder"].predict.return_value = {
            "is_threat": True,
            "confidence": 0.6,
            "threat_type": "dos_attack",
        }
        result = ens.predict(np.zeros(50))
        assert result["threat_type"] == "dos_attack"

    def test_consensus_perfect_agreement(self):
        ens, _ = self._make_ensemble()
        results = {
            "a": {"is_threat": True},
            "b": {"is_threat": True},
            "c": {"is_threat": True},
        }
        assert ens._calculate_consensus(results) == 1.0

    def test_consensus_total_disagreement(self):
        ens, _ = self._make_ensemble()
        results = {"a": {"is_threat": True}, "b": {"is_threat": False}}
        assert ens._calculate_consensus(results) == 0.5

    def test_consensus_single_detector(self):
        ens, _ = self._make_ensemble()
        results = {"only": {"is_threat": True}}
        assert ens._calculate_consensus(results) == 1.0

    def test_context_increases_score_for_critical_assets(self):
        ens, dets = self._make_ensemble(threshold=0.50)
        for d in dets.values():
            d.predict.return_value = {
                "is_threat": True,
                "confidence": 0.48,
                "threat_type": "unknown",
            }
        context = {"asset_criticality": 5, "time_risk": 0.9}
        result = ens.predict(np.zeros(50), context)
        assert result["threat_score"] >= 0.48

    def test_context_admin_role_adds_scrutiny(self):
        ens, dets = self._make_ensemble(threshold=0.50)
        for d in dets.values():
            d.predict.return_value = {
                "is_threat": True,
                "confidence": 0.49,
                "threat_type": "unknown",
            }

        result_no_ctx = ens.predict(np.zeros(50))
        result_admin = ens.predict(
            np.zeros(50), {"user_role": "admin", "asset_criticality": 4}
        )
        assert result_admin["threat_score"] >= result_no_ctx["threat_score"]

    def test_no_ready_detectors_returns_default(self):
        ens, dets = self._make_ensemble()
        for d in dets.values():
            d.is_ready.return_value = False
        result = ens.predict(np.zeros(50))
        assert result["is_threat"] is False
        assert result["confidence"] == 0.0

    def test_single_detector_failure_still_produces_result(self):
        ens, dets = self._make_ensemble()
        dets["xgboost"].predict.side_effect = RuntimeError("model error")
        for name in ("lstm", "isolation_forest", "autoencoder"):
            dets[name].predict.return_value = {
                "is_threat": True,
                "confidence": 0.9,
                "threat_type": "dos_attack",
            }
        result = ens.predict(np.zeros(50))
        assert result["is_threat"] is True
        assert "xgboost" not in result["model_verdicts"]

    def test_weight_update_normalises_to_one(self):
        ens, _ = self._make_ensemble()
        ens.update_weights(
            {"xgboost": 10.0, "lstm": 5.0, "isolation_forest": 3.0, "autoencoder": 2.0}
        )
        assert sum(ens.weights.values()) == pytest.approx(1.0, abs=1e-9)

    def test_threshold_clamps_to_valid_range(self):
        ens, _ = self._make_ensemble()
        ens.update_threshold(1.5)
        assert ens.threshold == 1.0
        ens.update_threshold(-0.3)
        assert ens.threshold == 0.0

    def test_result_includes_model_verdicts(self):
        ens, dets = self._make_ensemble()
        for d in dets.values():
            d.predict.return_value = {
                "is_threat": True,
                "confidence": 0.88,
                "threat_type": "malware",
            }
        result = ens.predict(np.zeros(50))
        assert len(result["model_verdicts"]) == 4
        for verdict in result["model_verdicts"].values():
            assert "is_threat" in verdict
            assert "confidence" in verdict

    def test_result_includes_ensemble_details(self):
        ens, dets = self._make_ensemble(threshold=0.6)
        for d in dets.values():
            d.predict.return_value = {
                "is_threat": True,
                "confidence": 0.9,
                "threat_type": "malware",
            }
        result = ens.predict(np.zeros(50))
        details = result["ensemble_details"]
        assert details["threshold"] == 0.6
        assert details["n_detectors"] == 4
        assert 0.0 <= details["consensus"] <= 1.0

    def test_batch_prediction(self):
        ens, dets = self._make_ensemble()
        for d in dets.values():
            d.predict.return_value = {
                "is_threat": True,
                "confidence": 0.9,
                "threat_type": "malware",
            }
        features = np.zeros((5, 50))
        results = ens.predict_batch(features)
        assert len(results) == 5
        assert all(r["is_threat"] for r in results)


# ===================================================================
# log_detection helper
# ===================================================================


class TestLogDetection:
    def test_threat_increments_both_counters(self, mock_redis):
        ai_app.log_detection(
            {
                "detection_id": "det_t1",
                "is_threat": True,
                "confidence": 0.9,
                "threat_type": "malware",
                "model_verdicts": {},
            }
        )
        mock_redis.incr.assert_any_call("ai_engine:total_detections")
        mock_redis.incr.assert_any_call("ai_engine:threats_detected")
        mock_redis.hset.assert_called_once()
        mock_redis.expire.assert_called_once()

    def test_benign_increments_only_total(self, mock_redis):
        ai_app.log_detection(
            {
                "detection_id": "det_b1",
                "is_threat": False,
                "confidence": 0.1,
                "threat_type": "benign",
                "model_verdicts": {},
            }
        )
        mock_redis.incr.assert_called_once_with("ai_engine:total_detections")

    def test_redis_failure_swallowed(self, mock_redis):
        mock_redis.incr.side_effect = _redis_mod.ConnectionError("down")
        ai_app.log_detection(
            {"detection_id": "x", "is_threat": False, "model_verdicts": {}}
        )


# ===================================================================
# Error handlers
# ===================================================================


class TestErrorHandlers:
    def test_404(self, client):
        resp = client.get("/nonexistent-path")
        assert resp.status_code == 404
        assert "Endpoint not found" in resp.get_json()["error"]
