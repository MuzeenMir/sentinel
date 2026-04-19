"""
Comprehensive pytest tests for the SENTINEL DRL Policy Engine.

Covers Flask endpoints (decide, batch, feedback, train, save/load, stats)
and the core domain classes (StateBuilder, ActionSpace, RewardFunction,
PPOAgent).  All external dependencies (Redis, Kafka, model files) are mocked.

PPOAgent tests require PyTorch – they are guarded with
``pytest.importorskip`` so the rest of the suite passes cleanly without it.
"""

import os
import sys
import json
import tempfile
import pytest
from unittest.mock import MagicMock, patch
import numpy as np

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_tests_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.join(_tests_dir, "..")
_drl_engine_dir = os.path.join(_backend_dir, "drl-engine")
sys.path.insert(0, _drl_engine_dir)
sys.path.insert(0, _backend_dir)

# ---------------------------------------------------------------------------
# Pre-import mocks.
#
# The PPOAgent module defines PolicyNetwork(nn.Module) and
# ValueNetwork(nn.Module) at module level.  When PyTorch is absent we inject
# a lightweight real-class stub so class inheritance succeeds.  Redis is
# patched before the app's module-level ``redis.from_url()`` call.
# ---------------------------------------------------------------------------
import types as _types

_TORCH_IS_REAL = False


def _install_torch_stub():
    """Inject a minimal torch stub when torch is absent."""
    global _TORCH_IS_REAL
    try:
        import torch

        torch.zeros(1)
        _TORCH_IS_REAL = True
        return
    except Exception:
        pass

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

# Uses the real auth_middleware; _bypass_auth fixture patches per-test.
# Global sys.modules replacement removed to prevent leakage into other
# test modules.

_mock_redis_client = MagicMock()
_redis_patcher = patch("redis.from_url", return_value=_mock_redis_client)
_redis_patcher.start()

# Use a unique module name so running alongside test_ai_engine doesn't clash.
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "sentinel_drl_engine_app",
    os.path.join(_drl_engine_dir, "app.py"),
    submodule_search_locations=[],
)
drl_app = _ilu.module_from_spec(_spec)
sys.modules["sentinel_drl_engine_app"] = drl_app
_spec.loader.exec_module(drl_app)

# Stop patcher so it doesn't leak into other test modules' sessions.
_redis_patcher.stop()

from agent.state_builder import StateBuilder  # noqa: E402
from agent.action_space import ActionSpace, ActionType  # noqa: E402
from agent.reward_function import RewardFunction  # noqa: E402

import redis as _redis_mod  # noqa: E402


# ===================================================================
# Helpers
# ===================================================================

_SAMPLE_DETECTION = {
    "detection_id": "det_test_001",
    "threat_score": 0.92,
    "threat_type": "brute_force",
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "dest_port": 22,
    "protocol": "TCP",
    "asset_criticality": 4,
}


def _make_mock_ppo_agent(*, action_idx=1, ready=True):
    """Return a MagicMock satisfying the PPOAgent interface."""
    agent = MagicMock()
    agent.is_ready.return_value = ready
    agent.get_version.return_value = "1.0.0"
    probs = np.array([0.05, 0.70, 0.05, 0.05, 0.05, 0.03, 0.03, 0.04])
    agent.select_action.return_value = (action_idx, probs)
    agent.get_value.return_value = 0.75
    agent.save_model.return_value = True
    agent.load_model.return_value = True
    return agent


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture()
def mock_redis():
    _mock_redis_client.reset_mock(side_effect=True)
    for attr in (
        "get",
        "set",
        "lrange",
        "llen",
        "incr",
        "lpush",
        "ltrim",
        "expire",
        "keys",
    ):
        child = getattr(_mock_redis_client, attr)
        child.side_effect = None
        child.return_value = None
    _mock_redis_client.get.return_value = None
    _mock_redis_client.lrange.return_value = []
    _mock_redis_client.llen.return_value = 0
    _mock_redis_client.incr.return_value = 1
    return _mock_redis_client


@pytest.fixture(autouse=True)
def _bypass_auth():
    """Bypass JWT + role checks for every test."""
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
def mock_ppo_agent():
    """Inject a mocked PPO agent into the app module."""
    agent = _make_mock_ppo_agent()
    original = drl_app.ppo_agent
    drl_app.ppo_agent = agent
    yield agent
    drl_app.ppo_agent = original


@pytest.fixture()
def mock_trainer():
    """Inject a mocked DRLTrainer into the app module."""
    trainer = MagicMock()
    trainer.train_on_experiences.return_value = {
        "policy_loss": 0.12,
        "value_loss": 0.08,
        "entropy": 0.45,
        "training_steps": 10,
    }
    original = drl_app.trainer
    drl_app.trainer = trainer
    yield trainer
    drl_app.trainer = original


@pytest.fixture()
def client(mock_redis, mock_ppo_agent):
    """Flask test client with Redis and PPO agent mocked."""
    drl_app.app.config["TESTING"] = True
    with drl_app.app.test_client() as c:
        yield c


@pytest.fixture()
def bare_client(mock_redis):
    """Test client with only Redis mocked (no agent stub)."""
    drl_app.app.config["TESTING"] = True
    with drl_app.app.test_client() as c:
        yield c


# ===================================================================
# Health check
# ===================================================================


class TestHealthCheck:
    def test_healthy_with_agent(self, client, mock_ppo_agent):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert data["agent_ready"] is True
        assert data["model_version"] == "1.0.0"

    def test_agent_not_ready(self, client, mock_ppo_agent):
        mock_ppo_agent.is_ready.return_value = False
        resp = client.get("/health")
        data = resp.get_json()
        assert data["agent_ready"] is False

    def test_agent_none(self, bare_client):
        original = drl_app.ppo_agent
        drl_app.ppo_agent = None
        try:
            resp = bare_client.get("/health")
            data = resp.get_json()
            assert data["agent_ready"] is False
            assert data["model_version"] is None
        finally:
            drl_app.ppo_agent = original

    def test_health_is_public(self, bare_client, mock_ppo_agent):
        """Health must not require auth (load-balancer probes)."""
        drl_app.ppo_agent = mock_ppo_agent
        with patch("auth_middleware._verify_token", return_value=None):
            resp = bare_client.get("/health")
            assert resp.status_code == 200


# ===================================================================
# Single decision  (/api/v1/decide)
# ===================================================================


class TestDecide:
    def test_successful_decision(
        self, client, auth_headers, mock_ppo_agent, mock_redis
    ):
        resp = client.post(
            "/api/v1/decide", headers=auth_headers, json=_SAMPLE_DETECTION
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "decision_id" in data
        assert data["action"] == "DENY"  # action_idx=1 → DENY
        assert data["action_code"] == 1
        assert 0.0 <= data["confidence"] <= 1.0
        assert data["state_features"]["threat_score"] == 0.92

    def test_decision_stores_to_redis(
        self, client, auth_headers, mock_ppo_agent, mock_redis
    ):
        client.post("/api/v1/decide", headers=auth_headers, json=_SAMPLE_DETECTION)
        mock_redis.set.assert_called()
        mock_redis.incr.assert_any_call("drl:total_decisions")

    def test_missing_threat_score_returns_400(self, client, auth_headers):
        payload = {"detection_id": "det_1", "source_ip": "1.2.3.4"}
        resp = client.post("/api/v1/decide", headers=auth_headers, json=payload)
        assert resp.status_code == 400
        assert "threat_score" in resp.get_json()["error"]

    def test_null_body_returns_400(self, client, auth_headers):
        resp = client.post(
            "/api/v1/decide",
            headers=auth_headers,
            data="null",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_agent_failure_returns_500(self, client, auth_headers, mock_ppo_agent):
        mock_ppo_agent.select_action.side_effect = RuntimeError("torch error")
        resp = client.post(
            "/api/v1/decide", headers=auth_headers, json=_SAMPLE_DETECTION
        )
        assert resp.status_code == 500

    def test_parameters_include_target(self, client, auth_headers, mock_ppo_agent):
        resp = client.post(
            "/api/v1/decide", headers=auth_headers, json=_SAMPLE_DETECTION
        )
        params = resp.get_json()["parameters"]
        assert params["target"]["source_ip"] == "192.168.1.100"
        assert params["target"]["dest_port"] == 22

    def test_requires_auth(self, bare_client, mock_ppo_agent):
        drl_app.ppo_agent = mock_ppo_agent
        resp = bare_client.post("/api/v1/decide", json=_SAMPLE_DETECTION)
        assert resp.status_code == 401


# ===================================================================
# Batch decisions  (/api/v1/decide/batch)
# ===================================================================


class TestDecideBatch:
    @staticmethod
    def _batch_payload(count=3):
        return {
            "detections": [
                {
                    "detection_id": f"det_{i}",
                    "threat_score": 0.6 + 0.1 * i,
                    "source_ip": f"10.0.0.{i}",
                    "dest_port": 22,
                    "protocol": "TCP",
                }
                for i in range(count)
            ]
        }

    def test_successful_batch(self, client, auth_headers, mock_ppo_agent):
        resp = client.post(
            "/api/v1/decide/batch", headers=auth_headers, json=self._batch_payload()
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 3
        assert len(data["decisions"]) == 3
        for d in data["decisions"]:
            assert "action" in d
            assert "confidence" in d

    def test_each_detection_gets_own_action(self, client, auth_headers, mock_ppo_agent):
        call_count = [0]
        actions = [0, 1, 7]  # ALLOW, DENY, MONITOR
        probs = np.array([0.05, 0.70, 0.05, 0.05, 0.05, 0.03, 0.03, 0.04])

        def side_effect(state):
            idx = call_count[0] % len(actions)
            call_count[0] += 1
            return actions[idx], probs

        mock_ppo_agent.select_action.side_effect = side_effect
        resp = client.post(
            "/api/v1/decide/batch", headers=auth_headers, json=self._batch_payload()
        )
        data = resp.get_json()
        action_names = [d["action"] for d in data["decisions"]]
        assert "ALLOW" in action_names
        assert "DENY" in action_names
        assert "MONITOR" in action_names

    def test_missing_detections_returns_400(self, client, auth_headers):
        resp = client.post(
            "/api/v1/decide/batch", headers=auth_headers, json={"foo": "bar"}
        )
        assert resp.status_code == 400
        assert "detections" in resp.get_json()["error"]

    def test_single_item_batch(self, client, auth_headers, mock_ppo_agent):
        resp = client.post(
            "/api/v1/decide/batch",
            headers=auth_headers,
            json=self._batch_payload(count=1),
        )
        assert resp.status_code == 200
        assert resp.get_json()["total"] == 1

    def test_agent_failure_returns_500(self, client, auth_headers, mock_ppo_agent):
        mock_ppo_agent.select_action.side_effect = RuntimeError("fail")
        resp = client.post(
            "/api/v1/decide/batch", headers=auth_headers, json=self._batch_payload()
        )
        assert resp.status_code == 500

    def test_requires_auth(self, bare_client, mock_ppo_agent):
        drl_app.ppo_agent = mock_ppo_agent
        resp = bare_client.post("/api/v1/decide/batch", json=self._batch_payload())
        assert resp.status_code == 401


# ===================================================================
# Feedback  (/api/v1/feedback)
# ===================================================================


class TestFeedback:
    def _stored_decision(self):
        return json.dumps(
            {
                "decision_id": "drl_20260313_test01",
                "action": "DENY",
                "action_code": 1,
                "state": [0.9, 0.5, 0.8, 0.2, 0.3, 0.5, 0.1, 0.0, 0.9, 0.2, 0.3, 0.2],
            }
        )

    def test_successful_feedback(self, client, auth_headers, mock_redis):
        mock_redis.get.return_value = self._stored_decision()
        payload = {
            "decision_id": "drl_20260313_test01",
            "outcome": "success",
            "blocked_threat": True,
            "false_positive": False,
            "latency_impact": 0.01,
        }
        resp = client.post("/api/v1/feedback", headers=auth_headers, json=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "reward" in data
        assert isinstance(data["reward"], float)
        mock_redis.lpush.assert_called()
        mock_redis.incr.assert_any_call("drl:total_feedback")
        mock_redis.incr.assert_any_call("drl:blocked_threats")

    def test_false_positive_feedback(self, client, auth_headers, mock_redis):
        mock_redis.get.return_value = self._stored_decision()
        payload = {
            "decision_id": "drl_20260313_test01",
            "outcome": "false_positive",
            "blocked_threat": False,
            "false_positive": True,
        }
        resp = client.post("/api/v1/feedback", headers=auth_headers, json=payload)
        assert resp.status_code == 200
        mock_redis.incr.assert_any_call("drl:false_positives")

    def test_decision_not_found_returns_404(self, client, auth_headers, mock_redis):
        mock_redis.get.return_value = None
        payload = {"decision_id": "drl_nonexistent"}
        resp = client.post("/api/v1/feedback", headers=auth_headers, json=payload)
        assert resp.status_code == 404

    def test_missing_decision_id_returns_400(self, client, auth_headers):
        resp = client.post(
            "/api/v1/feedback", headers=auth_headers, json={"outcome": "success"}
        )
        assert resp.status_code == 400

    def test_experience_trimmed(self, client, auth_headers, mock_redis):
        mock_redis.get.return_value = self._stored_decision()
        payload = {"decision_id": "drl_20260313_test01", "blocked_threat": True}
        client.post("/api/v1/feedback", headers=auth_headers, json=payload)
        mock_redis.ltrim.assert_called_with("drl:experiences", 0, 100000)

    def test_requires_auth(self, bare_client, mock_ppo_agent):
        drl_app.ppo_agent = mock_ppo_agent
        resp = bare_client.post("/api/v1/feedback", json={"decision_id": "x"})
        assert resp.status_code == 401


# ===================================================================
# Train endpoint  (/api/v1/train)
# ===================================================================


class TestTrain:
    def _make_experiences(self, count):
        return [
            json.dumps(
                {
                    "state": [0.5] * 12,
                    "action": 1,
                    "reward": 0.8,
                    "outcome": "success",
                }
            ).encode()
            for _ in range(count)
        ]

    def test_successful_training(self, client, auth_headers, mock_redis, mock_trainer):
        mock_redis.lrange.return_value = self._make_experiences(700)
        resp = client.post(
            "/api/v1/train", headers=auth_headers, json={"epochs": 5, "batch_size": 64}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "metrics" in data
        assert data["experiences_used"] == 700

    def test_insufficient_data_returns_400(
        self, client, auth_headers, mock_redis, mock_trainer
    ):
        mock_redis.lrange.return_value = self._make_experiences(10)
        resp = client.post(
            "/api/v1/train", headers=auth_headers, json={"batch_size": 64}
        )
        assert resp.status_code == 400
        assert "Insufficient" in resp.get_json()["error"]

    def test_requires_admin_role(self, bare_client, mock_ppo_agent, mock_trainer):
        drl_app.ppo_agent = mock_ppo_agent
        with patch("auth_middleware._verify_token") as mv:
            mv.return_value = {"user_id": "u2", "username": "viewer", "role": "viewer"}
            resp = bare_client.post(
                "/api/v1/train",
                headers={
                    "Authorization": "Bearer tok",
                    "Content-Type": "application/json",
                },
                json={},
            )
            assert resp.status_code == 403


# ===================================================================
# Model save/load endpoints
# ===================================================================


class TestModelSaveLoad:
    def test_save_success(self, client, auth_headers, mock_ppo_agent):
        resp = client.post("/api/v1/model/save", headers=auth_headers)
        assert resp.status_code == 200
        mock_ppo_agent.save_model.assert_called_once()

    def test_save_failure(self, client, auth_headers, mock_ppo_agent):
        mock_ppo_agent.save_model.return_value = False
        resp = client.post("/api/v1/model/save", headers=auth_headers)
        assert resp.status_code == 500

    def test_load_success(self, client, auth_headers, mock_ppo_agent):
        resp = client.post("/api/v1/model/load", headers=auth_headers)
        assert resp.status_code == 200
        mock_ppo_agent.load_model.assert_called_once()

    def test_load_failure(self, client, auth_headers, mock_ppo_agent):
        mock_ppo_agent.load_model.return_value = False
        resp = client.post("/api/v1/model/load", headers=auth_headers)
        assert resp.status_code == 500

    def test_save_requires_admin(self, bare_client, mock_ppo_agent):
        drl_app.ppo_agent = mock_ppo_agent
        with patch("auth_middleware._verify_token") as mv:
            mv.return_value = {
                "user_id": "u2",
                "username": "analyst",
                "role": "security_analyst",
            }
            resp = bare_client.post(
                "/api/v1/model/save",
                headers={"Authorization": "Bearer tok"},
            )
            assert resp.status_code == 403


# ===================================================================
# Statistics  (/api/v1/statistics)
# ===================================================================


class TestStatistics:
    def test_returns_computed_stats(
        self, client, auth_headers, mock_redis, mock_ppo_agent
    ):
        mock_redis.get.side_effect = lambda k: {
            "drl:total_decisions": b"500",
            "drl:total_feedback": b"200",
            "drl:false_positives": b"10",
            "drl:blocked_threats": b"180",
        }.get(k)
        mock_redis.llen.return_value = 1500
        resp = client.get("/api/v1/statistics", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_decisions"] == 500
        assert data["total_feedback"] == 200
        assert data["blocked_threats"] == 180
        assert data["false_positive_rate"] == pytest.approx(10 / 200)
        assert data["block_rate"] == pytest.approx(180 / 200)
        assert data["experiences_available"] == 1500

    def test_handles_zero_feedback(
        self, client, auth_headers, mock_redis, mock_ppo_agent
    ):
        mock_redis.get.return_value = None
        mock_redis.llen.return_value = 0
        resp = client.get("/api/v1/statistics", headers=auth_headers)
        data = resp.get_json()
        assert data["total_feedback"] == 0
        assert data["false_positive_rate"] == 0.0


# ===================================================================
# Action space / state space info endpoints
# ===================================================================


class TestInfoEndpoints:
    def test_action_space(self, client, auth_headers):
        resp = client.get("/api/v1/action-space", headers=auth_headers)
        assert resp.status_code == 200
        actions = resp.get_json()["actions"]
        assert len(actions) == 8
        names = {a["name"] for a in actions}
        assert {"ALLOW", "DENY", "RATE_LIMIT", "QUARANTINE", "MONITOR"} == names

    def test_state_space(self, client, auth_headers):
        resp = client.get("/api/v1/state-space", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["state_dim"] == 12
        assert len(data["features"]) == 12


# ===================================================================
# Error handlers
# ===================================================================


class TestErrorHandlers:
    def test_404(self, client):
        resp = client.get("/nonexistent-path")
        assert resp.status_code == 404
        assert "Endpoint not found" in resp.get_json()["error"]


# ===================================================================
# StateBuilder  (unit tests on the real class)
# ===================================================================


class TestStateBuilder:
    @pytest.fixture()
    def builder(self):
        return StateBuilder()

    def test_state_dimension(self, builder):
        assert builder.state_dim == 12

    def test_build_returns_float32_array(self, builder):
        state = builder.build_state({"threat_score": 0.9})
        assert state.dtype == np.float32
        assert state.shape == (12,)

    def test_threat_score_mapped(self, builder):
        state = builder.build_state({"threat_score": 0.95})
        assert state[0] == pytest.approx(0.95)

    def test_asset_criticality_normalized(self, builder):
        state_low = builder.build_state({"asset_criticality": 1})
        state_high = builder.build_state({"asset_criticality": 5})
        assert state_low[2] == pytest.approx(0.0)
        assert state_high[2] == pytest.approx(1.0)

    def test_protocol_risk_tcp(self, builder):
        state = builder.build_state({"protocol": "TCP"})
        assert state[4] == pytest.approx(0.3)

    def test_protocol_risk_icmp(self, builder):
        state = builder.build_state({"protocol": "ICMP"})
        assert state[4] == pytest.approx(0.5)

    def test_protocol_risk_unknown_defaults_to_tcp(self, builder):
        state = builder.build_state({"protocol": "SCTP"})
        assert state[4] == pytest.approx(0.3)

    def test_sensitive_port_ssh(self, builder):
        state = builder.build_state({"dest_port": 22})
        assert state[8] == pytest.approx(0.9)

    def test_nonsensitive_port_default(self, builder):
        state = builder.build_state({"dest_port": 8080})
        assert state[8] == pytest.approx(0.2)

    def test_is_internal_flag(self, builder):
        state_internal = builder.build_state({"is_internal": True})
        state_external = builder.build_state({"is_internal": False})
        assert state_internal[7] == 1.0
        assert state_external[7] == 0.0

    def test_traffic_volume_clipped(self, builder):
        state = builder.build_state({"traffic_volume": 50000})
        assert state[3] == pytest.approx(1.0)

    def test_historical_alerts_clipped(self, builder):
        state = builder.build_state({"historical_alert_count": 500})
        assert state[6] == pytest.approx(1.0)

    def test_time_risk_from_data(self, builder):
        state = builder.build_state({"time_risk": 0.8})
        assert state[5] == pytest.approx(0.8)

    def test_time_risk_default(self, builder):
        state = builder.build_state({})
        assert 0.0 <= state[5] <= 1.0

    def test_all_defaults_no_crash(self, builder):
        state = builder.build_state({})
        assert state.shape == (12,)
        assert np.all(np.isfinite(state))

    def test_feature_descriptions(self, builder):
        descs = builder.get_feature_descriptions()
        assert len(descs) == 12
        for d in descs:
            assert "name" in d
            assert "description" in d
            assert "index" in d

    def test_normalize_equal_bounds(self, builder):
        assert builder._normalize(5, 5, 5) == 0.5

    def test_normalize_clip_high(self, builder):
        assert builder._normalize(200, 0, 100, clip=True) == 1.0

    def test_normalize_clip_low(self, builder):
        assert builder._normalize(-10, 0, 100, clip=True) == 0.0


# ===================================================================
# ActionSpace  (unit tests on the real class)
# ===================================================================


class TestActionSpace:
    @pytest.fixture()
    def space(self):
        return ActionSpace()

    def test_action_dim(self, space):
        assert space.action_dim == 8

    def test_decode_allow(self, space):
        result = space.decode_action(ActionType.ALLOW)
        assert result["action"] == "ALLOW"
        assert result["action_code"] == 0

    def test_decode_deny(self, space):
        result = space.decode_action(ActionType.DENY)
        assert result["action"] == "DENY"
        assert result["parameters"]["duration"] == 3600

    def test_decode_rate_limit_low(self, space):
        result = space.decode_action(ActionType.RATE_LIMIT_LOW)
        assert result["action"] == "RATE_LIMIT"
        assert result["parameters"]["packets_per_second"] == 1000

    def test_decode_rate_limit_medium(self, space):
        result = space.decode_action(ActionType.RATE_LIMIT_MEDIUM)
        assert result["parameters"]["packets_per_second"] == 100

    def test_decode_rate_limit_high(self, space):
        result = space.decode_action(ActionType.RATE_LIMIT_HIGH)
        assert result["parameters"]["packets_per_second"] == 10

    def test_decode_quarantine_short(self, space):
        result = space.decode_action(ActionType.QUARANTINE_SHORT)
        assert result["action"] == "QUARANTINE"
        assert result["parameters"]["duration"] == 3600

    def test_decode_quarantine_long(self, space):
        result = space.decode_action(ActionType.QUARANTINE_LONG)
        assert result["parameters"]["duration"] == 86400

    def test_decode_monitor(self, space):
        result = space.decode_action(ActionType.MONITOR)
        assert result["action"] == "MONITOR"
        assert result["parameters"]["enhanced_logging"] is True

    def test_decode_invalid_falls_back_to_monitor(self, space):
        result = space.decode_action(99)
        assert result["action"] == "MONITOR"

    def test_decode_parameters_are_copies(self, space):
        r1 = space.decode_action(ActionType.DENY)
        r2 = space.decode_action(ActionType.DENY)
        r1["parameters"]["duration"] = 9999
        assert r2["parameters"]["duration"] == 3600

    def test_encode_allow(self, space):
        assert space.encode_action("ALLOW") == ActionType.ALLOW

    def test_encode_deny(self, space):
        assert space.encode_action("deny") == ActionType.DENY

    def test_encode_rate_limit_by_pps(self, space):
        assert (
            space.encode_action("RATE_LIMIT", {"packets_per_second": 1000})
            == ActionType.RATE_LIMIT_LOW
        )
        assert (
            space.encode_action("RATE_LIMIT", {"packets_per_second": 100})
            == ActionType.RATE_LIMIT_MEDIUM
        )
        assert (
            space.encode_action("RATE_LIMIT", {"packets_per_second": 5})
            == ActionType.RATE_LIMIT_HIGH
        )

    def test_encode_quarantine_by_duration(self, space):
        assert (
            space.encode_action("QUARANTINE", {"duration": 3600})
            == ActionType.QUARANTINE_SHORT
        )
        assert (
            space.encode_action("QUARANTINE", {"duration": 86400})
            == ActionType.QUARANTINE_LONG
        )

    def test_encode_unknown_defaults_to_monitor(self, space):
        assert space.encode_action("NUKE_FROM_ORBIT") == ActionType.MONITOR

    def test_action_descriptions(self, space):
        descs = space.get_action_descriptions()
        assert len(descs) == 8
        for d in descs:
            assert "index" in d
            assert "name" in d
            assert "description" in d

    def test_action_mask_high_threat_blocks_allow(self, space):
        mask = space.get_action_mask({"threat_score": 0.99})
        assert mask[ActionType.ALLOW] is False
        assert mask[ActionType.DENY] is True
        assert mask[ActionType.MONITOR] is True

    def test_action_mask_low_threat_blocks_long_quarantine(self, space):
        mask = space.get_action_mask({"threat_score": 0.3})
        assert mask[ActionType.QUARANTINE_LONG] is False

    def test_action_mask_internal_blocks_strict_rate_limit(self, space):
        mask = space.get_action_mask({"threat_score": 0.7, "is_internal": True})
        assert mask[ActionType.RATE_LIMIT_HIGH] is False

    def test_sample_action_with_mask(self, space):
        mask = [False] * 8
        mask[ActionType.MONITOR] = True
        for _ in range(20):
            assert space.sample_action(mask) == ActionType.MONITOR

    def test_sample_action_without_mask(self, space):
        action = space.sample_action()
        assert 0 <= action < 8


# ===================================================================
# RewardFunction  (unit tests on the real class)
# ===================================================================


class TestRewardFunction:
    @pytest.fixture()
    def rf(self):
        return RewardFunction(redis_client=MagicMock())

    def test_blocked_threat_positive_reward(self, rf):
        reward = rf.calculate_reward(action=1, blocked_threat=True)
        assert reward > 0

    def test_false_positive_negative_reward(self, rf):
        reward = rf.calculate_reward(action=1, false_positive=True)
        assert reward < 0

    def test_allow_with_no_threat_small_positive(self, rf):
        reward = rf.calculate_reward(
            action=0, blocked_threat=False, false_positive=False
        )
        assert reward > 0

    def test_allow_missed_threat_negative(self, rf):
        reward = rf.calculate_reward(action=0, blocked_threat=True)
        assert reward < 0

    def test_latency_penalty(self, rf):
        reward_low = rf.calculate_reward(action=7, latency_impact=0.0)
        reward_high = rf.calculate_reward(action=7, latency_impact=0.9)
        assert reward_low > reward_high

    def test_compliance_bonus(self, rf):
        reward_low = rf.calculate_reward(action=7, compliance_score=0.0)
        reward_high = rf.calculate_reward(action=7, compliance_score=1.0)
        assert reward_high > reward_low

    def test_statistics_updated(self, rf):
        rf.calculate_reward(action=1, blocked_threat=True)
        rf.calculate_reward(action=0, false_positive=True)
        stats = rf.get_reward_statistics()
        assert stats["total_count"] == 2
        assert stats["max_reward"] >= stats["min_reward"]

    def test_gae_advantage_length(self, rf):
        rewards = [1.0, 0.5, -0.3, 0.8]
        values = [0.9, 0.6, -0.1, 0.7]
        advantages = rf.calculate_advantage(rewards, values)
        assert len(advantages) == 4

    def test_gae_advantage_values_finite(self, rf):
        rewards = [1.0, 0.5, -0.3]
        values = [0.9, 0.6, -0.1]
        advantages = rf.calculate_advantage(rewards, values)
        assert all(np.isfinite(a) for a in advantages)

    def test_normalize_reward(self, rf):
        rf._reward_min = -2.0
        rf._reward_max = 2.0
        assert rf.normalize_reward(0.0) == pytest.approx(0.0)
        assert rf.normalize_reward(2.0) == pytest.approx(1.0)
        assert rf.normalize_reward(-2.0) == pytest.approx(-1.0)

    def test_normalize_reward_equal_bounds(self, rf):
        rf._reward_min = 1.0
        rf._reward_max = 1.0
        assert rf.normalize_reward(1.0) == 0.0

    def test_update_weights(self, rf):
        rf.update_weights({"alpha": 5.0})
        assert rf.weights["alpha"] == 5.0


# ===================================================================
# PPOAgent  (requires torch — skipped cleanly when not installed)
# ===================================================================


class TestPPOAgent:
    """Test the real PPOAgent class.  Requires PyTorch."""

    @pytest.fixture(autouse=True)
    def _require_real_torch(self):
        if not _TORCH_IS_REAL:
            pytest.skip("Real PyTorch required for PPOAgent tests")

    @pytest.fixture()
    def agent(self):
        from agent.ppo_agent import PPOAgent

        return PPOAgent(state_dim=12, action_dim=8, model_path=tempfile.mkdtemp())

    def test_init_sets_dimensions(self, agent):
        assert agent.state_dim == 12
        assert agent.action_dim == 8

    def test_is_ready_on_init(self, agent):
        assert agent.is_ready() is True

    def test_get_version(self, agent):
        assert isinstance(agent.get_version(), str)

    def test_select_action_stochastic(self, agent):
        state = np.random.randn(12).astype(np.float32)
        action, probs = agent.select_action(state)
        assert 0 <= action < 8
        assert probs.shape == (8,)
        assert np.isclose(probs.sum(), 1.0, atol=1e-4)

    def test_select_action_deterministic(self, agent):
        state = np.random.randn(12).astype(np.float32)
        action, probs = agent.select_action(state, deterministic=True)
        assert action == np.argmax(probs)

    def test_select_action_deterministic_consistent(self, agent):
        state = np.random.randn(12).astype(np.float32)
        actions = [agent.select_action(state, deterministic=True)[0] for _ in range(10)]
        assert len(set(actions)) == 1

    def test_get_value(self, agent):
        state = np.random.randn(12).astype(np.float32)
        value = agent.get_value(state)
        assert isinstance(value, float)
        assert np.isfinite(value)

    def test_update_returns_metrics(self, agent):
        batch = 16
        states = np.random.randn(batch, 12).astype(np.float32)
        actions = np.random.randint(0, 8, size=batch)
        rewards = np.random.randn(batch).astype(np.float32)
        old_log_probs = np.random.randn(batch).astype(np.float32)
        advantages = np.random.randn(batch).astype(np.float32)

        metrics = agent.update(
            states, actions, rewards, old_log_probs, advantages, epochs=2
        )
        assert "policy_loss" in metrics
        assert "value_loss" in metrics
        assert "entropy" in metrics
        assert metrics["training_steps"] == 2

    def test_update_changes_policy(self, agent):
        state = np.random.randn(12).astype(np.float32)
        _, probs_before = agent.select_action(state, deterministic=True)

        batch = 32
        states = np.tile(state, (batch, 1))
        actions = np.full(batch, 1, dtype=np.int64)
        rewards = np.ones(batch, dtype=np.float32)
        old_log_probs = np.log(np.full(batch, 0.125, dtype=np.float32))
        advantages = np.ones(batch, dtype=np.float32)
        agent.update(states, actions, rewards, old_log_probs, advantages, epochs=20)

        _, probs_after = agent.select_action(state, deterministic=True)
        assert not np.allclose(probs_before, probs_after, atol=1e-3)

    def test_save_and_load_model(self, agent):
        state = np.random.randn(12).astype(np.float32)
        _, probs_before = agent.select_action(state, deterministic=True)

        assert agent.save_model() is True

        from agent.ppo_agent import PPOAgent

        new_agent = PPOAgent(state_dim=12, action_dim=8, model_path=agent.model_path)
        assert new_agent.load_model() is True

        _, probs_after = new_agent.select_action(state, deterministic=True)
        np.testing.assert_allclose(probs_before, probs_after, atol=1e-5)

    def test_save_creates_meta_json(self, agent):
        agent.save_model()
        meta_path = os.path.join(agent.model_path, "meta.json")
        assert os.path.exists(meta_path)
        with open(meta_path) as f:
            meta = json.load(f)
        assert meta["state_dim"] == 12
        assert meta["action_dim"] == 8
        assert "version" in meta

    def test_load_nonexistent_returns_false(self, agent):
        agent.model_path = tempfile.mkdtemp()
        assert agent.load_model() is False

    def test_save_model_custom_path(self, agent):
        custom_path = tempfile.mkdtemp()
        assert agent.save_model(path=custom_path) is True
        assert os.path.exists(os.path.join(custom_path, "policy_net.pt"))
        assert os.path.exists(os.path.join(custom_path, "value_net.pt"))

    def test_load_restores_metadata(self, agent):
        agent._version = "2.0.0"
        agent._training_steps = 42
        agent.save_model()

        from agent.ppo_agent import PPOAgent

        new_agent = PPOAgent(state_dim=12, action_dim=8, model_path=agent.model_path)
        new_agent.load_model()
        assert new_agent.get_version() == "2.0.0"
        assert new_agent._training_steps == 42

    def test_torch_not_available_raises(self):
        """Verify the guard in __init__ when torch is absent."""
        from agent import ppo_agent as ppo_mod

        original = ppo_mod.torch
        ppo_mod.torch = None
        try:
            with pytest.raises(ImportError):
                ppo_mod.PPOAgent(state_dim=12, action_dim=8)
        finally:
            ppo_mod.torch = original


# ===================================================================
# store_decision helper
# ===================================================================


class TestStoreDecision:
    def test_stores_decision_and_increments_counter(self, mock_redis):
        decision = {"decision_id": "drl_test_001", "action": "DENY", "action_code": 1}
        context = {
            "threat_score": 0.9,
            "source_ip": "1.2.3.4",
            "dest_port": 22,
            "protocol": "TCP",
        }
        drl_app.store_decision(decision, context)
        mock_redis.set.assert_called_once()
        stored = mock_redis.set.call_args[0][1]
        parsed = json.loads(stored)
        assert parsed["decision_id"] == "drl_test_001"
        assert "state" in parsed
        mock_redis.expire.assert_called_once()
        mock_redis.incr.assert_called_with("drl:total_decisions")

    def test_redis_error_swallowed(self, mock_redis):
        mock_redis.set.side_effect = _redis_mod.ConnectionError("down")
        drl_app.store_decision(
            {"decision_id": "drl_err", "action_code": 0},
            {"threat_score": 0.5},
        )
