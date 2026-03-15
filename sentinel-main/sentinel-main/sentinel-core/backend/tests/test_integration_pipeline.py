"""
Integration tests for the Sentinel threat detection pipeline.

Validates that trained models can be loaded and produce sensible predictions
on synthetic traffic data.  These tests do NOT require Docker or external
services; they exercise the model-loading and prediction code paths directly.
"""
import os
import sys
import json
import pytest
import numpy as np
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup: ensure ai-engine modules are importable
# ---------------------------------------------------------------------------
_backend_root = Path(__file__).resolve().parent.parent
_ai_engine_root = _backend_root / "ai-engine"
_trained_models = _ai_engine_root / "trained_models"
sys.path.insert(0, str(_ai_engine_root))

HAVE_TRAINED_MODELS = _trained_models.exists() and any(_trained_models.iterdir())

try:
    import joblib  # noqa: F401
    import sklearn  # noqa: F401
    HAVE_ML_DEPS = True
except ImportError:
    HAVE_ML_DEPS = False

try:
    import torch  # noqa: F401
    HAVE_TORCH = True
except ImportError:
    HAVE_TORCH = False

MODELS_TESTABLE = HAVE_TRAINED_MODELS and HAVE_ML_DEPS


@pytest.fixture(scope="module")
def trained_models_dir():
    return str(_trained_models)


# ---------------------------------------------------------------------------
# Model loading tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not MODELS_TESTABLE, reason="trained_models/ or ML deps not present")
class TestModelLoading:
    """Verify each model loads from its artifact directory without errors."""

    def test_xgboost_loads(self, trained_models_dir):
        from models.supervised.xgboost_detector import XGBoostDetector
        d = XGBoostDetector(model_path=os.path.join(trained_models_dir, "xgboost"))
        assert d._is_ready

    def test_isolation_forest_loads(self, trained_models_dir):
        from models.unsupervised.isolation_forest import IsolationForestDetector
        d = IsolationForestDetector(model_path=os.path.join(trained_models_dir, "isolation_forest"))
        assert d._is_ready

    def test_autoencoder_loads(self, trained_models_dir):
        from models.unsupervised.autoencoder import AutoencoderDetector
        d = AutoencoderDetector(model_path=os.path.join(trained_models_dir, "autoencoder"))
        assert d._is_ready

    def test_lstm_loads(self, trained_models_dir):
        from models.supervised.lstm_sequence import LSTMSequenceDetector
        d = LSTMSequenceDetector(model_path=os.path.join(trained_models_dir, "lstm"))
        assert d._is_ready

    def test_training_report_valid(self, trained_models_dir):
        report_path = os.path.join(trained_models_dir, "training_report.json")
        assert os.path.exists(report_path)
        with open(report_path) as f:
            report = json.load(f)
        assert "metrics" in report
        assert "models_trained" in report
        assert len(report["models_trained"]) >= 4


# ---------------------------------------------------------------------------
# Prediction contract tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not MODELS_TESTABLE, reason="trained_models/ or ML deps not present")
class TestPredictionContract:
    """Verify each detector returns the expected dict schema."""

    EXPECTED_KEYS = {"detector", "is_threat", "confidence", "threat_type"}

    @pytest.fixture(scope="class")
    def sample_features(self):
        np.random.seed(42)
        return np.random.randn(50).astype(np.float32)

    @pytest.fixture(scope="class")
    def sample_batch(self):
        np.random.seed(42)
        return np.random.randn(16, 50).astype(np.float32)

    def test_xgboost_predict(self, trained_models_dir, sample_features):
        from models.supervised.xgboost_detector import XGBoostDetector
        d = XGBoostDetector(model_path=os.path.join(trained_models_dir, "xgboost"))
        result = d.predict(sample_features)
        assert self.EXPECTED_KEYS.issubset(result.keys())
        assert isinstance(result["is_threat"], bool)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_isolation_forest_predict(self, trained_models_dir, sample_features):
        from models.unsupervised.isolation_forest import IsolationForestDetector
        d = IsolationForestDetector(model_path=os.path.join(trained_models_dir, "isolation_forest"))
        result = d.predict(sample_features)
        assert self.EXPECTED_KEYS.issubset(result.keys())
        assert isinstance(result["is_threat"], bool)
        assert 0.0 <= result["confidence"] <= 1.0
        assert "anomaly_score" in result

    def test_autoencoder_predict(self, trained_models_dir, sample_features):
        from models.unsupervised.autoencoder import AutoencoderDetector
        d = AutoencoderDetector(model_path=os.path.join(trained_models_dir, "autoencoder"))
        result = d.predict(sample_features)
        assert self.EXPECTED_KEYS.issubset(result.keys())
        assert isinstance(result["is_threat"], bool)
        assert 0.0 <= result["confidence"] <= 1.0
        assert "reconstruction_error" in result

    def test_isolation_forest_batch(self, trained_models_dir, sample_batch):
        from models.unsupervised.isolation_forest import IsolationForestDetector
        d = IsolationForestDetector(model_path=os.path.join(trained_models_dir, "isolation_forest"))
        results = d.predict_batch(sample_batch)
        assert len(results) == len(sample_batch)
        for r in results:
            assert "is_threat" in r

    def test_autoencoder_batch(self, trained_models_dir, sample_batch):
        from models.unsupervised.autoencoder import AutoencoderDetector
        d = AutoencoderDetector(model_path=os.path.join(trained_models_dir, "autoencoder"))
        results = d.predict_batch(sample_batch)
        assert len(results) == len(sample_batch)
        for r in results:
            assert "is_threat" in r


# ---------------------------------------------------------------------------
# DRL environment sanity tests (no trained model needed)
# ---------------------------------------------------------------------------

class TestDRLEnvironment:
    """Validate the network security environment contract."""

    def test_env_reset_returns_valid_obs(self):
        sys.path.insert(0, str(_backend_root / "drl-engine"))
        from environment.network_env import NetworkSecurityEnv
        env = NetworkSecurityEnv(state_dim=12, action_dim=8)
        obs, info = env.reset()
        assert obs.shape == (12,)
        assert obs.dtype == np.float32

    def test_env_step_returns_5_tuple(self):
        sys.path.insert(0, str(_backend_root / "drl-engine"))
        from environment.network_env import NetworkSecurityEnv
        env = NetworkSecurityEnv(state_dim=12, action_dim=8)
        env.reset()
        obs, reward, terminated, truncated, info = env.step(0)
        assert obs.shape == (12,)
        assert isinstance(reward, float)
        assert isinstance(terminated, bool)
        assert isinstance(truncated, bool)
        assert isinstance(info, dict)

    def test_env_episode_terminates(self):
        sys.path.insert(0, str(_backend_root / "drl-engine"))
        from environment.network_env import NetworkSecurityEnv
        env = NetworkSecurityEnv(state_dim=12, action_dim=8)
        env._max_steps = 10
        env.reset()
        done = False
        steps = 0
        while not done:
            _, _, terminated, truncated, _ = env.step(0)
            done = terminated or truncated
            steps += 1
        assert steps == 10
