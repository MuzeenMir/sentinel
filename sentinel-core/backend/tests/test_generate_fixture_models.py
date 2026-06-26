"""Unit coverage for the fixture-model generator.

The generator (``training/generate_fixture_models.py``) exists so the
model-loading / prediction integration suite
(``backend/tests/test_integration_pipeline.py``) actually executes instead of
skipping on a missing ``trained_models/`` directory (audit SUB-05).

This test is self-contained: it generates into a pytest ``tmp_path`` (no working
tree pollution), then asserts the on-disk artefact layout each detector's
``load_model()`` expects is present, the training report is valid, and every
detector loads + predicts from the generated artefacts. It is gated on the ML
stack the same way the integration suite is, so it runs wherever those deps are
installed (CI ``unit-backend``) and skips cleanly otherwise.
"""

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
_AI_ENGINE = _BACKEND_ROOT / "ai-engine"
_GENERATOR = _BACKEND_ROOT.parent / "training" / "generate_fixture_models.py"

try:
    import joblib  # noqa: F401
    import sklearn  # noqa: F401
    import torch  # noqa: F401
    import xgboost  # noqa: F401

    HAVE_ML_STACK = True
except ImportError:
    HAVE_ML_STACK = False

pytestmark = pytest.mark.skipif(
    not HAVE_ML_STACK,
    reason="ML stack (joblib/sklearn/torch/xgboost) not installed",
)

EXPECTED_KEYS = {"detector", "is_threat", "confidence", "threat_type"}


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_fixture_models", _GENERATOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generates_full_artifact_layout(tmp_path):
    gen = _load_generator()
    out = Path(gen.generate(tmp_path / "trained_models"))

    # Per-detector artefacts, named exactly as each load_model() reads them.
    assert (out / "xgboost" / "xgboost_model.joblib").exists()
    assert (out / "isolation_forest" / "isolation_forest.joblib").exists()
    assert (out / "autoencoder" / "autoencoder_model.pt").exists()
    assert (out / "lstm" / "lstm_model.pt").exists()


def test_training_report_is_valid(tmp_path):
    gen = _load_generator()
    out = Path(gen.generate(tmp_path / "trained_models"))

    report_path = out / "training_report.json"
    assert report_path.exists()
    report = json.loads(report_path.read_text())
    # Matches what test_integration_pipeline.py::test_training_report_valid asserts.
    assert "metrics" in report
    assert "models_trained" in report
    assert len(report["models_trained"]) >= 4


def test_generated_models_load_and_predict(tmp_path):
    gen = _load_generator()
    out = Path(gen.generate(tmp_path / "trained_models"))

    sys.path.insert(0, str(_AI_ENGINE))
    from models.supervised.xgboost_detector import XGBoostDetector
    from models.unsupervised.autoencoder import AutoencoderDetector
    from models.unsupervised.isolation_forest import IsolationForestDetector

    features = np.random.RandomState(0).randn(50).astype(np.float32)
    for detector_cls, subdir in (
        (XGBoostDetector, "xgboost"),
        (IsolationForestDetector, "isolation_forest"),
        (AutoencoderDetector, "autoencoder"),
    ):
        det = detector_cls(model_path=str(out / subdir))
        assert det.is_ready(), f"{subdir} did not load to a ready state"
        result = det.predict(features)
        assert EXPECTED_KEYS.issubset(result.keys())
        assert isinstance(result["is_threat"], bool)
        assert 0.0 <= result["confidence"] <= 1.0
