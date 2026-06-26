#!/usr/bin/env python3
"""Generate tiny, synthetic fixture models for the integration test suite.

The model-loading / prediction integration tests
(``backend/tests/test_integration_pipeline.py``) skip entirely when
``backend/ai-engine/trained_models/`` is empty — which it always is in a clean
checkout, since the repo ships real trained models out-of-band (audit SUB-05).

This script populates that directory with disposable fixtures: each detector is
constructed in its default (synthetic-init) mode and persisted via its own
``save_model()``, so the on-disk artefact layout is exactly what each
``load_model()`` reads back. These are NOT real detectors — they are fitted on a
handful of synthetic samples (or left as freshly-built networks) purely so the
load + predict code paths execute under test.

The artefacts are deliberately NOT committed: binaries would be corrupted by the
repo's LF normalisation, and trained models are distributed separately. CI runs
this right before the integration tests; locally, run it the same way:

    cd sentinel-core
    python -m training.generate_fixture_models           # default trained_models/
    python -m training.generate_fixture_models --out /tmp/fx
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_TRAINING_DIR = Path(__file__).resolve().parent
_SENTINEL_CORE = _TRAINING_DIR.parent
_AI_ENGINE = _SENTINEL_CORE / "backend" / "ai-engine"
_DEFAULT_OUT = _AI_ENGINE / "trained_models"

# ai-engine detectors import as ``models.*``; put the package root on sys.path.
if str(_AI_ENGINE) not in sys.path:
    sys.path.insert(0, str(_AI_ENGINE))

MODELS = ("xgboost", "isolation_forest", "autoencoder", "lstm")


def _build_xgboost(out: Path) -> None:
    # Small tree count keeps the synthetic fit fast and the artefact tiny;
    # the loaded model carries its own structure, so load_model is unaffected.
    from models.supervised.xgboost_detector import XGBoostDetector

    XGBoostDetector(params={"n_estimators": 20, "max_depth": 4}).save_model(
        str(out / "xgboost")
    )


def _build_isolation_forest(out: Path) -> None:
    from models.unsupervised.isolation_forest import IsolationForestDetector

    IsolationForestDetector(params={"n_estimators": 40}).save_model(
        str(out / "isolation_forest")
    )


def _build_autoencoder(out: Path) -> None:
    # Default config so the saved state_dict matches the architecture rebuilt on
    # load (an untrained network is sufficient for the load/predict contract).
    from models.unsupervised.autoencoder import AutoencoderDetector

    AutoencoderDetector().save_model(str(out / "autoencoder"))


def _build_lstm(out: Path) -> None:
    from models.supervised.lstm_sequence import LSTMSequenceDetector

    LSTMSequenceDetector().save_model(str(out / "lstm"))


_BUILDERS = {
    "xgboost": _build_xgboost,
    "isolation_forest": _build_isolation_forest,
    "autoencoder": _build_autoencoder,
    "lstm": _build_lstm,
}


def generate(out_dir: "os.PathLike[str] | str" = _DEFAULT_OUT) -> Path:
    """Build every fixture model under *out_dir* and write training_report.json.

    Returns the resolved output directory.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    for name in MODELS:
        _BUILDERS[name](out)

    report = {
        "generated_by": "training/generate_fixture_models.py",
        "synthetic_fixture": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "models_trained": list(MODELS),
        "metrics": {
            name: {
                "accuracy": 0.0,
                "f1": 0.0,
                "note": "synthetic fixture — not a real evaluation metric",
            }
            for name in MODELS
        },
    }
    (out / "training_report.json").write_text(json.dumps(report, indent=2))
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate disposable fixture ML models for integration tests."
    )
    parser.add_argument(
        "--out",
        default=str(_DEFAULT_OUT),
        help="output trained_models directory (default: ai-engine/trained_models)",
    )
    args = parser.parse_args(argv)

    out = generate(args.out)
    print(f"fixture models written to {out}")
    for name in MODELS:
        print(f"  - {name}/")
    print("  - training_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
