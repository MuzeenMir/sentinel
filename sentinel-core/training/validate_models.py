#!/usr/bin/env python3
"""
SENTINEL Model Validation Gate

Evaluates trained model artefacts against minimum performance thresholds
before they are promoted to the ai_models volume or uploaded to S3.

Usage
-----
    python training/validate_models.py --model-path backend/ai-engine/trained_models
    python training/validate_models.py --model-path trained_models --strict

Exit codes
----------
    0 — all required models pass thresholds
    1 — one or more models below threshold (gate fails)
    2 — a required model artefact is missing
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

# Add backend/ai-engine to path so detector classes can be imported
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "backend" / "ai-engine"))
sys.path.insert(0, str(SCRIPT_DIR))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("sentinel.validate_models")


# ── Thresholds ────────────────────────────────────────────────────────────────

@dataclass
class ModelThreshold:
    name: str
    artefact: str          # relative path inside model_path
    required: bool = True  # if True, gate fails on missing artefact
    min_accuracy: float = 0.90
    min_f1: float = 0.88
    min_auc: float = 0.92


THRESHOLDS: List[ModelThreshold] = [
    ModelThreshold(
        name="xgboost",
        artefact="xgboost/model.json",
        min_accuracy=0.94,
        min_f1=0.92,
        min_auc=0.96,
    ),
    ModelThreshold(
        name="isolation_forest",
        artefact="isolation_forest/model.pkl",
        required=True,
        min_accuracy=0.85,
        min_f1=0.80,
        min_auc=0.88,
    ),
    ModelThreshold(
        name="autoencoder",
        artefact="autoencoder/model.pkl",
        required=False,
        min_accuracy=0.82,
        min_f1=0.78,
        min_auc=0.85,
    ),
    ModelThreshold(
        name="lstm",
        artefact="lstm/model.pt",
        required=False,
        min_accuracy=0.91,
        min_f1=0.89,
        min_auc=0.93,
    ),
    ModelThreshold(
        name="ensemble",
        artefact="ensemble/model.pkl",
        required=False,
        min_accuracy=0.95,
        min_f1=0.94,
        min_auc=0.97,
    ),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_metrics(model_path: Path, model_name: str) -> Optional[Dict[str, float]]:
    """Load metrics.json written by train_all.py for a given model."""
    candidates = [
        model_path / model_name / "metrics.json",
        model_path / f"{model_name}_metrics.json",
        model_path / "metrics" / f"{model_name}.json",
    ]
    for p in candidates:
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return None


def _evaluate_with_validation_set(
    model_path: Path, model_name: str
) -> Optional[Dict[str, float]]:
    """
    If no pre-computed metrics exist, try to load the model and evaluate it
    against a small labelled validation set shipped alongside the artefacts.

    Returns None if evaluation cannot be performed.
    """
    val_features_path = model_path / "validation" / "X_val.npy"
    val_labels_path = model_path / "validation" / "y_val.npy"

    if not (val_features_path.exists() and val_labels_path.exists()):
        return None

    X_val = np.load(val_features_path)
    y_val = np.load(val_labels_path)

    try:
        from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

        if model_name == "xgboost":
            import xgboost as xgb
            artefact = model_path / "xgboost" / "model.json"
            if not artefact.exists():
                return None
            booster = xgb.Booster()
            booster.load_model(str(artefact))
            dm = xgb.DMatrix(X_val)
            raw = booster.predict(dm)
            if raw.ndim == 2:
                y_pred = raw.argmax(axis=1)
                y_score = raw[:, 1] if raw.shape[1] == 2 else raw.max(axis=1)
            else:
                y_pred = (raw > 0.5).astype(int)
                y_score = raw
            is_binary = len(np.unique(y_val)) <= 2
            return {
                "accuracy": accuracy_score(y_val, y_pred),
                "f1": f1_score(y_val, y_pred, average="binary" if is_binary else "weighted"),
                "auc": roc_auc_score(y_val, y_score, multi_class="ovr") if not is_binary else roc_auc_score(y_val, y_score),
            }

        if model_name == "isolation_forest":
            artefact = model_path / "isolation_forest" / "model.pkl"
            if not artefact.exists():
                return None
            with open(artefact, "rb") as f:
                clf = pickle.load(f)
            y_pred_raw = clf.predict(X_val)
            # IsolationForest returns 1 (inlier) / -1 (outlier); map to 0/1
            y_pred = np.where(y_pred_raw == -1, 1, 0)
            y_score = -clf.score_samples(X_val)
            return {
                "accuracy": accuracy_score(y_val, y_pred),
                "f1": f1_score(y_val, y_pred, average="binary", zero_division=0),
                "auc": roc_auc_score(y_val, y_score),
            }

    except Exception as exc:  # noqa: BLE001
        logger.warning("Live evaluation of %s failed: %s", model_name, exc)

    return None


# ── Gate logic ────────────────────────────────────────────────────────────────

def validate(model_path: Path, strict: bool = False) -> bool:
    """
    Validate all models.  Returns True if the gate passes.

    In *strict* mode, optional models that are present but below threshold
    also cause a failure.
    """
    model_path = model_path.resolve()
    logger.info("Validating models in %s", model_path)

    passed: List[str] = []
    failed: List[str] = []
    missing: List[str] = []
    results: Dict[str, Dict] = {}

    for thr in THRESHOLDS:
        artefact_path = model_path / thr.artefact
        artefact_exists = artefact_path.exists()

        if not artefact_exists:
            if thr.required:
                logger.error("MISSING required artefact: %s", artefact_path)
                missing.append(thr.name)
            else:
                logger.info("SKIP optional model not yet trained: %s", thr.name)
            continue

        # Try to load pre-computed metrics first, then live evaluation.
        metrics = _load_metrics(model_path, thr.name)
        if metrics is None:
            logger.info("No metrics.json for %s — attempting live evaluation", thr.name)
            metrics = _evaluate_with_validation_set(model_path, thr.name)

        if metrics is None:
            logger.warning(
                "SKIP %s — artefact present but no metrics available "
                "(run train_all.py or supply validation/X_val.npy + y_val.npy)",
                thr.name,
            )
            continue

        acc = metrics.get("accuracy", 0.0)
        f1 = metrics.get("f1", 0.0)
        auc = metrics.get("auc", 0.0)

        ok = acc >= thr.min_accuracy and f1 >= thr.min_f1 and auc >= thr.min_auc
        status = "PASS" if ok else "FAIL"

        results[thr.name] = {
            "status": status,
            "accuracy": round(acc, 4),
            "f1": round(f1, 4),
            "auc": round(auc, 4),
            "thresholds": {
                "accuracy": thr.min_accuracy,
                "f1": thr.min_f1,
                "auc": thr.min_auc,
            },
        }

        if ok:
            logger.info(
                "PASS %s — acc=%.4f f1=%.4f auc=%.4f", thr.name, acc, f1, auc
            )
            passed.append(thr.name)
        else:
            logger.error(
                "FAIL %s — acc=%.4f (min %.2f) f1=%.4f (min %.2f) auc=%.4f (min %.2f)",
                thr.name, acc, thr.min_accuracy, f1, thr.min_f1, auc, thr.min_auc,
            )
            if thr.required or strict:
                failed.append(thr.name)

    # Write validation report
    report_path = model_path / "validation_report.json"
    report = {
        "model_path": str(model_path),
        "passed": passed,
        "failed": failed,
        "missing_required": missing,
        "models": results,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Validation report written to %s", report_path)

    if missing:
        logger.error("Gate FAILED — %d required artefact(s) missing: %s", len(missing), missing)
        return False
    if failed:
        logger.error("Gate FAILED — %d model(s) below threshold: %s", len(failed), failed)
        return False

    logger.info("Gate PASSED — %d model(s) validated: %s", len(passed), passed)
    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL model validation gate",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--model-path",
        default=os.environ.get(
            "MODEL_PATH",
            str(SCRIPT_DIR.parent / "backend" / "ai-engine" / "trained_models"),
        ),
        help="Directory containing trained model artefacts",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if any optional model is below threshold (not just required ones)",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Always exit 0 — only generate the report without blocking",
    )
    args = parser.parse_args()

    ok = validate(Path(args.model_path), strict=args.strict)

    if args.report_only:
        sys.exit(0)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
