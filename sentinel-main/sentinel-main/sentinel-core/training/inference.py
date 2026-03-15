"""
SageMaker inference entry point for SENTINEL threat detection model.

SageMaker calls:
    model_fn(model_dir)         → loaded model object
    input_fn(body, content_type) → parsed input data
    predict_fn(data, model)     → raw prediction output
    output_fn(prediction, accept) → serialised HTTP response

The hosted model is a PyTorch-based ensemble exported by train_all.py.
Model artefacts layout inside model_dir (unpacked from model.tar.gz):
    model.pt         -- PyTorch state dict (LSTM / Autoencoder)
    xgboost.json     -- XGBoost booster (JSON format)
    iso_forest.pkl   -- Isolation Forest (joblib)
    autoencoder.pkl  -- Autoencoder (joblib, optional)
    scaler.pkl       -- StandardScaler fitted on training data
    label_map.json   -- index → threat-category label mapping
"""

from __future__ import annotations

import io
import json
import logging
import os
import pickle
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

N_FEATURES = int(os.environ.get("MODEL_N_FEATURES", "78"))
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.75"))
CONTENT_TYPE_JSON = "application/json"


# ── Model container ───────────────────────────────────────────────────────────

class ThreatDetectorEnsemble:
    """Lightweight inference wrapper loaded in model_fn."""

    def __init__(self):
        self.xgb_model = None
        self.lstm_model = None
        self.iso_forest = None
        self.scaler = None
        self.label_map: Dict[int, str] = {}

    def predict(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Return a list of per-sample threat assessments."""
        results = []
        for row in features:
            row_2d = row.reshape(1, -1)
            scores: Dict[str, float] = {}

            if self.scaler is not None:
                try:
                    row_2d = self.scaler.transform(row_2d)
                except Exception:  # noqa: BLE001
                    pass

            if self.xgb_model is not None:
                try:
                    import xgboost as xgb
                    dm = xgb.DMatrix(row_2d)
                    proba = self.xgb_model.predict(dm)[0]
                    if isinstance(proba, (list, np.ndarray)) and len(proba) > 1:
                        scores["xgboost"] = float(1.0 - proba[0])
                        class_idx = int(np.argmax(proba))
                    else:
                        scores["xgboost"] = float(proba)
                        class_idx = 1 if float(proba) > CONFIDENCE_THRESHOLD else 0
                    predicted_label = self.label_map.get(class_idx, "unknown")
                except Exception as exc:  # noqa: BLE001
                    logger.warning("XGBoost inference failed: %s", exc)
                    predicted_label = "unknown"
            else:
                predicted_label = "unknown"

            if self.iso_forest is not None:
                try:
                    iso_score = float(self.iso_forest.score_samples(row_2d)[0])
                    # Isolation Forest: lower score = more anomalous
                    scores["isolation_forest"] = float(np.clip(-iso_score, 0, 1))
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Isolation Forest inference failed: %s", exc)

            if self.lstm_model is not None:
                try:
                    import torch
                    tensor = torch.FloatTensor(row_2d).unsqueeze(0)
                    with torch.no_grad():
                        logits = self.lstm_model(tensor)
                        proba = torch.softmax(logits, dim=-1).numpy()[0]
                    scores["lstm"] = float(1.0 - proba[0])
                except Exception as exc:  # noqa: BLE001
                    logger.warning("LSTM inference failed: %s", exc)

            # Ensemble: weighted average of available scores
            if scores:
                weights = {"xgboost": 0.5, "lstm": 0.3, "isolation_forest": 0.2}
                total_weight = sum(weights.get(k, 0.1) for k in scores)
                ensemble_score = sum(
                    v * weights.get(k, 0.1) / total_weight
                    for k, v in scores.items()
                )
            else:
                ensemble_score = 0.0

            is_threat = ensemble_score >= CONFIDENCE_THRESHOLD
            results.append({
                "is_threat": is_threat,
                "confidence": round(ensemble_score, 4),
                "threat_type": predicted_label if is_threat else "benign",
                "model_scores": scores,
            })

        return results


# ── SageMaker handler functions ───────────────────────────────────────────────

def model_fn(model_dir: str) -> ThreatDetectorEnsemble:
    """Load all model artefacts from *model_dir* and return the ensemble."""
    ensemble = ThreatDetectorEnsemble()
    logger.info("Loading SENTINEL threat detector from %s", model_dir)

    # Label map
    label_map_path = os.path.join(model_dir, "label_map.json")
    if os.path.exists(label_map_path):
        with open(label_map_path, "r") as f:
            raw = json.load(f)
        ensemble.label_map = {int(k): v for k, v in raw.items()}
        logger.info("Loaded label map: %d classes", len(ensemble.label_map))

    # StandardScaler
    scaler_path = os.path.join(model_dir, "scaler.pkl")
    if os.path.exists(scaler_path):
        with open(scaler_path, "rb") as f:
            ensemble.scaler = pickle.load(f)
        logger.info("Loaded StandardScaler")

    # XGBoost
    xgb_path = os.path.join(model_dir, "xgboost.json")
    if os.path.exists(xgb_path):
        try:
            import xgboost as xgb
            booster = xgb.Booster()
            booster.load_model(xgb_path)
            ensemble.xgb_model = booster
            logger.info("Loaded XGBoost booster")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load XGBoost: %s", exc)

    # Isolation Forest
    iso_path = os.path.join(model_dir, "iso_forest.pkl")
    if os.path.exists(iso_path):
        with open(iso_path, "rb") as f:
            ensemble.iso_forest = pickle.load(f)
        logger.info("Loaded Isolation Forest")

    # LSTM (PyTorch)
    lstm_path = os.path.join(model_dir, "model.pt")
    if os.path.exists(lstm_path):
        try:
            import torch
            ensemble.lstm_model = torch.load(lstm_path, map_location="cpu")
            ensemble.lstm_model.eval()
            logger.info("Loaded LSTM model")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load LSTM: %s", exc)

    if not any([ensemble.xgb_model, ensemble.iso_forest, ensemble.lstm_model]):
        logger.warning(
            "No model artefacts found in %s — predictions will be empty", model_dir
        )

    return ensemble


def input_fn(request_body: bytes, content_type: str = CONTENT_TYPE_JSON) -> np.ndarray:
    """Deserialise the request body into a (N, features) numpy array."""
    if content_type == CONTENT_TYPE_JSON:
        data = json.loads(request_body)
        if isinstance(data, dict) and "instances" in data:
            features = data["instances"]
        elif isinstance(data, list):
            features = data
        else:
            raise ValueError(
                f"Expected JSON with 'instances' key or a list; got {type(data)}"
            )
        return np.array(features, dtype=np.float32)

    if content_type in ("text/csv", "application/x-npy"):
        buf = io.BytesIO(request_body if isinstance(request_body, bytes) else request_body.encode())
        return np.load(buf) if content_type == "application/x-npy" else np.genfromtxt(buf, delimiter=",", dtype=np.float32)

    raise ValueError(f"Unsupported content type: {content_type}")


def predict_fn(
    data: np.ndarray, model: ThreatDetectorEnsemble
) -> List[Dict[str, Any]]:
    """Run the ensemble model on *data* and return predictions."""
    if data.ndim == 1:
        data = data.reshape(1, -1)
    return model.predict(data)


def output_fn(prediction: List[Dict[str, Any]], accept: str = CONTENT_TYPE_JSON) -> bytes:
    """Serialise model output for the HTTP response."""
    return json.dumps({"predictions": prediction}).encode("utf-8")
