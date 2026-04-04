"""
LSTM sequence detector for temporal attack-pattern recognition.

Processes ordered sequences of network events through a bidirectional LSTM
with attention to detect multi-step attacks, lateral movement, and other
time-dependent threat patterns.
"""
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.utils.data as td
except ImportError:
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]
    td = None  # type: ignore[assignment]

from ..base import BaseDetector, ThreatCategory

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Network architecture
# ──────────────────────────────────────────────────────────────────────


class _LSTMNetwork(nn.Module):
    """Bidirectional LSTM with soft-attention and linear classification head."""

    def __init__(
        self,
        input_size: int,
        hidden_size: int,
        num_layers: int,
        num_classes: int,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
            bidirectional=True,
        )

        bidir_size = hidden_size * 2

        self.attention = nn.Sequential(
            nn.Linear(bidir_size, hidden_size),
            nn.Tanh(),
            nn.Linear(hidden_size, 1),
        )

        self.classifier = nn.Sequential(
            nn.Linear(bidir_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, num_classes),
        )

    def forward(self, x: "torch.Tensor") -> "torch.Tensor":
        lstm_out, _ = self.lstm(x)  # (B, T, 2H)
        attn_w = torch.softmax(self.attention(lstm_out), dim=1)  # (B, T, 1)
        context = torch.sum(attn_w * lstm_out, dim=1)  # (B, 2H)
        return self.classifier(context)  # (B, C)


# ──────────────────────────────────────────────────────────────────────
# Detector wrapper
# ──────────────────────────────────────────────────────────────────────

CATEGORY_MAP: Dict[int, ThreatCategory] = {
    i: cat for i, cat in enumerate(ThreatCategory)
}


class LSTMSequenceDetector(BaseDetector):
    """
    LSTM-based detector for temporal attack-pattern recognition.

    Consumes fixed-length sequences of network-event feature vectors and
    classifies them into :class:`ThreatCategory` classes.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "input_size": 50,
        "hidden_size": 128,
        "num_layers": 2,
        "num_classes": len(ThreatCategory),
        "dropout": 0.3,
        "sequence_length": 32,
        "learning_rate": 1e-3,
        "batch_size": 64,
        "max_epochs": 50,
    }

    def __init__(
        self,
        model_path: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(model_path)

        if torch is None:
            raise ImportError("PyTorch is required for LSTMSequenceDetector")

        self.config: Dict[str, Any] = {**self.DEFAULT_CONFIG, **(config or {})}
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model: Optional[_LSTMNetwork] = None

        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            self._initialize_default_model()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _initialize_default_model(self) -> None:
        logger.info("Initializing default LSTM model on %s", self.device)
        self.model = self._build_network().to(self.device)
        self.model.eval()
        self._is_ready = True
        self._version = "1.0.0-default"
        self._last_updated = datetime.utcnow().isoformat()
        logger.info("Default LSTM model initialized (untrained)")

    def _build_network(self) -> "_LSTMNetwork":
        return _LSTMNetwork(
            input_size=self.config["input_size"],
            hidden_size=self.config["hidden_size"],
            num_layers=self.config["num_layers"],
            num_classes=self.config["num_classes"],
            dropout=self.config["dropout"],
        )

    def load_model(self) -> bool:
        try:
            model_file = os.path.join(self.model_path, "lstm_model.pt")
            meta_file = os.path.join(self.model_path, "lstm_meta.json")

            if not os.path.exists(model_file):
                logger.warning("Model file not found at %s", model_file)
                self._initialize_default_model()
                return True

            if os.path.exists(meta_file):
                with open(meta_file, "r") as fh:
                    meta = json.load(fh)
                self.config.update(meta.get("config", {}))
                self._version = meta.get("version", "1.0.0")
                self._last_updated = meta.get("last_updated")
                self._metrics = meta.get("metrics", {})

            self.model = self._build_network().to(self.device)
            state_dict = torch.load(
                model_file, map_location=self.device, weights_only=True
            )
            self.model.load_state_dict(state_dict)
            self.model.eval()

            self._is_ready = True
            logger.info("LSTM model loaded from %s", self.model_path)
            return True

        except Exception as exc:
            logger.error("Failed to load LSTM model: %s", exc)
            self._initialize_default_model()
            return True

    def save_model(self, path: Optional[str] = None) -> bool:
        try:
            save_path = path or self.model_path
            os.makedirs(save_path, exist_ok=True)

            torch.save(
                self.model.state_dict(), os.path.join(save_path, "lstm_model.pt")
            )

            meta = {
                "version": self._version,
                "last_updated": datetime.utcnow().isoformat(),
                "metrics": self._metrics,
                "config": self.config,
                "device": str(self.device),
            }
            with open(os.path.join(save_path, "lstm_meta.json"), "w") as fh:
                json.dump(meta, fh, indent=2)

            logger.info("LSTM model saved to %s", save_path)
            return True

        except Exception as exc:
            logger.error("Failed to save LSTM model: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Input preparation
    # ------------------------------------------------------------------

    def _prepare_input(self, features: np.ndarray) -> "torch.Tensor":
        """Reshape arbitrary input into ``(batch, seq_len, input_size)``."""
        seq_len = self.config["sequence_length"]
        input_size = self.config["input_size"]

        if features.ndim == 1:
            total = seq_len * input_size
            if len(features) < total:
                padded = np.zeros(total, dtype=np.float32)
                padded[: len(features)] = features
                features = padded
            elif len(features) > total:
                features = features[:total]
            features = features.reshape(1, seq_len, input_size)

        elif features.ndim == 2:
            features = features[np.newaxis, :, :]

        return torch.tensor(features, dtype=torch.float32, device=self.device)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")

        features = self._validate_features(features)

        try:
            tensor = self._prepare_input(features)

            with torch.no_grad():
                logits = self.model(tensor)
                probs = torch.softmax(logits, dim=-1)[0].cpu().numpy()

            cls = int(np.argmax(probs))
            confidence = float(probs[cls])
            category = CATEGORY_MAP.get(cls, ThreatCategory.UNKNOWN)

            return {
                "detector": "lstm_sequence",
                "is_threat": category != ThreatCategory.BENIGN,
                "confidence": confidence,
                "threat_type": category,
                "predicted_class": cls,
                "probabilities": {
                    CATEGORY_MAP.get(i, ThreatCategory.UNKNOWN).value: float(p)
                    for i, p in enumerate(probs)
                },
            }

        except Exception as exc:
            logger.error("LSTM prediction error: %s", exc)
            return {
                "detector": "lstm_sequence",
                "is_threat": False,
                "confidence": 0.0,
                "threat_type": ThreatCategory.UNKNOWN,
                "details": {"error": str(exc)},
            }

    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")

        features = self._validate_features(features)

        if features.ndim == 2:
            return [self.predict(row) for row in features]

        try:
            tensor = torch.tensor(
                features, dtype=torch.float32, device=self.device
            )
            with torch.no_grad():
                logits = self.model(tensor)
                all_probs = torch.softmax(logits, dim=-1).cpu().numpy()

            results: List[Dict[str, Any]] = []
            for probs in all_probs:
                cls = int(np.argmax(probs))
                cat = CATEGORY_MAP.get(cls, ThreatCategory.UNKNOWN)
                results.append(
                    {
                        "detector": "lstm_sequence",
                        "is_threat": cat != ThreatCategory.BENIGN,
                        "confidence": float(probs[cls]),
                        "threat_type": cat,
                        "predicted_class": cls,
                    }
                )
            return results

        except Exception as exc:
            logger.error("LSTM batch prediction error: %s", exc)
            n = features.shape[0] if features.ndim >= 2 else 1
            return [
                {
                    "detector": "lstm_sequence",
                    "is_threat": False,
                    "confidence": 0.0,
                    "threat_type": ThreatCategory.UNKNOWN,
                    "error": str(exc),
                }
                for _ in range(n)
            ]

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Train the LSTM on labelled event sequences.

        *X* may be 2-D ``(n_samples, features)`` — reshaped into sequences —
        or 3-D ``(n_samples, seq_len, input_size)`` used directly.
        """
        if y is None:
            raise ValueError("LSTM requires labelled data (y must not be None)")

        logger.info("Training LSTM model …")
        X = self._validate_features(X)
        y = np.asarray(y, dtype=np.int64)

        X = self._reshape_for_training(X)

        num_classes = int(np.max(y) + 1)
        self.config["num_classes"] = num_classes

        self.model = self._build_network().to(self.device)
        self.model.train()

        optimizer = torch.optim.Adam(
            self.model.parameters(), lr=self.config["learning_rate"]
        )
        criterion = nn.CrossEntropyLoss()
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, patience=3, factor=0.5
        )

        X_t = torch.tensor(X, dtype=torch.float32, device=self.device)
        y_t = torch.tensor(y, dtype=torch.long, device=self.device)

        loader = td.DataLoader(
            td.TensorDataset(X_t, y_t),
            batch_size=self.config["batch_size"],
            shuffle=True,
        )

        best_loss = float("inf")
        patience_counter = 0
        epochs_done = 0
        avg_loss = 0.0
        accuracy = 0.0

        for epoch in range(self.config["max_epochs"]):
            epoch_loss = 0.0
            correct = 0
            total = 0

            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                logits = self.model(batch_x)
                loss = criterion(logits, batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                optimizer.step()

                epoch_loss += loss.item() * batch_x.size(0)
                correct += (torch.argmax(logits, dim=-1) == batch_y).sum().item()
                total += batch_y.size(0)

            avg_loss = epoch_loss / total
            accuracy = correct / total
            scheduler.step(avg_loss)
            epochs_done = epoch + 1

            if avg_loss < best_loss:
                best_loss = avg_loss
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= 7:
                    logger.info("Early stopping at epoch %d", epochs_done)
                    break

        self.model.eval()

        self._metrics = {
            "n_samples": len(y),
            "n_classes": num_classes,
            "final_loss": float(avg_loss),
            "final_accuracy": float(accuracy),
            "epochs_trained": epochs_done,
        }
        self._is_ready = True
        self._last_updated = datetime.utcnow().isoformat()

        logger.info("LSTM training complete. Metrics: %s", self._metrics)
        return self._metrics

    def _reshape_for_training(self, X: np.ndarray) -> np.ndarray:
        if X.ndim == 2:
            seq_len = self.config["sequence_length"]
            input_size = self.config["input_size"]
            total = seq_len * input_size
            if X.shape[1] == total:
                return X.reshape(-1, seq_len, input_size)
            self.config["input_size"] = X.shape[1]
            self.config["sequence_length"] = 1
            return X[:, np.newaxis, :]
        if X.ndim == 3:
            self.config["sequence_length"] = X.shape[1]
            self.config["input_size"] = X.shape[2]
            return X
        raise ValueError(f"Expected 2-D or 3-D input, got {X.ndim}-D")
