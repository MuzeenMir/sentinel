"""
Autoencoder-based anomaly detector for unsupervised threat detection.

Learns to reconstruct normal traffic patterns.  Anomalies (attacks) produce
high reconstruction error because they deviate from the learned distribution
of benign traffic.
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


class _AutoencoderNetwork(nn.Module):
    """Symmetric encoder-decoder with batch normalisation."""

    def __init__(self, input_dim: int, latent_dim: int, dropout: float = 0.2):
        super().__init__()
        h1 = max(input_dim // 2, latent_dim * 2)
        h2 = max(input_dim // 4, latent_dim)

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, h1),
            nn.BatchNorm1d(h1),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(h1, h2),
            nn.BatchNorm1d(h2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(h2, latent_dim),
        )

        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, h2),
            nn.BatchNorm1d(h2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(h2, h1),
            nn.BatchNorm1d(h1),
            nn.ReLU(),
            nn.Linear(h1, input_dim),
        )

    def forward(self, x: "torch.Tensor") -> "torch.Tensor":
        return self.decoder(self.encoder(x))

    def encode(self, x: "torch.Tensor") -> "torch.Tensor":
        return self.encoder(x)


# ──────────────────────────────────────────────────────────────────────
# Detector wrapper
# ──────────────────────────────────────────────────────────────────────


class AutoencoderDetector(BaseDetector):
    """
    Autoencoder-based anomaly detector.

    Samples whose reconstruction error exceeds a learned threshold (set
    from the training-data error distribution) are flagged as threats.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "input_dim": 50,
        "latent_dim": 16,
        "dropout": 0.2,
        "learning_rate": 1e-3,
        "batch_size": 128,
        "max_epochs": 100,
        "threshold_percentile": 95.0,
    }

    def __init__(
        self,
        model_path: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(model_path)

        if torch is None:
            raise ImportError("PyTorch is required for AutoencoderDetector")

        self.config: Dict[str, Any] = {**self.DEFAULT_CONFIG, **(config or {})}
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model: Optional[_AutoencoderNetwork] = None
        self._threshold: float = 0.5
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None

        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            self._initialize_default_model()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _initialize_default_model(self) -> None:
        logger.info("Initializing default autoencoder model on %s", self.device)
        self.model = self._build_network().to(self.device)
        self.model.eval()
        self._is_ready = True
        self._version = "1.0.0-default"
        self._last_updated = datetime.utcnow().isoformat()
        logger.info("Default autoencoder model initialized (untrained)")

    def _build_network(self) -> "_AutoencoderNetwork":
        return _AutoencoderNetwork(
            input_dim=self.config["input_dim"],
            latent_dim=self.config["latent_dim"],
            dropout=self.config["dropout"],
        )

    def load_model(self) -> bool:
        try:
            model_file = os.path.join(self.model_path, "autoencoder_model.pt")
            meta_file = os.path.join(self.model_path, "autoencoder_meta.json")

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
                self._threshold = meta.get("threshold", 0.5)
                if meta.get("mean") is not None:
                    self._mean = np.array(meta["mean"], dtype=np.float32)
                if meta.get("std") is not None:
                    self._std = np.array(meta["std"], dtype=np.float32)

            self.model = self._build_network().to(self.device)
            state_dict = torch.load(
                model_file, map_location=self.device, weights_only=True
            )
            self.model.load_state_dict(state_dict)
            self.model.eval()

            self._is_ready = True
            logger.info("Autoencoder model loaded from %s", self.model_path)
            return True

        except Exception as exc:
            logger.error("Failed to load autoencoder model: %s", exc)
            self._initialize_default_model()
            return True

    def save_model(self, path: Optional[str] = None) -> bool:
        try:
            save_path = path or self.model_path
            os.makedirs(save_path, exist_ok=True)

            torch.save(
                self.model.state_dict(),
                os.path.join(save_path, "autoencoder_model.pt"),
            )

            meta = {
                "version": self._version,
                "last_updated": datetime.utcnow().isoformat(),
                "metrics": self._metrics,
                "config": self.config,
                "threshold": self._threshold,
                "mean": self._mean.tolist() if self._mean is not None else None,
                "std": self._std.tolist() if self._std is not None else None,
                "device": str(self.device),
            }
            with open(os.path.join(save_path, "autoencoder_meta.json"), "w") as fh:
                json.dump(meta, fh, indent=2)

            logger.info("Autoencoder model saved to %s", save_path)
            return True

        except Exception as exc:
            logger.error("Failed to save autoencoder model: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize(self, features: np.ndarray) -> np.ndarray:
        if self._mean is not None and self._std is not None:
            safe_std = np.where(self._std < 1e-8, 1.0, self._std)
            return (features - self._mean) / safe_std
        return features

    def _reconstruction_error(self, features: np.ndarray) -> np.ndarray:
        """Per-sample MSE between input and reconstruction."""
        normalized = self._normalize(features)
        if normalized.ndim == 1:
            normalized = normalized.reshape(1, -1)

        tensor = torch.tensor(normalized, dtype=torch.float32, device=self.device)

        with torch.no_grad():
            self.model.eval()
            reconstructed = self.model(tensor)
            mse = torch.mean((tensor - reconstructed) ** 2, dim=-1)

        return mse.cpu().numpy()

    def _error_to_confidence(self, error: float) -> float:
        """Map reconstruction error to a 0-1 confidence for the anomaly flag."""
        if error > self._threshold:
            return min(error / (self._threshold * 2), 1.0)
        return max(1.0 - error / max(self._threshold, 1e-8), 0.0)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")

        features = self._validate_features(features)
        if features.ndim == 1:
            features = features.reshape(1, -1)

        try:
            error = float(self._reconstruction_error(features)[0])
            is_anomaly = error > self._threshold

            return {
                "detector": "autoencoder",
                "is_threat": bool(is_anomaly),
                "confidence": self._error_to_confidence(error),
                "threat_type": (
                    ThreatCategory.UNKNOWN if is_anomaly else ThreatCategory.BENIGN
                ),
                "reconstruction_error": error,
                "details": {
                    "threshold": self._threshold,
                    "error_ratio": error / max(self._threshold, 1e-8),
                },
            }

        except Exception as exc:
            logger.error("Autoencoder prediction error: %s", exc)
            return {
                "detector": "autoencoder",
                "is_threat": False,
                "confidence": 0.0,
                "threat_type": ThreatCategory.UNKNOWN,
                "reconstruction_error": 0.0,
                "details": {"error": str(exc)},
            }

    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")

        features = self._validate_features(features)
        if features.ndim == 1:
            features = features.reshape(1, -1)

        try:
            errors = self._reconstruction_error(features)
            results: List[Dict[str, Any]] = []
            for err in errors:
                err_f = float(err)
                is_anomaly = err_f > self._threshold
                results.append(
                    {
                        "detector": "autoencoder",
                        "is_threat": bool(is_anomaly),
                        "confidence": self._error_to_confidence(err_f),
                        "threat_type": (
                            ThreatCategory.UNKNOWN
                            if is_anomaly
                            else ThreatCategory.BENIGN
                        ),
                        "reconstruction_error": err_f,
                    }
                )
            return results

        except Exception as exc:
            logger.error("Autoencoder batch prediction error: %s", exc)
            return [
                {
                    "detector": "autoencoder",
                    "is_threat": False,
                    "confidence": 0.0,
                    "threat_type": ThreatCategory.UNKNOWN,
                    "error": str(exc),
                }
                for _ in range(len(features))
            ]

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Train on (predominantly normal) traffic data.

        The autoencoder learns the distribution of *X*; *y* is ignored
        (unsupervised).  The anomaly threshold is set at the configured
        percentile of training reconstruction error.
        """
        logger.info("Training autoencoder model …")
        X = self._validate_features(X)

        self._mean = np.mean(X, axis=0).astype(np.float32)
        self._std = np.std(X, axis=0).astype(np.float32)
        X_norm = self._normalize(X)

        self.config["input_dim"] = X.shape[1]
        self.model = self._build_network().to(self.device)
        self.model.train()

        optimizer = torch.optim.Adam(
            self.model.parameters(), lr=self.config["learning_rate"]
        )
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, patience=5, factor=0.5
        )
        criterion = nn.MSELoss()

        X_t = torch.tensor(X_norm, dtype=torch.float32, device=self.device)
        loader = td.DataLoader(
            td.TensorDataset(X_t),
            batch_size=self.config["batch_size"],
            shuffle=True,
        )

        best_loss = float("inf")
        patience_ctr = 0
        epochs_done = 0

        for epoch in range(self.config["max_epochs"]):
            epoch_loss = 0.0
            total = 0
            for (batch_x,) in loader:
                optimizer.zero_grad()
                loss = criterion(self.model(batch_x), batch_x)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * batch_x.size(0)
                total += batch_x.size(0)

            avg_loss = epoch_loss / total
            scheduler.step(avg_loss)
            epochs_done = epoch + 1

            if avg_loss < best_loss:
                best_loss = avg_loss
                patience_ctr = 0
            else:
                patience_ctr += 1
                if patience_ctr >= 10:
                    logger.info("Early stopping at epoch %d", epochs_done)
                    break

        self.model.eval()

        errors = self._reconstruction_error(X)
        self._threshold = float(
            np.percentile(errors, self.config["threshold_percentile"])
        )

        self._metrics = {
            "n_samples": len(X),
            "n_features": X.shape[1],
            "final_loss": float(best_loss),
            "threshold": self._threshold,
            "mean_reconstruction_error": float(np.mean(errors)),
            "std_reconstruction_error": float(np.std(errors)),
            "epochs_trained": epochs_done,
        }
        self._is_ready = True
        self._last_updated = datetime.utcnow().isoformat()

        logger.info("Autoencoder training complete. Metrics: %s", self._metrics)
        return self._metrics
