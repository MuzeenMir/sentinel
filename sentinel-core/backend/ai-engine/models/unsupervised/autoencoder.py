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
    """Plain symmetric encoder-decoder (no BatchNorm).

    BatchNorm is deliberately excluded: its running statistics, computed
    over the benign training distribution, collapse the variance of the
    error signal at eval time and let attack samples reconstruct almost
    as well as benign ones. Dropping BN restores the gap in
    reconstruction error that a downstream threshold can actually use.
    """

    def __init__(self, input_dim: int, latent_dim: int, dropout: float = 0.2):
        super().__init__()
        h1 = max(input_dim // 2, latent_dim * 2)
        h2 = max(input_dim // 4, latent_dim)

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, h1),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(h1, h2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(h2, latent_dim),
        )

        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, h2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(h2, h1),
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
            try:
                self.model.load_state_dict(state_dict)
            except RuntimeError as load_err:
                # Old checkpoints were trained with BatchNorm layers and
                # therefore include `running_mean`/`running_var` keys that
                # the current no-BN architecture does not declare. Fall
                # back to a fresh model but make the mismatch impossible
                # to miss in the logs so operators retrain rather than
                # silently running an untrained detector in production.
                logger.error(
                    "Autoencoder state_dict mismatch — this checkpoint "
                    "predates the BatchNorm removal. Retrain with "
                    "`train_all.py --force --models autoencoder`. "
                    "Details: %s",
                    load_err,
                )
                self._initialize_default_model()
                return False
            self.model.eval()

            self._is_ready = True
            logger.info("Autoencoder model loaded from %s", self.model_path)
            return True

        except Exception as exc:
            logger.error("Failed to load autoencoder model: %s", exc)
            self._initialize_default_model()
            return False

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

    # Hard cap on per-feature standardised values. A handful of extreme
    # outliers in CIC-IDS2018 (e.g. gigantic flow-duration or byte-count
    # columns) otherwise push normalised inputs into the hundreds of
    # sigmas, which the decoder cannot reconstruct — one such sample can
    # dominate the reconstruction-error std and make FPR-based threshold
    # calibration useless.
    _NORM_CLIP = 10.0

    def _normalize(self, features: np.ndarray) -> np.ndarray:
        if self._mean is not None and self._std is not None:
            safe_std = np.where(self._std < 1e-8, 1.0, self._std)
            out = (features - self._mean) / safe_std
        else:
            out = features
        return np.clip(out, -self._NORM_CLIP, self._NORM_CLIP)

    def _reconstruction_error(
        self, features: np.ndarray, chunk_size: int = 8192
    ) -> np.ndarray:
        """Per-sample MSE between input and reconstruction.

        Processes the input in CPU-sized chunks so that GPU memory stays
        bounded regardless of dataset size.  Each chunk is normalised
        lazily to avoid duplicating the full array on CPU as well.
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        n = features.shape[0]
        errors = np.empty(n, dtype=np.float32)

        self.model.eval()
        with torch.no_grad():
            for start in range(0, n, chunk_size):
                end = min(start + chunk_size, n)
                chunk_np = self._normalize(features[start:end])
                chunk = torch.as_tensor(
                    chunk_np, dtype=torch.float32, device=self.device
                )
                reconstructed = self.model(chunk)
                mse = torch.mean((chunk - reconstructed) ** 2, dim=-1)
                errors[start:end] = mse.detach().cpu().numpy()
                del chunk, reconstructed, mse

        return errors

    def _error_to_confidence(self, error: float) -> float:
        """Map reconstruction error to a 0-1 confidence for the anomaly flag."""
        if error > self._threshold:
            return min(error / (self._threshold * 2), 1.0)
        return max(1.0 - error / max(self._threshold, 1e-8), 0.0)

    def calibrate_threshold(
        self,
        X_benign: np.ndarray,
        X_attack: np.ndarray,
        target_fpr: float = 0.01,
    ) -> float:
        """
        Calibrate the anomaly threshold against labelled validation data.

        Picks a threshold that maximises Youden's J (TPR − FPR) while
        respecting a hard cap on FPR. Falls back to the legacy
        percentile-based threshold when the label arrays are too small to
        sweep.

        Why not just a percentile of benign errors?
        When the benign error distribution is heavy-tailed (outlier flows
        that genuinely look unusual but aren't malicious), fixing the
        threshold at the (1 − target_fpr) percentile drags it above the
        bulk of the attack distribution and collapses recall — exactly
        the failure mode that produced F1 ≈ 0.055 on the last run.
        """
        benign_errors = self._reconstruction_error(X_benign)
        attack_errors = self._reconstruction_error(X_attack)

        if len(benign_errors) < 100 or len(attack_errors) < 100:
            # Not enough data for a meaningful ROC sweep — fall back.
            self._threshold = float(
                np.percentile(benign_errors, (1.0 - target_fpr) * 100)
            )
        else:
            self._threshold = self._roc_optimal_threshold(
                benign_errors, attack_errors, target_fpr
            )

        detection_rate = float(np.mean(attack_errors > self._threshold))
        actual_fpr = float(np.mean(benign_errors > self._threshold))

        logger.info(
            "Calibrated threshold=%.6f  detection_rate=%.4f  fpr=%.4f",
            self._threshold,
            detection_rate,
            actual_fpr,
        )

        self._metrics["calibrated_threshold"] = self._threshold
        self._metrics["calibrated_detection_rate"] = detection_rate
        self._metrics["calibrated_fpr"] = actual_fpr
        return self._threshold

    @staticmethod
    def _roc_optimal_threshold(
        benign_errors: np.ndarray,
        attack_errors: np.ndarray,
        fpr_cap: float,
    ) -> float:
        """
        Sweep candidate thresholds drawn from the benign error quantiles
        and pick the one that maximises ``TPR − FPR`` subject to
        ``FPR ≤ fpr_cap``. If no candidate meets the cap we fall back to
        the tightest FPR threshold we can produce from the benign tail.
        """
        # Sweep candidates from the benign distribution; concentrate the
        # candidates in the upper tail where the decision actually lives.
        q = np.concatenate(
            [
                np.linspace(0.50, 0.95, 46),
                np.linspace(0.951, 1.0, 50),
            ]
        )
        candidates = np.quantile(benign_errors, q)
        # Deduplicate and sort so downstream sweeps are monotone.
        candidates = np.unique(candidates)

        best_threshold = float(candidates[-1])
        best_j = -np.inf
        feasible_found = False

        for thr in candidates:
            thr_f = float(thr)
            tpr = float(np.mean(attack_errors > thr_f))
            fpr = float(np.mean(benign_errors > thr_f))
            if fpr > fpr_cap:
                continue
            feasible_found = True
            j = tpr - fpr
            if j > best_j:
                best_j = j
                best_threshold = thr_f

        if not feasible_found:
            # No candidate hit the FPR cap (e.g. the benign tail is so
            # thin that even the max sample exceeds the cap). Use the
            # classic percentile as a last resort.
            best_threshold = float(np.percentile(benign_errors, (1.0 - fpr_cap) * 100))

        return best_threshold

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

        # Keep the full dataset on CPU; the DataLoader moves each batch
        # to the GPU inside the loop.  This avoids a one-shot multi-GB
        # allocation that would OOM on small GPUs (e.g. 4 GB cards) and
        # also frees the GPU for the post-training reconstruction pass.
        X_t = torch.as_tensor(X_norm, dtype=torch.float32)
        pin = self.device.type == "cuda"
        loader = td.DataLoader(
            td.TensorDataset(X_t),
            batch_size=self.config["batch_size"],
            shuffle=True,
            pin_memory=pin,
        )

        best_loss = float("inf")
        patience_ctr = 0
        epochs_done = 0
        max_epochs = self.config.get("epochs", self.config.get("max_epochs", 100))
        es_patience = self.config.get("early_stopping_patience", 10)

        for epoch in range(max_epochs):
            epoch_loss = 0.0
            total = 0
            for (batch_x,) in loader:
                batch_x = batch_x.to(self.device, non_blocking=pin)
                optimizer.zero_grad()
                loss = criterion(self.model(batch_x), batch_x)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * batch_x.size(0)
                total += batch_x.size(0)

            avg_loss = epoch_loss / total
            scheduler.step(avg_loss)
            epochs_done = epoch + 1

            if epochs_done % 5 == 0 or epochs_done == 1:
                logger.info(
                    "  Epoch %d/%d  loss=%.6f  best=%.6f  patience=%d/%d",
                    epochs_done,
                    max_epochs,
                    avg_loss,
                    best_loss,
                    patience_ctr,
                    es_patience,
                )

            if avg_loss < best_loss:
                best_loss = avg_loss
                patience_ctr = 0
            else:
                patience_ctr += 1
                if patience_ctr >= es_patience:
                    logger.info(
                        "Early stopping at epoch %d (patience=%d)",
                        epochs_done,
                        es_patience,
                    )
                    break

        self.model.eval()

        # Release the large training tensor / loader before the
        # post-training reconstruction pass so peak GPU memory stays low.
        del loader, X_t
        if self.device.type == "cuda":
            torch.cuda.empty_cache()

        errors = self._reconstruction_error(X)
        self._threshold = float(
            np.percentile(errors, self.config["threshold_percentile"])
        )

        # Report trimmed statistics so a handful of pathological
        # training samples don't distort the diagnostic numbers written
        # to the training report (previously: mean=0.25, std=202 because
        # a few rows had reconstruction errors in the thousands).
        trimmed = errors[errors <= np.percentile(errors, 99.5)]
        self._metrics = {
            "n_samples": len(X),
            "n_features": X.shape[1],
            "final_loss": float(best_loss),
            "threshold": self._threshold,
            "mean_reconstruction_error": float(np.mean(trimmed)),
            "std_reconstruction_error": float(np.std(trimmed)),
            "median_reconstruction_error": float(np.median(errors)),
            "p99_reconstruction_error": float(np.percentile(errors, 99.0)),
            "epochs_trained": epochs_done,
        }
        self._is_ready = True
        self._last_updated = datetime.utcnow().isoformat()

        logger.info("Autoencoder training complete. Metrics: %s", self._metrics)
        return self._metrics
