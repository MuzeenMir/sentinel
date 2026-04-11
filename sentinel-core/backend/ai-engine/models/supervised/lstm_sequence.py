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
        """Reshape arbitrary input into ``(batch, seq_len, input_size)``.

        A flat feature vector of length ``input_size`` (the typical
        ensemble-meta-feature case) is **replicated** across all
        ``sequence_length`` timesteps rather than zero-padded: the model was
        trained on sequences of real consecutive events, so feeding it 19
        zero timesteps produces garbage predictions. Replicating the single
        observation is the closest zero-context fallback that keeps every
        timestep on-distribution.
        """
        seq_len = self.config["sequence_length"]
        input_size = self.config["input_size"]

        if features.ndim == 1:
            total = seq_len * input_size
            if len(features) == input_size:
                features = np.broadcast_to(
                    features, (seq_len, input_size)
                ).reshape(1, seq_len, input_size).copy()
            elif len(features) == total:
                features = features.reshape(1, seq_len, input_size)
            elif len(features) < total:
                padded = np.zeros(total, dtype=np.float32)
                padded[: len(features)] = features
                features = padded.reshape(1, seq_len, input_size)
            else:
                features = features[:total].reshape(1, seq_len, input_size)

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

    # Max samples fed to the LSTM in a single GPU forward pass. cuDNN's
    # workspace + backward graph can balloon past 1 GB on larger batches,
    # and the expandable_segments allocator has been observed to hit
    # `!handles_.at(i) INTERNAL ASSERT FAILED` when a detector in an
    # ensemble pipeline is called repeatedly on very large 3-D inputs.
    # Chunking to this many sequences per sub-batch keeps peak allocation
    # bounded and lets us recover cleanly from transient CUDA errors.
    _PREDICT_SUBBATCH = 2048

    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")

        features = self._validate_features(features)

        if features.ndim == 2:
            seq_len = int(self.config["sequence_length"])
            input_size = int(self.config["input_size"])
            total = seq_len * input_size
            batch = features.shape[0]

            if features.shape[1] == total:
                # Flat rows already encode full sequences.
                features = features.reshape(batch, seq_len, input_size)
            elif features.shape[1] == input_size:
                # One feature vector per row → replicate across timesteps
                # so the LSTM sees an on-distribution sequence instead of
                # a row of real data padded with 19 zero timesteps. See
                # ``_prepare_input`` for the rationale.
                features = np.broadcast_to(
                    features[:, None, :], (batch, seq_len, input_size)
                )
            elif features.shape[1] < total:
                padded = np.zeros((batch, total), dtype=np.float32)
                padded[:, : features.shape[1]] = features
                features = padded.reshape(batch, seq_len, input_size)
            else:
                features = features[:, :total].reshape(batch, seq_len, input_size)

        # Sub-batch the forward pass to bound peak GPU memory and to
        # isolate failures: one chunk crashing shouldn't break the
        # subsequent chunks.
        n = int(features.shape[0])
        results: List[Dict[str, Any]] = []
        cpu_fallback = False

        for start in range(0, n, self._PREDICT_SUBBATCH):
            end = min(start + self._PREDICT_SUBBATCH, n)
            sub = np.ascontiguousarray(features[start:end], dtype=np.float32)
            all_probs = self._forward_chunk(sub, use_cpu=cpu_fallback)

            if all_probs is None and not cpu_fallback:
                # First GPU failure: flush allocator state and retry this
                # chunk on CPU. Stay on CPU for remaining chunks so we
                # don't re-trigger the bad allocator handle.
                logger.warning(
                    "LSTM GPU forward failed at chunk [%d:%d]; falling "
                    "back to CPU for the rest of this batch",
                    start, end,
                )
                if self.device.type == "cuda":
                    try:
                        torch.cuda.synchronize()
                        torch.cuda.empty_cache()
                    except Exception:
                        pass
                cpu_fallback = True
                all_probs = self._forward_chunk(sub, use_cpu=True)

            if all_probs is None:
                # Even CPU failed — surface stub results for this chunk.
                logger.error(
                    "LSTM batch prediction error on chunk [%d:%d]; "
                    "returning stub verdicts",
                    start, end,
                )
                results.extend(
                    {
                        "detector": "lstm_sequence",
                        "is_threat": False,
                        "confidence": 0.0,
                        "threat_type": ThreatCategory.UNKNOWN,
                        "error": "forward_failed",
                    }
                    for _ in range(end - start)
                )
                continue

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

    def _forward_chunk(
        self, features: np.ndarray, use_cpu: bool = False
    ) -> Optional[np.ndarray]:
        """Run one sub-batch through the model and return softmax probs.

        Returns ``None`` on failure so the caller can decide whether to
        retry on a different device or emit stub verdicts.
        """
        target_device = torch.device("cpu") if use_cpu else self.device
        try:
            if use_cpu and next(self.model.parameters()).device.type == "cuda":
                # Move a lightweight copy to CPU for the fallback path.
                # ``.cpu()`` without detach is safe because we're under
                # inference_mode below.
                model = self.model.to("cpu")
                moved = True
            else:
                model = self.model
                moved = False

            tensor = torch.as_tensor(
                features, dtype=torch.float32, device=target_device
            )
            with torch.inference_mode():
                logits = model(tensor)
                probs = torch.softmax(logits, dim=-1).detach().cpu().numpy()

            del tensor, logits
            if target_device.type == "cuda":
                try:
                    torch.cuda.synchronize()
                except Exception:
                    pass

            if moved:
                # Restore the model to its original device for subsequent
                # callers that may expect GPU residency.
                self.model.to(self.device)

            return probs

        except Exception as exc:
            logger.error(
                "LSTM forward (device=%s) failed: %s", target_device, exc
            )
            return None

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

        # Keep the whole training set on CPU and move each batch to the
        # GPU inside the loop.  This avoids a multi-GB one-shot CUDA
        # allocation that would OOM on small GPUs when training on the
        # full CIC-IDS2018 dataset.
        X_t = torch.as_tensor(X, dtype=torch.float32)
        y_t = torch.as_tensor(y, dtype=torch.long)

        pin = self.device.type == "cuda"
        loader = td.DataLoader(
            td.TensorDataset(X_t, y_t),
            batch_size=self.config["batch_size"],
            shuffle=True,
            pin_memory=pin,
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
                batch_x = batch_x.to(self.device, non_blocking=pin)
                batch_y = batch_y.to(self.device, non_blocking=pin)
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

        # Free the large training tensors before returning so the GPU
        # allocator is clean for whatever runs next in the pipeline.
        del loader, X_t, y_t
        if self.device.type == "cuda":
            torch.cuda.empty_cache()

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
