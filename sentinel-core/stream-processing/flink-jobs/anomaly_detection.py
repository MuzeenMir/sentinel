"""
SENTINEL Anomaly Detection Stream Job

Consumes network events from Kafka, applies lightweight statistical
anomaly scoring (z-score on per-feature running statistics plus
per-source behavioural tracking), and publishes results to dedicated
alert and detection topics.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional

import numpy as np

from base_job import BaseStreamJob

logger = logging.getLogger(__name__)

ZSCORE_THRESHOLD = float(os.environ.get("ANOMALY_ZSCORE_THRESHOLD", "3.0"))
WINDOW_SIZE = int(os.environ.get("ANOMALY_WINDOW_SIZE", "1000"))
WARMUP_SAMPLES = int(os.environ.get("ANOMALY_WARMUP", "100"))

FEATURE_KEYS = [
    "packet_size",
    "packet_rate",
    "byte_rate",
    "flow_duration",
    "src_port",
    "dst_port",
    "protocol_type",
    "flag_count",
    "payload_size",
    "ttl",
    "window_size",
    "entropy",
]


class WelfordAccumulator:
    """Welford's online algorithm for numerically stable running mean/variance."""

    __slots__ = ("n", "mean", "m2")

    def __init__(self, n_features: int):
        self.n = 0
        self.mean = np.zeros(n_features, dtype=np.float64)
        self.m2 = np.zeros(n_features, dtype=np.float64)

    def update(self, sample: np.ndarray):
        self.n += 1
        delta = sample - self.mean
        self.mean += delta / self.n
        delta2 = sample - self.mean
        self.m2 += delta * delta2

    @property
    def std(self) -> np.ndarray:
        if self.n < 2:
            return np.ones_like(self.mean)
        return np.sqrt(np.maximum(self.m2 / (self.n - 1), 1e-10))


class AnomalyDetectionJob(BaseStreamJob):

    def __init__(self):
        super().__init__("anomaly-detection")
        self.input_topic = os.environ.get(
            "KAFKA_INPUT_TOPIC", "sentinel-network-events",
        )
        self.alerts_topic = "sentinel-alerts"
        self.detections_topic = "sentinel-detections"

        self.stats = WelfordAccumulator(len(FEATURE_KEYS))
        self._processed = 0
        self._anomalies_detected = 0
        self._src_rates: Dict[str, List[float]] = defaultdict(list)

    def setup(self):
        self.create_consumer(
            topics=[self.input_topic],
            group_id="sentinel-anomaly-detection",
        )
        self.create_producer()

        saved = self.load_checkpoint()
        if saved:
            self.stats.n = saved.get("stats_n", 0)
            self.stats.mean = np.array(saved.get("stats_mean", np.zeros(len(FEATURE_KEYS))))
            self.stats.m2 = np.array(saved.get("stats_m2", np.zeros(len(FEATURE_KEYS))))
            self._processed = saved.get("processed", 0)
            logger.info("Restored checkpoint: %d samples processed", self._processed)

    # ── Feature extraction & scoring ──────────────────────────────────────

    def _extract_features(self, event: Dict[str, Any]) -> Optional[np.ndarray]:
        try:
            return np.array(
                [float(event.get(k, 0.0) or 0.0) for k in FEATURE_KEYS],
                dtype=np.float64,
            )
        except (ValueError, TypeError):
            return None

    def _zscore(self, features: np.ndarray) -> np.ndarray:
        return np.abs((features - self.stats.mean) / self.stats.std)

    def _src_behaviour_score(self, src_ip: str, current_rate: float) -> float:
        history = self._src_rates[src_ip]
        history.append(current_rate)
        if len(history) > WINDOW_SIZE:
            history[:] = history[-WINDOW_SIZE:]
        if len(history) < 10:
            return 0.0
        arr = np.array(history)
        std = float(np.std(arr))
        if std < 1e-10:
            return 0.0
        return abs((current_rate - float(np.mean(arr))) / std)

    # ── Message processing ────────────────────────────────────────────────

    def process(self, message: Dict[str, Any]):
        features = self._extract_features(message)
        if features is None:
            return

        self.stats.update(features)
        self._processed += 1

        if self.stats.n < WARMUP_SAMPLES:
            return

        zscores = self._zscore(features)
        max_z = float(np.max(zscores))
        mean_z = float(np.mean(zscores))

        src_ip = message.get("src_ip", "unknown")
        src_z = self._src_behaviour_score(
            src_ip, float(message.get("packet_rate", 0.0)),
        )

        composite = 0.6 * max_z + 0.25 * mean_z + 0.15 * src_z
        is_anomaly = composite > ZSCORE_THRESHOLD

        detection = {
            "detection_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "source_event_id": message.get("event_id"),
            "src_ip": src_ip,
            "dst_ip": message.get("dst_ip", "unknown"),
            "max_zscore": round(max_z, 4),
            "mean_zscore": round(mean_z, 4),
            "src_anomaly_score": round(src_z, 4),
            "composite_score": round(composite, 4),
            "is_anomaly": is_anomaly,
            "feature_zscores": {
                k: round(float(z), 4)
                for k, z in zip(FEATURE_KEYS, zscores)
                if z > ZSCORE_THRESHOLD * 0.5
            },
        }
        self.produce(self.detections_topic, detection, key=src_ip)

        if is_anomaly:
            self._anomalies_detected += 1
            self._emit_alert(message, detection, zscores, composite)

        if self._processed % 10_000 == 0:
            rate = (self._anomalies_detected / self._processed * 100) if self._processed else 0
            logger.info(
                "Processed %d events, %d anomalies (%.2f%%)",
                self._processed, self._anomalies_detected, rate,
            )
            self._checkpoint()

    def _emit_alert(
        self,
        event: Dict[str, Any],
        detection: Dict[str, Any],
        zscores: np.ndarray,
        composite: float,
    ):
        top_features = sorted(
            zip(FEATURE_KEYS, zscores), key=lambda x: x[1], reverse=True,
        )[:3]

        if composite > ZSCORE_THRESHOLD * 2:
            severity = "critical"
        elif composite > ZSCORE_THRESHOLD * 1.5:
            severity = "high"
        else:
            severity = "medium"

        src_ip = event.get("src_ip", "unknown")
        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "detection_id": detection["detection_id"],
            "type": "statistical_anomaly",
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": event.get("dst_ip", "unknown"),
            "score": round(composite, 4),
            "description": (
                f"Statistical anomaly from {src_ip}: "
                f"composite z-score {composite:.2f} "
                f"(top: {', '.join(f'{k}={z:.1f}' for k, z in top_features)})"
            ),
            "recommended_action": "investigate" if severity == "medium" else "block",
        }
        self.produce(self.alerts_topic, alert, key=src_ip)

    def _checkpoint(self):
        self.save_checkpoint({
            "stats_n": self.stats.n,
            "stats_mean": self.stats.mean.tolist(),
            "stats_m2": self.stats.m2.tolist(),
            "processed": self._processed,
            "anomalies_detected": self._anomalies_detected,
        })


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    AnomalyDetectionJob().run()


if __name__ == "__main__":
    main()
