"""
Statistical feature extraction from raw network traffic data.

Computes packet-rate, byte-rate, entropy, timing, and distributional
statistics from raw traffic fields.
"""
import logging
import math
from collections import Counter
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)


class StatisticalFeatureExtractor:
    """
    Extracts aggregate statistical features from a raw traffic sample.

    Expected *raw_data* keys (all optional, missing → zero-filled):
        packet_sizes, timestamps, bytes_sent, bytes_received,
        protocols, ports, flags.
    """

    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        features: Dict[str, float] = {}

        try:
            packet_sizes = raw_data.get("packet_sizes", [])
            timestamps = raw_data.get("timestamps", [])
            bytes_sent = raw_data.get("bytes_sent", [])
            bytes_received = raw_data.get("bytes_received", [])
            ports = raw_data.get("ports", [])
            protocols = raw_data.get("protocols", [])
            flags = raw_data.get("flags", [])

            features.update(self._array_stats(packet_sizes, "pkt_size"))
            features.update(self._array_stats(bytes_sent, "bytes_sent"))
            features.update(self._array_stats(bytes_received, "bytes_recv"))
            features.update(self._timing_features(timestamps))

            features["port_entropy"] = self._entropy(ports)
            features["unique_ports"] = float(len(set(ports))) if ports else 0.0

            total_sent = sum(bytes_sent) if bytes_sent else 0
            total_recv = sum(bytes_received) if bytes_received else 0
            features["send_recv_ratio"] = (
                total_sent / max(total_recv, 1) if (total_sent + total_recv) > 0 else 0.0
            )
            features["total_bytes"] = float(total_sent + total_recv)

            features["protocol_entropy"] = self._entropy(protocols)

            features["flag_entropy"] = self._entropy(flags)
            flag_counts = Counter(flags)
            n_flags = max(len(flags), 1)
            features["syn_ratio"] = flag_counts.get("SYN", 0) / n_flags
            features["rst_ratio"] = flag_counts.get("RST", 0) / n_flags
            features["fin_ratio"] = flag_counts.get("FIN", 0) / n_flags

        except Exception as exc:
            logger.error("Statistical feature extraction failed: %s", exc)

        return features

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _array_stats(values: List, prefix: str) -> Dict[str, float]:
        if not values:
            return {
                f"{prefix}_mean": 0.0,
                f"{prefix}_std": 0.0,
                f"{prefix}_min": 0.0,
                f"{prefix}_max": 0.0,
                f"{prefix}_median": 0.0,
                f"{prefix}_count": 0.0,
                f"{prefix}_sum": 0.0,
            }
        arr = np.array(values, dtype=np.float64)
        return {
            f"{prefix}_mean": float(np.mean(arr)),
            f"{prefix}_std": float(np.std(arr)),
            f"{prefix}_min": float(np.min(arr)),
            f"{prefix}_max": float(np.max(arr)),
            f"{prefix}_median": float(np.median(arr)),
            f"{prefix}_count": float(len(arr)),
            f"{prefix}_sum": float(np.sum(arr)),
        }

    @staticmethod
    def _timing_features(timestamps: List[float]) -> Dict[str, float]:
        if len(timestamps) < 2:
            return {
                "inter_arrival_mean": 0.0,
                "inter_arrival_std": 0.0,
                "inter_arrival_min": 0.0,
                "inter_arrival_max": 0.0,
                "packet_rate": 0.0,
                "duration": 0.0,
            }
        sorted_ts = sorted(timestamps)
        inter = np.diff(sorted_ts)
        duration = sorted_ts[-1] - sorted_ts[0]
        return {
            "inter_arrival_mean": float(np.mean(inter)),
            "inter_arrival_std": float(np.std(inter)),
            "inter_arrival_min": float(np.min(inter)),
            "inter_arrival_max": float(np.max(inter)),
            "packet_rate": float(len(timestamps) / max(duration, 1e-6)),
            "duration": float(duration),
        }

    @staticmethod
    def _entropy(values: List) -> float:
        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        return -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values()
            if c > 0
        )
