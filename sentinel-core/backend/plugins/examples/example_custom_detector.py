"""Example plugin: entropy-based DNS-tunnelling detector.

Demonstrates how to implement a SENTINEL plugin that acts as a custom
threat detector.  The plugin analyses DNS query names and flags those
with abnormally high Shannon entropy — a strong indicator of data
exfiltration via DNS tunnelling.

Register with the plugin registry::

    from plugins.registry import PluginRegistry
    registry = PluginRegistry()
    registry.register(DNSTunnelDetectorPlugin)
    registry.start_all(config={"dns_tunnel_detector": {"entropy_threshold": 3.8}})
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import Counter
from typing import Any, Dict, List

from plugins.registry import Plugin

logger = logging.getLogger("sentinel-plugins")

_DEFAULT_ENTROPY_THRESHOLD = 3.5
_DEFAULT_MIN_LABEL_LENGTH = 20


class DNSTunnelDetectorPlugin(Plugin):
    """Detects DNS tunnelling by measuring query-name entropy."""

    def __init__(self) -> None:
        self._entropy_threshold: float = _DEFAULT_ENTROPY_THRESHOLD
        self._min_label_length: int = _DEFAULT_MIN_LABEL_LENGTH
        self._running = False
        self._detections: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._queries_analysed: int = 0
        self._alerts_raised: int = 0

    @property
    def name(self) -> str:
        return "dns_tunnel_detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects DNS tunnelling via Shannon entropy analysis of query labels"

    def init(self, config: Dict[str, Any]) -> None:
        self._entropy_threshold = config.get(
            "entropy_threshold", _DEFAULT_ENTROPY_THRESHOLD
        )
        self._min_label_length = config.get(
            "min_label_length", _DEFAULT_MIN_LABEL_LENGTH
        )
        logger.info(
            "[%s] initialised — threshold=%.2f, min_length=%d",
            self.name,
            self._entropy_threshold,
            self._min_label_length,
        )

    def start(self) -> None:
        self._running = True
        logger.info("[%s] started", self.name)

    def stop(self) -> None:
        self._running = False
        logger.info(
            "[%s] stopped — analysed=%d alerts=%d",
            self.name,
            self._queries_analysed,
            self._alerts_raised,
        )

    def health_check(self) -> bool:
        return self._running

    # ── detection logic ───────────────────────────────────────────────

    def analyse_query(
        self, query_name: str, source_ip: str = ""
    ) -> Dict[str, Any] | None:
        """Analyse a single DNS query name.

        Returns a detection dict if tunnelling is suspected, else ``None``.
        """
        if not self._running:
            return None
        self._queries_analysed += 1

        labels = query_name.rstrip(".").split(".")
        longest_label = max(labels, key=len) if labels else ""

        if len(longest_label) < self._min_label_length:
            return None

        entropy = self._shannon_entropy(longest_label)
        if entropy < self._entropy_threshold:
            return None

        self._alerts_raised += 1
        detection = {
            "event_type": "dns_tunnel_suspected",
            "severity": "high",
            "query_name": query_name,
            "source_ip": source_ip,
            "entropy": round(entropy, 4),
            "threshold": self._entropy_threshold,
            "label_length": len(longest_label),
            "timestamp": time.time(),
        }
        with self._lock:
            self._detections.append(detection)
            if len(self._detections) > 10_000:
                self._detections = self._detections[-5_000:]
        return detection

    def get_recent_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._detections[-limit:])

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length) for count in freq.values()
        )
