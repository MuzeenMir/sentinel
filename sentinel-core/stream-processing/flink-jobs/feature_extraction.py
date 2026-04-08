"""
SENTINEL Feature Extraction Stream Job

Consumes raw network events, normalises fields to a Common Information
Model (CIM), computes statistical features (packet rate, byte entropy,
connection frequency, inter-arrival statistics), and publishes enriched
events to the ``extracted_features`` topic.
"""
from __future__ import annotations

import logging
import math
import os
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

import numpy as np

from base_job import BaseStreamJob

logger = logging.getLogger(__name__)

CIM_FIELD_MAP: Dict[str, List[str]] = {
    "src_ip":      ["src_ip", "source_ip", "srcip", "src_addr", "source_address"],
    "dst_ip":      ["dst_ip", "dest_ip", "dstip", "dst_addr", "destination_address"],
    "src_port":    ["src_port", "source_port", "srcport", "sport"],
    "dst_port":    ["dst_port", "dest_port", "dstport", "dport"],
    "protocol":    ["protocol", "proto", "ip_protocol"],
    "action":      ["action", "event_action", "disposition"],
    "bytes_in":    ["bytes_in", "bytes_received", "in_bytes", "rx_bytes"],
    "bytes_out":   ["bytes_out", "bytes_sent", "out_bytes", "tx_bytes"],
    "packets_in":  ["packets_in", "pkts_in", "rx_packets"],
    "packets_out": ["packets_out", "pkts_out", "tx_packets"],
    "duration":    ["duration", "flow_duration", "session_duration"],
    "timestamp":   ["timestamp", "ts", "event_time", "@timestamp"],
}

PROTOCOL_RISK = {"tcp": 0.3, "udp": 0.5, "icmp": 0.6}


def normalise_to_cim(event: Dict[str, Any]) -> Dict[str, Any]:
    """Map vendor-specific field names to CIM canonical names."""
    normalised: Dict[str, Any] = {}
    for cim_field, variants in CIM_FIELD_MAP.items():
        for variant in variants:
            if variant in event:
                normalised[cim_field] = event[variant]
                break
    for key, value in event.items():
        if key not in normalised:
            normalised[key] = value
    return normalised


def byte_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0–8 bits)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


class ConnectionTracker:
    """Per-source sliding-window connection statistics."""

    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self._ts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10_000))
        self._bytes: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10_000))
        self._dsts: Dict[str, set] = defaultdict(set)
        self._ports: Dict[str, set] = defaultdict(set)

    def record(self, src: str, dst: str, port: int, nbytes: float, ts: float):
        self._ts[src].append(ts)
        self._bytes[src].append(nbytes)
        self._dsts[src].add(dst)
        self._ports[src].add(port)
        self._evict(src, ts)

    def stats(self, src: str, now: float) -> Dict[str, float]:
        self._evict(src, now)
        ts_q = self._ts[src]
        byte_q = self._bytes[src]
        n = len(ts_q)
        if n == 0:
            return {
                "connection_count": 0,
                "connection_rate": 0.0,
                "byte_rate": 0.0,
                "unique_destinations": 0,
                "unique_ports": 0,
                "inter_arrival_mean": 0.0,
                "inter_arrival_std": 0.0,
            }

        span = max((ts_q[-1] - ts_q[0]) if n > 1 else 1.0, 1.0)
        ia = np.diff(list(ts_q)) if n > 1 else np.array([0.0])
        return {
            "connection_count": n,
            "connection_rate": n / span,
            "byte_rate": sum(byte_q) / span,
            "unique_destinations": len(self._dsts[src]),
            "unique_ports": len(self._ports[src]),
            "inter_arrival_mean": float(np.mean(ia)),
            "inter_arrival_std": float(np.std(ia)),
        }

    def _evict(self, src: str, now: float):
        cutoff = now - self.window
        ts_q = self._ts[src]
        byte_q = self._bytes[src]
        while ts_q and ts_q[0] < cutoff:
            ts_q.popleft()
            byte_q.popleft()


class FeatureExtractionJob(BaseStreamJob):

    def __init__(self):
        super().__init__("feature-extraction")
        self.input_topic = os.environ.get("KAFKA_INPUT_TOPIC", "sentinel-network-events")
        self.output_topic = os.environ.get("KAFKA_OUTPUT_TOPIC", "extracted_features")
        self.tracker = ConnectionTracker(window_seconds=300)
        self._processed = 0

    def setup(self):
        self.create_consumer(
            topics=[self.input_topic],
            group_id="sentinel-feature-extraction",
        )
        self.create_producer()
        logger.info("Feature extraction: %s → %s", self.input_topic, self.output_topic)

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value) if value is not None else default
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _int(value: Any, default: int = 0) -> int:
        try:
            return int(value) if value is not None else default
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _parse_payload(raw) -> bytes:
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, str) and raw:
            try:
                return bytes.fromhex(raw)
            except ValueError:
                return raw.encode("utf-8", errors="replace")
        return b""

    # ── Processing ────────────────────────────────────────────────────────

    def process(self, message: Dict[str, Any]):
        norm = normalise_to_cim(message)

        src_ip = str(norm.get("src_ip", "0.0.0.0"))
        dst_ip = str(norm.get("dst_ip", "0.0.0.0"))
        dst_port = self._int(norm.get("dst_port"))
        bytes_in = self._float(norm.get("bytes_in"))
        bytes_out = self._float(norm.get("bytes_out"))
        total_bytes = bytes_in + bytes_out
        ts = self._float(norm.get("timestamp"), time.time())

        self.tracker.record(src_ip, dst_ip, dst_port, total_bytes, ts)
        conn = self.tracker.stats(src_ip, ts)

        payload = self._parse_payload(norm.get("payload", ""))
        entropy = byte_entropy(payload)

        packets_in = self._float(norm.get("packets_in"))
        packets_out = self._float(norm.get("packets_out"))
        duration = max(self._float(norm.get("duration"), 1.0), 0.001)

        protocol = str(norm.get("protocol", "unknown")).lower()

        enriched = {
            "event_id": norm.get("event_id", str(uuid.uuid4())),
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": self._int(norm.get("src_port")),
            "dst_port": dst_port,
            "protocol": protocol,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "total_bytes": total_bytes,
            "packets_in": packets_in,
            "packets_out": packets_out,
            "duration": duration,
            "action": norm.get("action"),
            # Computed features
            "packet_rate": round((packets_in + packets_out) / duration, 4),
            "byte_rate": round(total_bytes / duration, 4),
            "payload_entropy": round(entropy, 4),
            "protocol_risk": PROTOCOL_RISK.get(protocol, 0.7),
            "well_known_port": dst_port <= 1024,
            # Aggregated per-source features
            "connection_count": conn["connection_count"],
            "connection_rate": round(conn["connection_rate"], 4),
            "agg_byte_rate": round(conn["byte_rate"], 4),
            "unique_destinations": conn["unique_destinations"],
            "unique_ports": conn["unique_ports"],
            "inter_arrival_mean": round(conn["inter_arrival_mean"], 6),
            "inter_arrival_std": round(conn["inter_arrival_std"], 6),
        }

        self.produce(self.output_topic, enriched, key=src_ip)
        self._processed += 1

        if self._processed % 10_000 == 0:
            logger.info("Extracted features for %d events", self._processed)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    FeatureExtractionJob().run()


if __name__ == "__main__":
    main()
