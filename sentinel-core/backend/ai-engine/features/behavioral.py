"""
Behavioral feature extraction from network traffic patterns.

Captures connection patterns, session characteristics, request frequency,
and automated-access indicators.
"""

import logging
import math
from collections import Counter, defaultdict
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)


class BehavioralFeatureExtractor:
    """
    Extracts behavioral features from traffic dictionaries.

    Expected *raw_data* keys (all optional):
        connections  — list of connection dicts (src_ip, dst_ip, dst_port, …)
        requests     — list of request dicts (endpoint, method, status_code, …)
        sessions     — list of session dicts (user_id, duration, actions, …)
        timestamps   — list of floats (epoch seconds)
    """

    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        features: Dict[str, float] = {}

        try:
            features.update(self._connection_features(raw_data.get("connections", [])))
            features.update(self._request_features(raw_data.get("requests", [])))
            features.update(self._session_features(raw_data.get("sessions", [])))
            features.update(self._access_pattern_features(raw_data))
        except Exception as exc:
            logger.error("Behavioral feature extraction failed: %s", exc)

        return features

    # ------------------------------------------------------------------
    # Connection features
    # ------------------------------------------------------------------

    @staticmethod
    def _connection_features(connections: List[Dict]) -> Dict[str, float]:
        if not connections:
            return {
                "conn_count": 0.0,
                "unique_dst_ips": 0.0,
                "unique_dst_ports": 0.0,
                "conn_duration_mean": 0.0,
                "conn_duration_std": 0.0,
                "conn_bytes_mean": 0.0,
                "short_conn_ratio": 0.0,
                "port_scan_score": 0.0,
                "ip_fan_out": 0.0,
            }

        dst_ips = [c.get("dst_ip", "") for c in connections]
        dst_ports = [c.get("dst_port", 0) for c in connections]
        durations = np.array(
            [c.get("duration", 0.0) for c in connections], dtype=np.float64
        )
        byte_counts = [c.get("bytes", 0) for c in connections]

        unique_ips = len(set(dst_ips))
        unique_ports = len(set(dst_ports))
        n = len(connections)

        short_threshold = 0.5  # seconds
        short_count = int(np.sum(durations < short_threshold))

        ip_port_map: Dict[str, set] = defaultdict(set)
        for c in connections:
            ip_port_map[c.get("src_ip", "")].add(c.get("dst_port", 0))
        max_ports_per_src = max((len(v) for v in ip_port_map.values()), default=0)

        return {
            "conn_count": float(n),
            "unique_dst_ips": float(unique_ips),
            "unique_dst_ports": float(unique_ports),
            "conn_duration_mean": float(np.mean(durations)),
            "conn_duration_std": float(np.std(durations)),
            "conn_bytes_mean": float(np.mean(byte_counts)) if byte_counts else 0.0,
            "short_conn_ratio": short_count / max(n, 1),
            "port_scan_score": float(max_ports_per_src / max(unique_ports, 1)),
            "ip_fan_out": float(unique_ips / max(n, 1)),
        }

    # ------------------------------------------------------------------
    # Request features
    # ------------------------------------------------------------------

    @staticmethod
    def _request_features(requests: List[Dict]) -> Dict[str, float]:
        if not requests:
            return {
                "req_count": 0.0,
                "unique_endpoints": 0.0,
                "error_rate": 0.0,
                "req_frequency": 0.0,
                "method_entropy": 0.0,
                "sequential_failure_max": 0.0,
            }

        n = len(requests)
        endpoints = [r.get("endpoint", "") for r in requests]
        methods = [r.get("method", "GET") for r in requests]
        status_codes = [r.get("status_code", 200) for r in requests]
        timestamps = sorted(r.get("timestamp", 0.0) for r in requests)

        errors = sum(1 for s in status_codes if s >= 400)

        duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 1.0
        frequency = n / max(duration, 1e-6)

        method_counts = Counter(methods)
        total = sum(method_counts.values())
        method_entropy = -sum(
            (c / total) * math.log2(c / total) for c in method_counts.values() if c > 0
        )

        max_failures = current = 0
        for s in status_codes:
            if s >= 400:
                current += 1
                max_failures = max(max_failures, current)
            else:
                current = 0

        return {
            "req_count": float(n),
            "unique_endpoints": float(len(set(endpoints))),
            "error_rate": errors / max(n, 1),
            "req_frequency": float(frequency),
            "method_entropy": float(method_entropy),
            "sequential_failure_max": float(max_failures),
        }

    # ------------------------------------------------------------------
    # Session features
    # ------------------------------------------------------------------

    @staticmethod
    def _session_features(sessions: List[Dict]) -> Dict[str, float]:
        if not sessions:
            return {
                "session_count": 0.0,
                "session_duration_mean": 0.0,
                "session_duration_std": 0.0,
                "actions_per_session_mean": 0.0,
                "unique_users": 0.0,
            }

        durations = np.array(
            [s.get("duration", 0.0) for s in sessions], dtype=np.float64
        )
        actions = np.array(
            [len(s.get("actions", [])) for s in sessions], dtype=np.float64
        )
        users = set(s.get("user_id", "") for s in sessions)

        return {
            "session_count": float(len(sessions)),
            "session_duration_mean": float(np.mean(durations)),
            "session_duration_std": float(np.std(durations)),
            "actions_per_session_mean": float(np.mean(actions)),
            "unique_users": float(len(users)),
        }

    # ------------------------------------------------------------------
    # Access-pattern features
    # ------------------------------------------------------------------

    @staticmethod
    def _access_pattern_features(raw_data: Dict[str, Any]) -> Dict[str, float]:
        timestamps = raw_data.get("timestamps", [])

        if len(timestamps) < 3:
            return {"regularity_score": 0.0, "burst_score": 0.0}

        intervals = np.diff(sorted(timestamps))
        mean_iv = float(np.mean(intervals))
        std_iv = float(np.std(intervals))

        cv = std_iv / max(mean_iv, 1e-8)
        regularity = 1.0 / (1.0 + cv)

        burst_threshold = mean_iv * 0.1 if mean_iv > 0 else 0.01
        burst_count = int(np.sum(intervals < burst_threshold))
        burst_score = burst_count / max(len(intervals), 1)

        return {
            "regularity_score": float(regularity),
            "burst_score": float(burst_score),
        }
