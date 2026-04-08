"""
Converts raw threat-detection payloads into a 12-element normalised state
vector suitable for the PPO policy network.

Feature layout (index → meaning):
  0  threat_score           AI engine threat probability [0, 1]
  1  confidence             Model confidence score [0, 1]
  2  asset_criticality      Target asset criticality, normalised (1→0, 5→1)
  3  traffic_volume         Packet/byte volume, clipped at 50 000 → 1.0
  4  protocol_risk          L4 protocol risk (TCP=0.3, UDP=0.4, ICMP=0.5)
  5  time_risk              Time-of-day risk [0, 1] (or raw if provided)
  6  historical_alerts      Prior alert count clipped at 500 → 1.0
  7  is_internal            1.0 if source is RFC-1918, else 0.0
  8  port_sensitivity       Destination port risk [0, 1]
  9  threat_severity        Threat category severity weight [0, 1]
  10 connection_rate        Log-normalised connection rate
  11 geo_risk               Geolocation-based risk score [0, 1]
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)

_STATE_DIM = 12

_PROTOCOL_RISK: Dict[str, float] = {
    "TCP":  0.3,
    "UDP":  0.4,
    "ICMP": 0.5,
}
_PROTOCOL_DEFAULT = 0.3   # unknown protocols treated like TCP

_THREAT_SEVERITY: Dict[str, float] = {
    "brute_force":          0.80,
    "ddos":                 0.90,
    "port_scan":            0.60,
    "malware":              1.00,
    "ransomware":           1.00,
    "data_exfiltration":    0.95,
    "sql_injection":        0.85,
    "xss":                  0.70,
    "command_injection":    0.90,
    "privilege_escalation": 0.95,
    "lateral_movement":     0.90,
    "c2_communication":     0.95,
    "zero_day":             1.00,
    "insider_threat":       0.85,
    "phishing":             0.70,
    "credential_stuffing":  0.80,
    "dns_tunneling":        0.85,
}

_SENSITIVE_PORTS = frozenset({
    21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017,
})

_FEATURE_META: List[Dict[str, str]] = [
    {"name": "threat_score",         "description": "AI engine threat probability [0-1]"},
    {"name": "confidence",           "description": "Model confidence score [0-1]"},
    {"name": "asset_criticality",    "description": "Target asset criticality normalised to [0-1]"},
    {"name": "traffic_volume",       "description": "Packet/byte volume clipped at 50 000"},
    {"name": "protocol_risk",        "description": "L4 protocol risk (TCP=0.3, UDP=0.4, ICMP=0.5)"},
    {"name": "time_risk",            "description": "Time-of-day risk [0-1]"},
    {"name": "historical_alerts",    "description": "Prior alert count for this source, clipped at 500"},
    {"name": "is_internal",          "description": "1.0 if source is RFC-1918 private, else 0.0"},
    {"name": "port_sensitivity",     "description": "Destination port risk classification [0-1]"},
    {"name": "threat_severity",      "description": "Threat category severity weight [0-1]"},
    {"name": "connection_rate",      "description": "Log-normalised connection rate"},
    {"name": "geo_risk",             "description": "Geolocation-based risk score [0-1]"},
]


class StateBuilder:
    """Builds a fixed 12-dim normalised state vector from detection data."""

    def __init__(self) -> None:
        pass

    @property
    def state_dim(self) -> int:
        return _STATE_DIM

    def build_state(self, data: Dict[str, Any]) -> np.ndarray:
        ctx = data.get("context") or {}

        vec = np.array([
            # 0 — threat_score
            self._clamp(float(data.get("threat_score", 0.0))),
            # 1 — confidence
            self._clamp(float(data.get("confidence", 0.0))),
            # 2 — asset_criticality (1=min, 5=max → 0.0…1.0)
            self._normalize(float(data.get("asset_criticality", 1)), 1.0, 5.0, clip=True),
            # 3 — traffic_volume (linear clip at 50 000)
            min(float(data.get("traffic_volume", 0)) / 50_000.0, 1.0),
            # 4 — protocol_risk
            _PROTOCOL_RISK.get(str(data.get("protocol", "")).upper(), _PROTOCOL_DEFAULT),
            # 5 — time_risk (use provided value or derive from current hour)
            self._clamp(
                float(data["time_risk"]) if "time_risk" in data
                else self._hour_risk(datetime.now(timezone.utc).hour)
            ),
            # 6 — historical_alert_count (linear clip at 500)
            min(float(data.get("historical_alert_count", ctx.get("historical_alerts", 0))) / 500.0, 1.0),
            # 7 — is_internal
            1.0 if data.get("is_internal", False) else 0.0,
            # 8 — port_sensitivity
            self._port_risk(data.get("dest_port")),
            # 9 — threat_severity
            _THREAT_SEVERITY.get(str(data.get("threat_type", "")).lower(), 0.5),
            # 10 — connection_rate (log-normalised)
            self._log_norm(float(ctx.get("connection_rate", data.get("connection_rate", 0))), scale=1000.0),
            # 11 — geo_risk
            self._clamp(float(ctx.get("geo_risk", data.get("geo_risk", 0.0)))),
        ], dtype=np.float32)

        return vec

    def get_feature_descriptions(self) -> List[Dict[str, str]]:
        return [{"index": i, **m} for i, m in enumerate(_FEATURE_META)]

    # ------------------------------------------------------------------
    # Public normalisation helper (tested directly)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(value: float, lo: float, hi: float, clip: bool = False) -> float:
        """Scale *value* from [lo, hi] to [0, 1].

        If lo == hi returns 0.5.  If *clip* is True the result is clamped.
        """
        if lo == hi:
            return 0.5
        result = (value - lo) / (hi - lo)
        if clip:
            result = max(0.0, min(1.0, result))
        return float(result)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
        return float(max(lo, min(v, hi)))

    @staticmethod
    def _log_norm(value: float, scale: float = 1000.0) -> float:
        if value <= 0:
            return 0.0
        return min(math.log1p(value) / math.log1p(scale), 1.0)

    @staticmethod
    def _port_risk(port: Any) -> float:
        try:
            port = int(port)
        except (TypeError, ValueError):
            return 0.5
        if port == 0:
            return 1.0
        if port in _SENSITIVE_PORTS:
            return 0.9
        if port < 1024:
            return 0.7
        # Registered and dynamic ports — low risk
        return 0.2

    @staticmethod
    def _hour_risk(hour: int) -> float:
        """Off-hours (midnight–6 h and 22–24 h) are riskier."""
        if hour < 6 or hour >= 22:
            return 0.8
        if hour < 9 or hour >= 18:
            return 0.5
        return 0.2
