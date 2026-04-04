"""
Contextual feature extraction — environmental and reputation-based signals.

Produces features that represent the *context* around a traffic event rather
than the packet content itself: time-of-day risk, geo-risk, IP/domain
reputation, protocol risk, and user-agent heuristics.
"""
import logging
import math
from datetime import datetime
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

RISKY_PORTS: Set[int] = {
    22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389,
    4444, 5432, 5900, 6379, 8080, 8443, 9200,
}

HIGH_RISK_PROTOCOLS: Set[str] = {"telnet", "ftp", "tftp", "snmp", "rsh", "rlogin"}
MODERATE_RISK_PROTOCOLS: Set[str] = {"http", "smtp", "pop3", "imap"}

HIGH_RISK_COUNTRIES: Set[str] = {"CN", "RU", "KP", "IR"}

SUSPICIOUS_UA_TOKENS = (
    "curl", "wget", "python-requests", "nikto", "sqlmap",
    "nmap", "masscan", "zgrab", "gobuster", "dirbuster",
)


class ContextualFeatureExtractor:
    """
    Extracts contextual / environmental features.

    Expected *raw_data* keys (all optional):
        timestamp, timestamps, src_ip, dst_ip, src_country, dst_country,
        protocol, dst_port, ports, domain, user_agent, is_encrypted,
        has_payload.
    """

    def __init__(
        self,
        known_malicious_ips: Optional[Set[str]] = None,
        known_malicious_domains: Optional[Set[str]] = None,
    ):
        self._malicious_ips: Set[str] = known_malicious_ips or set()
        self._malicious_domains: Set[str] = known_malicious_domains or set()

    def update_threat_intel(
        self,
        malicious_ips: Optional[Set[str]] = None,
        malicious_domains: Optional[Set[str]] = None,
    ) -> None:
        if malicious_ips is not None:
            self._malicious_ips = malicious_ips
        if malicious_domains is not None:
            self._malicious_domains = malicious_domains

    def extract(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        features: Dict[str, float] = {}

        try:
            features.update(self._time_features(raw_data))
            features.update(self._geo_features(raw_data))
            features.update(self._reputation_features(raw_data))
            features.update(self._protocol_features(raw_data))
            features.update(self._environment_features(raw_data))
        except Exception as exc:
            logger.error("Contextual feature extraction failed: %s", exc)

        return features

    # ------------------------------------------------------------------
    # Time features
    # ------------------------------------------------------------------

    @staticmethod
    def _time_features(raw_data: Dict[str, Any]) -> Dict[str, float]:
        ts = raw_data.get("timestamp")
        if ts is None:
            timestamps = raw_data.get("timestamps", [])
            ts = timestamps[-1] if timestamps else None

        if ts is None:
            return {
                "hour_sin": 0.0,
                "hour_cos": 0.0,
                "is_off_hours": 0.0,
                "is_weekend": 0.0,
                "time_risk_score": 0.0,
            }

        if isinstance(ts, (int, float)):
            dt = datetime.utcfromtimestamp(ts)
        elif isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                dt = datetime.utcnow()
        elif isinstance(ts, datetime):
            dt = ts
        else:
            dt = datetime.utcnow()

        hour = dt.hour + dt.minute / 60.0
        hour_sin = math.sin(2 * math.pi * hour / 24.0)
        hour_cos = math.cos(2 * math.pi * hour / 24.0)

        is_off_hours = 1.0 if (hour < 6 or hour > 22) else 0.0
        is_weekend = 1.0 if dt.weekday() >= 5 else 0.0

        time_risk = 0.0
        if is_off_hours:
            time_risk += 0.4
        if is_weekend:
            time_risk += 0.2

        return {
            "hour_sin": float(hour_sin),
            "hour_cos": float(hour_cos),
            "is_off_hours": is_off_hours,
            "is_weekend": is_weekend,
            "time_risk_score": time_risk,
        }

    # ------------------------------------------------------------------
    # Geo features
    # ------------------------------------------------------------------

    @staticmethod
    def _geo_features(raw_data: Dict[str, Any]) -> Dict[str, float]:
        src_country = raw_data.get("src_country", "")
        dst_country = raw_data.get("dst_country", "")

        cross_border = 1.0 if (
            src_country and dst_country and src_country != dst_country
        ) else 0.0

        src_risk = 1.0 if src_country in HIGH_RISK_COUNTRIES else 0.0
        dst_risk = 1.0 if dst_country in HIGH_RISK_COUNTRIES else 0.0

        geo_risk = 0.0
        if cross_border:
            geo_risk += 0.2
        if src_risk:
            geo_risk += 0.4
        if dst_risk:
            geo_risk += 0.3

        return {
            "cross_border": cross_border,
            "src_country_risk": src_risk,
            "dst_country_risk": dst_risk,
            "geo_risk_score": min(geo_risk, 1.0),
        }

    # ------------------------------------------------------------------
    # Reputation features
    # ------------------------------------------------------------------

    def _reputation_features(self, raw_data: Dict[str, Any]) -> Dict[str, float]:
        src_ip = raw_data.get("src_ip", "")
        dst_ip = raw_data.get("dst_ip", "")
        domain = raw_data.get("domain", "")

        src_mal = 1.0 if src_ip in self._malicious_ips else 0.0
        dst_mal = 1.0 if dst_ip in self._malicious_ips else 0.0
        dom_mal = 1.0 if domain in self._malicious_domains else 0.0

        return {
            "src_ip_malicious": src_mal,
            "dst_ip_malicious": dst_mal,
            "domain_malicious": dom_mal,
            "reputation_risk_score": max(src_mal, dst_mal, dom_mal),
        }

    # ------------------------------------------------------------------
    # Protocol features
    # ------------------------------------------------------------------

    @staticmethod
    def _protocol_features(raw_data: Dict[str, Any]) -> Dict[str, float]:
        protocol = raw_data.get("protocol", "").lower()
        dst_port = raw_data.get("dst_port", 0)
        ports = raw_data.get("ports", [])

        if not dst_port and ports:
            dst_port = ports[0]

        if protocol in HIGH_RISK_PROTOCOLS:
            protocol_risk = 0.8
        elif protocol in MODERATE_RISK_PROTOCOLS:
            protocol_risk = 0.3
        else:
            protocol_risk = 0.1

        is_encrypted = 1.0 if raw_data.get("is_encrypted", False) else 0.0
        if not is_encrypted:
            protocol_risk = min(protocol_risk + 0.15, 1.0)

        port_risk = 1.0 if dst_port in RISKY_PORTS else 0.0
        risky_port_count = sum(1 for p in ports if p in RISKY_PORTS) if ports else 0

        return {
            "protocol_risk_score": protocol_risk,
            "is_encrypted": is_encrypted,
            "port_risk": port_risk,
            "risky_port_count": float(risky_port_count),
        }

    # ------------------------------------------------------------------
    # Environment / user-agent features
    # ------------------------------------------------------------------

    @staticmethod
    def _environment_features(raw_data: Dict[str, Any]) -> Dict[str, float]:
        user_agent = raw_data.get("user_agent", "")

        suspicious_ua = 0.0
        if user_agent:
            ua_lower = user_agent.lower()
            if any(token in ua_lower for token in SUSPICIOUS_UA_TOKENS):
                suspicious_ua = 1.0

        has_payload = 1.0 if raw_data.get("has_payload", False) else 0.0

        return {
            "suspicious_user_agent": suspicious_ua,
            "has_payload": has_payload,
        }
