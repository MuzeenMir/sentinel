"""Business-app profile — application sidecar security.

Runs alongside a web application to enforce API rate limits, detect
session anomalies, apply WAF rules (OWASP Top-10), log requests for
audit, and track SBOM / dependency vulnerabilities.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from profiles.base import BaseProfile, ProfileConfig

logger = logging.getLogger("sentinel-agent")

_OWASP_SQLI_PATTERNS = [
    r"(?i)(\b(select|insert|update|delete|drop|union|alter|create)\b.*\b(from|into|table|where)\b)",
    r"(?i)(--|;|/\*|\*/|@@|@)",
    r"(?i)('|\")\s*(or|and)\s*('|\")\s*=\s*('|\")",
]
_OWASP_XSS_PATTERNS = [
    r"(?i)<\s*script[^>]*>",
    r"(?i)(javascript|vbscript|data)\s*:",
    r"(?i)on(load|error|click|mouseover|focus|blur)\s*=",
]
_OWASP_PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"(?i)%2e%2e[/\\]",
    r"(?i)\.\.[/\\]",
]


class BusinessAppProfile(BaseProfile):
    """Sidecar security profile for web applications."""

    def __init__(self, config: ProfileConfig, event_bus: Any = None):
        super().__init__(config, event_bus)

        self._rate_limits: Dict[str, int] = config.extra.get("rate_limits", {
            "default": 100,
            "login": 10,
            "api": 60,
        })
        self._rate_window_sec: int = config.extra.get("rate_window_sec", 60)
        self._request_counts: Dict[str, List[float]] = defaultdict(list)

        self._session_store: Dict[str, dict] = {}
        self._session_anomaly_threshold: float = config.extra.get(
            "session_anomaly_threshold", 0.8,
        )

        self._waf_enabled: bool = config.extra.get("waf_enabled", True)
        self._compiled_sqli = [re.compile(p) for p in _OWASP_SQLI_PATTERNS]
        self._compiled_xss = [re.compile(p) for p in _OWASP_XSS_PATTERNS]
        self._compiled_traversal = [re.compile(p) for p in _OWASP_PATH_TRAVERSAL_PATTERNS]

        self._audit_log_path: str = config.extra.get(
            "audit_log_path",
            os.path.join(config.log_dir, "audit.jsonl"),
        )
        self._sbom_path: str = config.extra.get("sbom_path", "")
        self._known_vulns: Dict[str, List[str]] = {}

        self._stats = {
            "requests_inspected": 0,
            "rate_limited": 0,
            "waf_blocks": 0,
            "session_anomalies": 0,
            "audit_entries": 0,
            "vuln_alerts": 0,
        }

    @property
    def name(self) -> str:
        return "business_app"

    @property
    def description(self) -> str:
        return "Application sidecar (rate limiting, WAF, session anomaly, audit, SBOM)"

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._start_time = time.time()
        Path(self._audit_log_path).parent.mkdir(parents=True, exist_ok=True)
        self._load_sbom()
        self._start_thread("sbom", self._sbom_monitor_loop)
        self._start_thread("sessions", self._session_cleanup_loop)
        logger.info("[business_app] profile started — WAF=%s, rate_limits=%s, SBOM=%s",
                     self._waf_enabled, self._rate_limits, bool(self._sbom_path))

    def stop(self) -> None:
        self._running = False
        self._join_threads()
        logger.info("[business_app] profile stopped")

    # ── collection ────────────────────────────────────────────────────

    def collect_events(self) -> List[dict]:
        events: List[dict] = []
        events.extend(self._check_vulnerability_alerts())
        return events

    def apply_rules(self, rules: List[dict]) -> None:
        for rule in rules:
            action = rule.get("action", "")
            if action == "update_rate_limit":
                endpoint = rule.get("endpoint", "default")
                limit = rule.get("limit", 100)
                self._rate_limits[endpoint] = limit
                logger.info("[business_app] rate limit updated: %s = %d/min", endpoint, limit)
            elif action == "update_waf":
                self._waf_enabled = rule.get("enabled", True)
                logger.info("[business_app] WAF %s", "enabled" if self._waf_enabled else "disabled")
            elif action == "block_session":
                session_id = rule.get("session_id", "")
                if session_id in self._session_store:
                    del self._session_store[session_id]
                    logger.info("[business_app] session %s terminated", session_id[:8])

    def get_status(self) -> dict:
        return {
            "profile": self.name,
            "running": self._running,
            "uptime": self.uptime_seconds,
            "waf_enabled": self._waf_enabled,
            "active_sessions": len(self._session_store),
            "rate_limits": self._rate_limits,
            "sbom_loaded": bool(self._known_vulns),
            **self._stats,
        }

    # ── API rate limiting ─────────────────────────────────────────────

    def check_rate_limit(self, client_ip: str, endpoint: str = "default") -> bool:
        now = time.time()
        key = f"{client_ip}:{endpoint}"
        window_start = now - self._rate_window_sec

        timestamps = self._request_counts[key]
        self._request_counts[key] = [t for t in timestamps if t > window_start]
        self._request_counts[key].append(now)

        limit = self._rate_limits.get(endpoint, self._rate_limits.get("default", 100))
        if len(self._request_counts[key]) > limit:
            self._stats["rate_limited"] += 1
            self._publish({
                "event_type": "rate_limit_exceeded",
                "severity": "medium",
                "client_ip": client_ip,
                "endpoint": endpoint,
                "count": len(self._request_counts[key]),
                "limit": limit,
                "timestamp": now,
            })
            return False
        return True

    # ── session anomaly detection ─────────────────────────────────────

    def track_session(self, session_id: str, client_ip: str, user_agent: str,
                      endpoint: str) -> List[dict]:
        events: List[dict] = []
        now = time.time()
        self._stats["requests_inspected"] += 1

        existing = self._session_store.get(session_id)
        if existing is None:
            self._session_store[session_id] = {
                "client_ip": client_ip,
                "user_agent": user_agent,
                "first_seen": now,
                "last_seen": now,
                "request_count": 1,
                "endpoints": {endpoint},
            }
            return events

        if existing["client_ip"] != client_ip:
            events.append({
                "event_type": "session_anomaly",
                "severity": "high",
                "anomaly": "ip_change",
                "session_id": session_id[:16],
                "original_ip": existing["client_ip"],
                "new_ip": client_ip,
                "timestamp": now,
            })
            self._stats["session_anomalies"] += 1

        if existing["user_agent"] != user_agent:
            events.append({
                "event_type": "session_anomaly",
                "severity": "high",
                "anomaly": "user_agent_change",
                "session_id": session_id[:16],
                "timestamp": now,
            })
            self._stats["session_anomalies"] += 1

        gap = now - existing["last_seen"]
        if gap > 3600 and existing["request_count"] > 10:
            events.append({
                "event_type": "session_anomaly",
                "severity": "medium",
                "anomaly": "resumed_after_long_gap",
                "session_id": session_id[:16],
                "gap_seconds": round(gap),
                "timestamp": now,
            })
            self._stats["session_anomalies"] += 1

        existing["last_seen"] = now
        existing["request_count"] += 1
        existing["endpoints"].add(endpoint)
        return events

    # ── WAF (OWASP rules) ────────────────────────────────────────────

    def inspect_request(self, method: str, path: str, headers: Dict[str, str],
                        body: str = "", query: str = "") -> List[dict]:
        if not self._waf_enabled:
            return []

        events: List[dict] = []
        combined = f"{path} {query} {body}"

        for pattern in self._compiled_sqli:
            if pattern.search(combined):
                events.append(self._waf_event("sqli", method, path))
                break

        for pattern in self._compiled_xss:
            if pattern.search(combined):
                events.append(self._waf_event("xss", method, path))
                break

        for pattern in self._compiled_traversal:
            if pattern.search(path) or pattern.search(query):
                events.append(self._waf_event("path_traversal", method, path))
                break

        if events:
            self._stats["waf_blocks"] += len(events)
        return events

    def _waf_event(self, attack_type: str, method: str, path: str) -> dict:
        return {
            "event_type": "waf_block",
            "severity": "high",
            "attack_type": attack_type,
            "method": method,
            "path": path,
            "timestamp": time.time(),
        }

    # ── audit logging ─────────────────────────────────────────────────

    def log_audit(self, method: str, path: str, status_code: int,
                  client_ip: str, user_id: str = "", duration_ms: float = 0,
                  request_body: Optional[str] = None,
                  response_body: Optional[str] = None) -> None:
        entry = {
            "timestamp": time.time(),
            "method": method,
            "path": path,
            "status_code": status_code,
            "client_ip": client_ip,
            "user_id": user_id,
            "duration_ms": round(duration_ms, 2),
        }
        if request_body is not None:
            entry["request_body_hash"] = hashlib.sha256(
                request_body.encode("utf-8")
            ).hexdigest()[:16]
        if response_body is not None:
            entry["response_size"] = len(response_body)

        try:
            with open(self._audit_log_path, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
            self._stats["audit_entries"] += 1
        except OSError as exc:
            logger.error("[business_app] audit log write error: %s", exc)

    # ── SBOM / dependency vulnerability tracking ──────────────────────

    def _load_sbom(self) -> None:
        if not self._sbom_path or not os.path.exists(self._sbom_path):
            return
        try:
            with open(self._sbom_path) as f:
                sbom = json.load(f)
            components = sbom.get("components", [])
            logger.info("[business_app] SBOM loaded: %d components", len(components))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("[business_app] SBOM load error: %s", exc)

    def _check_vulnerability_alerts(self) -> List[dict]:
        events: List[dict] = []
        for pkg, vulns in self._known_vulns.items():
            for vuln_id in vulns:
                events.append({
                    "event_type": "dependency_vulnerability",
                    "severity": "high",
                    "package": pkg,
                    "vulnerability_id": vuln_id,
                    "timestamp": time.time(),
                })
                self._stats["vuln_alerts"] += 1
        return events

    def register_vulnerability(self, package: str, vulnerability_id: str) -> None:
        if package not in self._known_vulns:
            self._known_vulns[package] = []
        if vulnerability_id not in self._known_vulns[package]:
            self._known_vulns[package].append(vulnerability_id)

    # ── background loops ──────────────────────────────────────────────

    def _sbom_monitor_loop(self) -> None:
        while self._running:
            time.sleep(3600)
            try:
                self._load_sbom()
                for event in self._check_vulnerability_alerts():
                    self._publish(event)
            except Exception as exc:
                logger.error("[business_app] SBOM monitor error: %s", exc)

    def _session_cleanup_loop(self) -> None:
        while self._running:
            time.sleep(300)
            try:
                now = time.time()
                expired = [
                    sid for sid, s in self._session_store.items()
                    if now - s["last_seen"] > 7200
                ]
                for sid in expired:
                    del self._session_store[sid]
                if expired:
                    logger.debug("[business_app] cleaned %d expired sessions", len(expired))
            except Exception as exc:
                logger.error("[business_app] session cleanup error: %s", exc)
