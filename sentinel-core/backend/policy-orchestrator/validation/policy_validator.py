"""
Policy validation for SENTINEL firewall rules.

Enforces safety constraints before rules reach any vendor adapter:

* Valid IP addresses and CIDR prefixes
* Valid port ranges (0–65 535)
* Supported protocol and action values
* Rejects wildcard-source DENY on all ports (would black-hole traffic)
* Flags overly permissive ALLOW rules on sensitive ports
* Detects conflicting actions on identical network flows
"""

import ipaddress
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_SUPPORTED_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "any"})
_SUPPORTED_ACTIONS = frozenset({"ALLOW", "DENY", "RATE_LIMIT", "MONITOR"})
_SENSITIVE_PORTS = frozenset(
    {
        22,
        23,
        3389,  # remote access
        3306,
        5432,
        6379,  # databases
        27017,
        9200,
        2379,  # NoSQL / search / etcd
    }
)
_MAX_PORT = 65535
_BROAD_CIDR_THRESHOLD = 16


class PolicyValidator:
    """Validates firewall rules for safety, correctness, and conflicts."""

    def is_ready(self) -> bool:
        return True

    def validate(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate a list of rules.

        Returns:
            ``{'valid': bool, 'issues': [{'severity', 'rule_id', 'message'}, ...]}``
            where *valid* is ``False`` when any issue has severity ``error``.
        """
        issues: List[Dict[str, Any]] = []

        for rule in rules:
            issues.extend(self._validate_single(rule))

        issues.extend(self._detect_conflicts(rules))

        has_errors = any(i["severity"] == "error" for i in issues)
        return {"valid": not has_errors, "issues": issues}

    # ── per-rule checks ───────────────────────────────────────────

    def _validate_single(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        rid = rule.get("id", "unknown")
        issues: List[Dict[str, Any]] = []
        issues.extend(self._check_action(rule, rid))
        issues.extend(self._check_protocol(rule, rid))
        issues.extend(self._check_ip(rule.get("source_ip", "*"), "source", rid))
        issues.extend(self._check_ip(rule.get("dest_ip", "*"), "destination", rid))
        issues.extend(self._check_port(rule, rid))
        issues.extend(self._check_breadth(rule, rid))
        return issues

    @staticmethod
    def _check_action(rule: Dict[str, Any], rid: str) -> List[Dict[str, Any]]:
        action = rule.get("action", "")
        if action not in _SUPPORTED_ACTIONS:
            return [_issue("error", rid, f"Unsupported action: {action}")]
        return []

    @staticmethod
    def _check_protocol(rule: Dict[str, Any], rid: str) -> List[Dict[str, Any]]:
        proto = rule.get("protocol", "any")
        if proto not in _SUPPORTED_PROTOCOLS:
            return [_issue("error", rid, f"Unsupported protocol: {proto}")]
        return []

    @staticmethod
    def _check_ip(value: str, label: str, rid: str) -> List[Dict[str, Any]]:
        if value in ("*", "any", ""):
            return []
        try:
            ipaddress.ip_address(value)
        except ValueError:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                return [_issue("error", rid, f"Invalid {label} IP: {value}")]
        return []

    @staticmethod
    def _check_port(rule: Dict[str, Any], rid: str) -> List[Dict[str, Any]]:
        port = rule.get("dest_port", "*")
        if port == "*":
            return []

        try:
            if isinstance(port, int):
                if not 0 <= port <= _MAX_PORT:
                    return [_issue("error", rid, f"Port {port} out of range")]
                return []

            s = str(port)
            if "-" in s:
                lo_s, hi_s = s.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
                issues: List[Dict[str, Any]] = []
                if not 0 <= lo <= _MAX_PORT:
                    issues.append(
                        _issue("error", rid, f"Range start {lo} out of range")
                    )
                if not 0 <= hi <= _MAX_PORT:
                    issues.append(_issue("error", rid, f"Range end {hi} out of range"))
                if lo > hi:
                    issues.append(_issue("error", rid, f"Range start > end: {lo}-{hi}"))
                return issues

            p = int(s)
            if not 0 <= p <= _MAX_PORT:
                return [_issue("error", rid, f"Port {p} out of range")]
        except (ValueError, TypeError):
            return [_issue("error", rid, f"Invalid port value: {port}")]

        return []

    @staticmethod
    def _check_breadth(rule: Dict[str, Any], rid: str) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        action = rule.get("action", "")
        src = rule.get("source_ip", "*")
        src_cidr = rule.get("source_cidr", "/32")
        port = rule.get("dest_port", "*")

        is_wildcard = src == "*"
        if not is_wildcard and src_cidr and src_cidr != "*":
            try:
                prefix = int(str(src_cidr).lstrip("/"))
                if prefix == 0:
                    is_wildcard = True
                elif prefix <= _BROAD_CIDR_THRESHOLD:
                    issues.append(
                        _issue(
                            "warning",
                            rid,
                            f"Source CIDR {src_cidr} is very broad "
                            f"(<= /{_BROAD_CIDR_THRESHOLD})",
                        )
                    )
            except (ValueError, TypeError):
                pass

        if action == "DENY" and is_wildcard and port == "*":
            issues.append(
                _issue(
                    "error",
                    rid,
                    "DENY from any source on all ports would block all traffic",
                )
            )

        if action == "ALLOW" and is_wildcard:
            port_int = _port_as_int(port)
            if port_int in _SENSITIVE_PORTS:
                issues.append(
                    _issue(
                        "warning",
                        rid,
                        f"ALLOW from any source on sensitive port {port_int}",
                    )
                )
            elif port == "*":
                issues.append(
                    _issue(
                        "warning",
                        rid,
                        "ALLOW from any source on all ports is overly permissive",
                    )
                )

        return issues

    # ── cross-rule conflict detection ─────────────────────────────

    @staticmethod
    def _detect_conflicts(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Dict[tuple, List[Dict[str, Any]]] = {}

        for rule in rules:
            key = (
                rule.get("source_ip", "*"),
                rule.get("source_cidr", "*"),
                rule.get("dest_ip", "*"),
                str(rule.get("dest_port", "*")),
                rule.get("protocol", "any"),
                rule.get("direction", "INBOUND"),
            )
            seen.setdefault(key, []).append(rule)

        issues: List[Dict[str, Any]] = []
        for _key, group in seen.items():
            actions = {r.get("action") for r in group}
            if len(actions) > 1:
                ids = [r.get("id", "?") for r in group]
                issues.append(
                    _issue(
                        "error",
                        ids[0],
                        f"Conflicting actions {sorted(actions)} on same "
                        f"target; affected rules: {', '.join(ids)}",
                    )
                )
        return issues


# ── helpers ───────────────────────────────────────────────────────


def _issue(severity: str, rule_id: str, message: str) -> Dict[str, Any]:
    return {"severity": severity, "rule_id": rule_id, "message": message}


def _port_as_int(port: Any) -> int:
    try:
        return int(port)
    except (ValueError, TypeError):
        return -1
