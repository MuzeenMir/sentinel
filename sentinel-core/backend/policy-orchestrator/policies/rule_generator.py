"""
Rule generation from SENTINEL policy definitions.

Converts high-level policy dicts (action, source, destination, protocol)
into normalised firewall rule dicts consumable by vendor adapters and
the policy engine's conflict-detection index.
"""
import ipaddress
import logging
import uuid
from typing import Any, Dict, List, Tuple, Union

logger = logging.getLogger(__name__)

_SUPPORTED_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "any"})
_SUPPORTED_ACTIONS = frozenset({"ALLOW", "DENY", "RATE_LIMIT", "MONITOR"})
_VALID_DIRECTIONS = frozenset({"INBOUND", "OUTBOUND"})
_MAX_PORT = 65535


class RuleGenerator:
    """Converts policy definitions into normalised firewall rule dicts."""

    def generate(self, policy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate firewall rules from a policy definition.

        Args:
            policy_data: Policy dict with at minimum ``action``, and
                optionally ``source``, ``destination``, ``protocol``,
                ``priority``, ``direction``.

        Returns:
            List of rule dicts, each containing *id*, *action*,
            *source_ip*, *source_cidr*, *dest_ip*, *dest_port*,
            *protocol*, *priority*, *direction*.

        Raises:
            ValueError: When required fields are missing or malformed.
        """
        action = self._require_action(policy_data)
        protocol = self._parse_protocol(policy_data)
        priority = int(policy_data.get("priority", 100))
        direction = self._parse_direction(policy_data)

        sources = self._parse_sources(policy_data)
        dest_ips = self._parse_dest_ips(policy_data)
        ports = self._parse_ports(policy_data)

        rules: List[Dict[str, Any]] = []
        for src_ip, src_cidr in sources:
            for dest_ip in dest_ips:
                for port in ports:
                    rules.append({
                        "id": f"rule_{uuid.uuid4().hex[:12]}",
                        "action": action,
                        "source_ip": src_ip,
                        "source_cidr": src_cidr,
                        "dest_ip": dest_ip,
                        "dest_port": port,
                        "protocol": protocol,
                        "priority": priority,
                        "direction": direction,
                    })

        logger.debug(
            "Generated %d rule(s) for policy '%s'",
            len(rules),
            policy_data.get("name", "unnamed"),
        )
        return rules

    # ── action / protocol / direction ─────────────────────────────

    @staticmethod
    def _require_action(data: Dict[str, Any]) -> str:
        raw = data.get("action", "").upper()
        if raw not in _SUPPORTED_ACTIONS:
            raise ValueError(
                f"Unsupported action '{raw}'; "
                f"expected one of {sorted(_SUPPORTED_ACTIONS)}"
            )
        return raw

    @staticmethod
    def _parse_protocol(data: Dict[str, Any]) -> str:
        raw = str(data.get("protocol", "any")).lower()
        if raw not in _SUPPORTED_PROTOCOLS:
            raise ValueError(
                f"Unsupported protocol '{raw}'; "
                f"expected one of {sorted(_SUPPORTED_PROTOCOLS)}"
            )
        return raw

    @staticmethod
    def _parse_direction(data: Dict[str, Any]) -> str:
        raw = data.get("direction", "INBOUND").upper()
        if raw not in _VALID_DIRECTIONS:
            raise ValueError(
                f"Unsupported direction '{raw}'; "
                f"expected one of {sorted(_VALID_DIRECTIONS)}"
            )
        return raw

    # ── source parsing ────────────────────────────────────────────

    def _parse_sources(self, data: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Return ``[(ip, cidr), ...]`` from the policy's ``source`` field."""
        source = data.get("source") or {}
        if isinstance(source, str):
            return [self._normalise_ip_cidr(source, "/32")]

        ip_field = source.get("ip")
        cidr = source.get("cidr", "/32")

        if not ip_field:
            return [("*", "*")]

        ips = ip_field if isinstance(ip_field, list) else [ip_field]
        return [self._normalise_ip_cidr(ip, cidr) for ip in ips]

    # ── destination parsing ───────────────────────────────────────

    def _parse_dest_ips(self, data: Dict[str, Any]) -> List[str]:
        dest = data.get("destination") or {}
        if isinstance(dest, str):
            return [self._validate_ip(dest)]

        dest_ip = dest.get("ip") if isinstance(dest, dict) else None
        if not dest_ip:
            return ["*"]

        ips = dest_ip if isinstance(dest_ip, list) else [dest_ip]
        return [self._validate_ip(ip) for ip in ips]

    # ── port parsing ──────────────────────────────────────────────

    def _parse_ports(self, data: Dict[str, Any]) -> List[Union[int, str]]:
        """
        Return a list of port values.

        Each element is an ``int`` for a single port, a ``"lo-hi"``
        string for a range, or ``"*"`` for all ports.
        """
        dest = data.get("destination") or {}
        raw = dest.get("port") if isinstance(dest, dict) else None

        if raw is None or raw == "*":
            return ["*"]

        if isinstance(raw, list):
            out: List[Union[int, str]] = []
            for item in raw:
                out.extend(self._coerce_port(item))
            return out

        return self._coerce_port(raw)

    def _coerce_port(self, value: Any) -> List[Union[int, str]]:
        if isinstance(value, int):
            self._check_port_bound(value)
            return [value]

        s = str(value).strip()
        if "-" in s:
            parts = s.split("-", 1)
            lo, hi = int(parts[0]), int(parts[1])
            self._check_port_bound(lo)
            self._check_port_bound(hi)
            if lo > hi:
                raise ValueError(f"Invalid port range: {lo}-{hi}")
            return [f"{lo}-{hi}"]

        port = int(s)
        self._check_port_bound(port)
        return [port]

    @staticmethod
    def _check_port_bound(port: int) -> None:
        if not 0 <= port <= _MAX_PORT:
            raise ValueError(f"Port {port} outside valid range 0\u2013{_MAX_PORT}")

    # ── IP / CIDR helpers ─────────────────────────────────────────

    @staticmethod
    def _validate_ip(ip: str) -> str:
        if ip in ("*", "any"):
            return "*"
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            try:
                ipaddress.ip_network(ip, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid IP or network: {ip}") from exc
        return ip

    def _normalise_ip_cidr(self, ip: str, cidr: str) -> Tuple[str, str]:
        if ip in ("*", "any"):
            return ("*", "*")

        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
            addr, prefix = ip.rsplit("/", 1)
            return (addr, f"/{prefix}")

        self._validate_ip(ip)

        if not cidr.startswith("/"):
            cidr = f"/{cidr}"
        prefix_len = int(cidr.lstrip("/"))

        try:
            addr_obj = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc

        max_prefix = 32 if addr_obj.version == 4 else 128
        if not 0 <= prefix_len <= max_prefix:
            raise ValueError(
                f"CIDR prefix {cidr} out of range for IPv{addr_obj.version}"
            )

        return (ip, cidr)
