"""iptables firewall adapter."""
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List

from vendors.base import BaseVendorAdapter

logger = logging.getLogger(__name__)

_ENFORCE_MODE = os.environ.get("ENFORCE_MODE", "false").lower() == "true"

_ACTION_TARGET = {
    "ALLOW": "ACCEPT",
    "DENY": "DROP",
    "RATE_LIMIT": "DROP",
    "MONITOR": "LOG",
}

_DIRECTION_CHAIN = {
    "INBOUND": "INPUT",
    "OUTBOUND": "OUTPUT",
}

_PROTO_MAP = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "any": "all",
}


class IptablesAdapter(BaseVendorAdapter):
    """Translates SENTINEL rules to iptables commands."""

    @property
    def name(self) -> str:
        return "iptables"

    @property
    def vendor_type(self) -> str:
        return "iptables"

    # ── public API ────────────────────────────────────────────────

    def translate_rules(
        self, rules: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        translated = []
        for rule in rules:
            cmds = self._rule_to_commands(rule, flag="-A")
            translated.append({
                "rule_id": rule.get("id"),
                "commands": cmds,
                "original_rule": rule,
            })
        return translated

    def apply_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        translated = self.translate_rules(rules)
        commands = [c for t in translated for c in t["commands"]]

        if not _ENFORCE_MODE:
            return {
                "success": True,
                "message": "Dry-run: commands generated but not executed",
                "commands": commands,
                "enforce_mode": False,
            }

        return self._execute(commands)

    def remove_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        commands: List[str] = []
        for rule in rules:
            commands.extend(self._rule_to_commands(rule, flag="-D"))

        if not _ENFORCE_MODE:
            return {
                "success": True,
                "message": "Dry-run: remove commands generated but not executed",
                "commands": commands,
                "enforce_mode": False,
            }

        return self._execute(commands)

    def get_status(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor_type,
            "available": shutil.which("iptables") is not None,
            "enforce_mode": _ENFORCE_MODE,
        }

    # ── internals ─────────────────────────────────────────────────

    @staticmethod
    def _rule_to_commands(
        rule: Dict[str, Any], flag: str = "-A"
    ) -> List[str]:
        chain = _DIRECTION_CHAIN.get(
            rule.get("direction", "INBOUND"), "INPUT"
        )
        target = _ACTION_TARGET.get(rule.get("action", "DENY"), "DROP")
        proto = _PROTO_MAP.get(rule.get("protocol", "any"), "all")

        parts: List[str] = ["iptables", flag, chain]

        if proto != "all":
            parts.extend(["-p", proto])

        src = rule.get("source_ip", "*")
        if src and src != "*":
            cidr = rule.get("source_cidr", "/32")
            parts.extend(["-s", f"{src}{cidr}"])

        dst = rule.get("dest_ip", "*")
        if dst and dst != "*":
            parts.extend(["-d", dst])

        dport = rule.get("dest_port", "*")
        if dport and dport != "*" and proto in ("tcp", "udp"):
            port_str = str(dport).replace("-", ":")
            parts.extend(["--dport", port_str])

        if rule.get("action") == "RATE_LIMIT":
            parts.extend([
                "-m", "hashlimit",
                "--hashlimit-above", "10/sec",
                "--hashlimit-mode", "srcip",
                "--hashlimit-name", rule.get("id", "sentinel")[:15],
            ])

        if target == "LOG":
            prefix = f"SENTINEL:{rule.get('id', 'rule')}:"
            parts.extend(["--log-prefix", prefix[:29]])

        parts.extend(["-j", target])
        return [" ".join(parts)]

    @staticmethod
    def _execute(commands: List[str]) -> Dict[str, Any]:
        errors: List[str] = []
        for cmd in commands:
            try:
                subprocess.run(
                    cmd.split(),
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                errors.append(f"{cmd}: {exc.stderr.strip()}")
                logger.error("iptables command failed: %s – %s", cmd, exc.stderr)
            except FileNotFoundError:
                errors.append(f"{cmd}: iptables binary not found")
                logger.error("iptables binary not found")
                break

        if errors:
            return {
                "success": False,
                "message": "Some iptables commands failed",
                "errors": errors,
                "enforce_mode": True,
            }
        return {
            "success": True,
            "message": f"Applied {len(commands)} iptables command(s)",
            "enforce_mode": True,
        }
