"""nftables firewall adapter."""

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Set

from vendors.base import BaseVendorAdapter

logger = logging.getLogger(__name__)

_ENFORCE_MODE = os.environ.get("ENFORCE_MODE", "false").lower() == "true"
_TABLE = "sentinel_fw"
_FAMILY = "inet"

_CHAIN_MAP = {
    "INBOUND": "sentinel_input",
    "OUTBOUND": "sentinel_output",
}
_HOOK_MAP = {
    "sentinel_input": "input",
    "sentinel_output": "output",
}
_ACTION_VERDICT = {
    "ALLOW": "accept",
    "DENY": "drop",
}


class NftablesAdapter(BaseVendorAdapter):
    """Translates SENTINEL rules to nftables ruleset format."""

    @property
    def name(self) -> str:
        return "nftables"

    @property
    def vendor_type(self) -> str:
        return "nftables"

    # ── public API ────────────────────────────────────────────────

    def translate_rules(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        translated = []
        for rule in rules:
            chain = _CHAIN_MAP.get(rule.get("direction", "INBOUND"), "sentinel_input")
            stmt = self._rule_to_statement(rule)
            translated.append(
                {
                    "rule_id": rule.get("id"),
                    "table": _TABLE,
                    "family": _FAMILY,
                    "chain": chain,
                    "statement": stmt,
                    "command": f"nft add rule {_FAMILY} {_TABLE} {chain} {stmt}",
                }
            )
        return translated

    def apply_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        translated = self.translate_rules(rules)
        script = self._build_script(translated)

        if not _ENFORCE_MODE:
            return {
                "success": True,
                "message": "Dry-run: nftables script generated but not executed",
                "script": script,
                "enforce_mode": False,
            }

        return self._execute_script(script)

    def remove_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        rule_ids = {r["id"] for r in rules if r.get("id")}

        if not _ENFORCE_MODE:
            return {
                "success": True,
                "message": "Dry-run: would remove rules by handle lookup",
                "rule_ids": sorted(rule_ids),
                "enforce_mode": False,
            }

        return self._remove_by_handle(rule_ids)

    def get_status(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor_type,
            "available": shutil.which("nft") is not None,
            "enforce_mode": _ENFORCE_MODE,
            "table": _TABLE,
        }

    # ── rule translation ──────────────────────────────────────────

    @staticmethod
    def _rule_to_statement(rule: Dict[str, Any]) -> str:
        parts: List[str] = []

        src = rule.get("source_ip", "*")
        if src and src != "*":
            cidr = rule.get("source_cidr", "/32")
            parts.append(f"ip saddr {src}{cidr}")

        dst = rule.get("dest_ip", "*")
        if dst and dst != "*":
            parts.append(f"ip daddr {dst}")

        proto = rule.get("protocol", "any")
        if proto != "any":
            parts.append(proto)
            dport = rule.get("dest_port", "*")
            if dport and dport != "*" and proto in ("tcp", "udp"):
                parts.append(f"dport {dport}")

        action_key = rule.get("action", "DENY")
        if action_key == "RATE_LIMIT":
            parts.append("limit rate over 10/second drop")
        elif action_key == "MONITOR":
            prefix = f"sentinel:{rule.get('id', 'rule')}:"
            parts.append(f'log prefix "{prefix[:63]}" accept')
        else:
            parts.append(_ACTION_VERDICT.get(action_key, "drop"))

        rule_id = rule.get("id", "")
        if rule_id:
            parts.append(f'comment "sentinel:{rule_id}"')

        return " ".join(parts)

    # ── script helpers ────────────────────────────────────────────

    @staticmethod
    def _build_script(translated: List[Dict[str, Any]]) -> str:
        chains: Dict[str, List[str]] = {}
        for t in translated:
            chains.setdefault(t["chain"], []).append(t["statement"])

        lines = [f"table {_FAMILY} {_TABLE} {{"]
        for chain in sorted(chains):
            hook = _HOOK_MAP.get(chain, "input")
            lines.append(f"  chain {chain} {{")
            lines.append(f"    type filter hook {hook} priority 0; policy accept;")
            for stmt in chains[chain]:
                lines.append(f"    {stmt}")
            lines.append("  }")
        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def _execute_script(script: str) -> Dict[str, Any]:
        try:
            subprocess.run(
                ["nft", "-f", "-"],
                input=script,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "success": True,
                "message": "nftables rules applied",
                "enforce_mode": True,
            }
        except subprocess.CalledProcessError as exc:
            logger.error("nft script failed: %s", exc.stderr)
            return {
                "success": False,
                "message": f"nft apply failed: {exc.stderr.strip()}",
                "enforce_mode": True,
            }
        except FileNotFoundError:
            logger.error("nft binary not found")
            return {
                "success": False,
                "message": "nft binary not found",
                "enforce_mode": True,
            }

    @staticmethod
    def _remove_by_handle(rule_ids: Set[str]) -> Dict[str, Any]:
        """Locate rules by their sentinel comment tag and delete by handle."""
        try:
            proc = subprocess.run(
                ["nft", "-j", "list", "table", _FAMILY, _TABLE],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                return {
                    "success": False,
                    "message": (
                        f"Failed to list nftables table: " f"{proc.stderr.strip()}"
                    ),
                }

            data = json.loads(proc.stdout)
            to_delete: List[tuple] = []

            for item in data.get("nftables", []):
                rule_obj = item.get("rule")
                if not rule_obj:
                    continue
                comment = rule_obj.get("comment", "")
                for rid in rule_ids:
                    if f"sentinel:{rid}" in comment:
                        chain = rule_obj.get("chain")
                        handle = rule_obj.get("handle")
                        if chain and handle is not None:
                            to_delete.append((chain, handle))

            errors: List[str] = []
            for chain, handle in to_delete:
                try:
                    subprocess.run(
                        [
                            "nft",
                            "delete",
                            "rule",
                            _FAMILY,
                            _TABLE,
                            chain,
                            "handle",
                            str(handle),
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                except subprocess.CalledProcessError as exc:
                    errors.append(f"handle {handle}: {exc.stderr.strip()}")

            if errors:
                return {
                    "success": False,
                    "message": (f"Partially removed; {len(errors)} error(s)"),
                    "errors": errors,
                }
            return {
                "success": True,
                "message": f"Removed {len(to_delete)} nftables rule(s)",
            }

        except Exception as exc:
            logger.error("nftables remove failed: %s", exc)
            return {"success": False, "message": str(exc)}
