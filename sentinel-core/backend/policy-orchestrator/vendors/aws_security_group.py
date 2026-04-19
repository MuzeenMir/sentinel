"""AWS Security Group firewall adapter."""

import logging
import os
from typing import Any, Dict, List, Optional

from vendors.base import BaseVendorAdapter

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError

    _HAS_BOTO3 = True
except ImportError:
    boto3 = None  # type: ignore[assignment]
    ClientError = Exception  # type: ignore[misc,assignment]
    _HAS_BOTO3 = False

_ENFORCE_MODE = os.environ.get("ENFORCE_MODE", "false").lower() == "true"


class AWSSecurityGroupAdapter(BaseVendorAdapter):
    """
    Translates SENTINEL rules to AWS EC2 Security Group
    ingress / egress permissions.

    Configuration is read from environment variables:

    * ``AWS_SECURITY_GROUP_ID`` – target security group
    * ``AWS_REGION`` – AWS region (default ``us-east-1``)
    """

    def __init__(
        self,
        security_group_id: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        self._sg_id = security_group_id or os.environ.get("AWS_SECURITY_GROUP_ID")
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._client: Any = None

    @property
    def name(self) -> str:
        return "AWS Security Group"

    @property
    def vendor_type(self) -> str:
        return "aws_security_group"

    # ── public API ────────────────────────────────────────────────

    def translate_rules(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        translated = []
        for rule in rules:
            action = rule.get("action", "")
            if action == "RATE_LIMIT":
                logger.debug(
                    "Skipping rule %s: RATE_LIMIT not supported by AWS SGs",
                    rule.get("id"),
                )
                continue

            perm = self._to_ip_permission(rule)
            translated.append(
                {
                    "rule_id": rule.get("id"),
                    "direction": rule.get("direction", "INBOUND"),
                    "action": action,
                    "ip_permission": perm,
                }
            )
        return translated

    def apply_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not self._sg_id:
            return {
                "success": False,
                "message": "AWS_SECURITY_GROUP_ID not configured",
            }

        translated = self.translate_rules(rules)

        if not _ENFORCE_MODE:
            return {
                "success": True,
                "message": "Dry-run: AWS SG changes generated but not applied",
                "permissions": [t["ip_permission"] for t in translated],
                "security_group_id": self._sg_id,
                "enforce_mode": False,
            }

        return self._apply_permissions(translated)

    def remove_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not self._sg_id:
            return {
                "success": False,
                "message": "AWS_SECURITY_GROUP_ID not configured",
            }

        translated = self.translate_rules(rules)

        if not _ENFORCE_MODE:
            return {
                "success": True,
                "message": "Dry-run: AWS SG removals generated but not applied",
                "permissions": [t["ip_permission"] for t in translated],
                "security_group_id": self._sg_id,
                "enforce_mode": False,
            }

        return self._revoke_permissions(translated)

    def get_status(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor_type,
            "available": _HAS_BOTO3 and bool(self._sg_id),
            "boto3_installed": _HAS_BOTO3,
            "security_group_id": self._sg_id,
            "region": self._region,
            "enforce_mode": _ENFORCE_MODE,
        }

    # ── translation helpers ───────────────────────────────────────

    @staticmethod
    def _to_ip_permission(rule: Dict[str, Any]) -> Dict[str, Any]:
        proto = rule.get("protocol", "any")
        if proto == "any":
            proto = "-1"

        perm: Dict[str, Any] = {"IpProtocol": proto}

        dport = rule.get("dest_port", "*")
        if dport and dport != "*" and proto != "-1":
            if isinstance(dport, str) and "-" in str(dport):
                lo, hi = str(dport).split("-", 1)
                perm["FromPort"] = int(lo)
                perm["ToPort"] = int(hi)
            else:
                port = int(dport)
                perm["FromPort"] = port
                perm["ToPort"] = port
        elif proto == "-1":
            perm["FromPort"] = -1
            perm["ToPort"] = -1

        src_ip = rule.get("source_ip", "*")
        cidr = rule.get("source_cidr", "/32")
        cidr_str = "0.0.0.0/0" if src_ip == "*" else f"{src_ip}{cidr}"

        perm["IpRanges"] = [
            {
                "CidrIp": cidr_str,
                "Description": f"SENTINEL rule {rule.get('id', 'unknown')}",
            }
        ]

        return perm

    # ── EC2 API wrappers ──────────────────────────────────────────

    def _get_client(self) -> Any:
        if not _HAS_BOTO3:
            raise RuntimeError("boto3 is required but not installed")
        if self._client is None:
            self._client = boto3.client("ec2", region_name=self._region)
        return self._client

    def _apply_permissions(self, translated: List[Dict[str, Any]]) -> Dict[str, Any]:
        errors: List[str] = []
        applied = 0

        try:
            client = self._get_client()
        except RuntimeError as exc:
            return {"success": False, "message": str(exc)}

        for t in translated:
            perm = t["ip_permission"]
            direction = t.get("direction", "INBOUND")
            action = t.get("action", "ALLOW")

            try:
                if action in ("ALLOW", "MONITOR"):
                    if direction == "INBOUND":
                        client.authorize_security_group_ingress(
                            GroupId=self._sg_id,
                            IpPermissions=[perm],
                        )
                    else:
                        client.authorize_security_group_egress(
                            GroupId=self._sg_id,
                            IpPermissions=[perm],
                        )
                elif action == "DENY":
                    if direction == "INBOUND":
                        client.revoke_security_group_ingress(
                            GroupId=self._sg_id,
                            IpPermissions=[perm],
                        )
                    else:
                        client.revoke_security_group_egress(
                            GroupId=self._sg_id,
                            IpPermissions=[perm],
                        )
                applied += 1
            except ClientError as exc:
                code = getattr(
                    getattr(exc, "response", {}),
                    "get",
                    lambda *a: {},
                )("Error", {}).get("Code", "")
                if code == "InvalidPermission.Duplicate":
                    applied += 1
                else:
                    msg = str(exc)
                    errors.append(f"rule {t.get('rule_id')}: {msg}")
                    logger.error("AWS SG apply error: %s", msg)
            except Exception as exc:
                errors.append(f"rule {t.get('rule_id')}: {exc}")
                logger.error("AWS SG apply error: %s", exc)

        if errors:
            return {
                "success": False,
                "message": (
                    f"Applied {applied}/{len(translated)}, " f"{len(errors)} error(s)"
                ),
                "errors": errors,
                "enforce_mode": True,
            }
        return {
            "success": True,
            "message": f"Applied {applied} permission(s) to {self._sg_id}",
            "enforce_mode": True,
        }

    def _revoke_permissions(self, translated: List[Dict[str, Any]]) -> Dict[str, Any]:
        errors: List[str] = []
        removed = 0

        try:
            client = self._get_client()
        except RuntimeError as exc:
            return {"success": False, "message": str(exc)}

        for t in translated:
            perm = t["ip_permission"]
            direction = t.get("direction", "INBOUND")

            try:
                if direction == "INBOUND":
                    client.revoke_security_group_ingress(
                        GroupId=self._sg_id,
                        IpPermissions=[perm],
                    )
                else:
                    client.revoke_security_group_egress(
                        GroupId=self._sg_id,
                        IpPermissions=[perm],
                    )
                removed += 1
            except ClientError as exc:
                code = getattr(
                    getattr(exc, "response", {}),
                    "get",
                    lambda *a: {},
                )("Error", {}).get("Code", "")
                if code == "InvalidPermission.NotFound":
                    removed += 1
                else:
                    msg = str(exc)
                    errors.append(f"rule {t.get('rule_id')}: {msg}")
                    logger.error("AWS SG revoke error: %s", msg)
            except Exception as exc:
                errors.append(f"rule {t.get('rule_id')}: {exc}")
                logger.error("AWS SG revoke error: %s", exc)

        if errors:
            return {
                "success": False,
                "message": (
                    f"Removed {removed}/{len(translated)}, " f"{len(errors)} error(s)"
                ),
                "errors": errors,
                "enforce_mode": True,
            }
        return {
            "success": True,
            "message": f"Removed {removed} permission(s) from {self._sg_id}",
            "enforce_mode": True,
        }
