"""TTL reaper for reversible firewall enforcement actions."""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

# Shared modules (audit_logger, _lib) live one level up — both in the repo and
# in the container image (WORKDIR /app/policy-orchestrator, shared at /app).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_logger import AuditCategory, audit_log as default_audit_log  # noqa: E402
from enforcement_actions import EnforcementActionStore  # noqa: E402
from vendors.vendor_factory import VendorFactory  # noqa: E402


logger = logging.getLogger(__name__)


class EnforcementReaper:
    """Roll back expired, unconfirmed enforcement actions."""

    def __init__(
        self,
        *,
        store: EnforcementActionStore | None = None,
        vendor_factory: VendorFactory | None = None,
        audit_log: Callable[..., Any] | None = None,
        alert_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.store = store or EnforcementActionStore.from_env()
        self.vendor_factory = vendor_factory or VendorFactory()
        self.audit_log = audit_log or default_audit_log
        self.alert_callback = alert_callback or self._log_alert

    def run_once(self, *, limit: int = 100) -> dict[str, int]:
        actions = self.store.claim_expired_actions(limit=limit)
        result = {"reverted": 0, "failed": 0, "claimed": len(actions)}

        for action in actions:
            action_id = action["action_id"]
            try:
                vendor = self.vendor_factory.get_vendor(action["vendor_name"])
                if vendor is None:
                    raise RuntimeError(f"Unknown vendor: {action['vendor_name']}")

                inverse_result = vendor.remove_rules(action.get("rules") or [])
                if not inverse_result.get("success"):
                    raise RuntimeError(
                        inverse_result.get("message")
                        or inverse_result.get("error")
                        or str(inverse_result)
                    )

                self.store.mark_reverted(
                    action_id,
                    reason="ttl_expired_auto_rollback",
                )
                self.audit_log(
                    AuditCategory.POLICY,
                    "enforcement_reverted",
                    tenant_id=action.get("tenant_id"),
                    detail={
                        "action_id": action_id,
                        "policy_id": action.get("policy_id"),
                        "vendor": action.get("vendor_name"),
                        "reason": "ttl_expired_auto_rollback",
                    },
                )
                result["reverted"] += 1
            except Exception as exc:
                reason = str(exc)
                logger.warning(
                    "enforcement_revert_failed action=%s: %s", action_id, exc
                )
                self.store.mark_revert_failed(action_id, reason=reason)
                self.alert_callback(
                    {
                        "type": "enforcement_revert_failed",
                        "action_id": action_id,
                        "vendor": action.get("vendor_name"),
                        "reason": reason,
                    }
                )
                try:
                    self.audit_log(
                        AuditCategory.POLICY,
                        "enforcement_revert_failed",
                        tenant_id=action.get("tenant_id"),
                        detail={
                            "action_id": action_id,
                            "policy_id": action.get("policy_id"),
                            "vendor": action.get("vendor_name"),
                            "reason": reason,
                        },
                    )
                except Exception:
                    logger.exception("Failed to audit enforcement revert failure")
                result["failed"] += 1

        return result

    @staticmethod
    def _log_alert(alert: dict[str, Any]) -> None:
        logger.error("enforcement_reaper_alert %s", alert)


def beat() -> None:
    """Touch the heartbeat file the container healthcheck watches.

    Only beaten after a completed cycle, so a reaper hung mid-run_once (e.g.
    on a stuck DB connection) stops beating and the container goes unhealthy
    instead of silently leaving expired enforcement actions applied.
    """
    Path(os.environ.get("REAPER_HEARTBEAT_PATH", "/tmp/reaper-heartbeat")).touch()


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    interval = int(os.environ.get("ENFORCEMENT_REAPER_INTERVAL_SECONDS", "30"))
    batch_size = int(os.environ.get("ENFORCEMENT_REAPER_BATCH_SIZE", "100"))
    reaper = EnforcementReaper()

    while True:
        reaper.run_once(limit=batch_size)
        beat()
        time.sleep(interval)


if __name__ == "__main__":
    main()
