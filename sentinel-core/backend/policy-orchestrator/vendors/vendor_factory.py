"""Registry and factory for firewall vendor adapters."""
import logging
from typing import Any, Dict, List, Optional, Type

from vendors.base import BaseVendorAdapter

logger = logging.getLogger(__name__)


class VendorFactory:
    """
    Central registry of vendor adapters.

    Built-in adapters (iptables, nftables, AWS Security Group) are
    registered automatically.  Additional adapters can be added at
    runtime via :meth:`register`.
    """

    def __init__(self) -> None:
        self._adapters: Dict[str, Type[BaseVendorAdapter]] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        from vendors.iptables import IptablesAdapter
        from vendors.nftables import NftablesAdapter
        from vendors.aws_security_group import AWSSecurityGroupAdapter

        self._adapters["iptables"] = IptablesAdapter
        self._adapters["nftables"] = NftablesAdapter
        self._adapters["aws_security_group"] = AWSSecurityGroupAdapter

    def register(
        self, vendor_key: str, adapter_cls: Type[BaseVendorAdapter]
    ) -> None:
        """Register a custom vendor adapter class under *vendor_key*."""
        self._adapters[vendor_key] = adapter_cls
        logger.info("Registered vendor adapter: %s", vendor_key)

    def get_vendor(self, vendor_name: str) -> Optional[BaseVendorAdapter]:
        """Instantiate and return a vendor adapter, or ``None``."""
        cls = self._adapters.get(vendor_name)
        if cls is None:
            logger.warning("Unknown vendor requested: %s", vendor_name)
            return None
        return cls()

    def get_available_vendors(self) -> List[Dict[str, Any]]:
        """Return a summary list of every registered vendor."""
        vendors: List[Dict[str, Any]] = []
        for key, cls in self._adapters.items():
            try:
                adapter = cls()
                status = adapter.get_status()
                vendors.append({
                    "name": adapter.name,
                    "type": adapter.vendor_type,
                    "available": status.get("available", False),
                })
            except Exception as exc:
                logger.warning("Vendor %s status check failed: %s", key, exc)
                vendors.append({
                    "name": key,
                    "type": key,
                    "available": False,
                })
        return vendors
