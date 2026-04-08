"""Abstract base class for firewall vendor adapters."""
import abc
from typing import Any, Dict, List


class BaseVendorAdapter(abc.ABC):
    """
    Interface that every firewall vendor adapter must implement.

    Vendor adapters translate generic SENTINEL rules into vendor-specific
    commands / API calls and optionally execute them.  By default all
    adapters operate in *dry-run* mode (``ENFORCE_MODE`` env-var
    defaults to ``false``).
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable adapter name."""

    @property
    @abc.abstractmethod
    def vendor_type(self) -> str:
        """Machine key used by :class:`VendorFactory` lookups."""

    @abc.abstractmethod
    def apply_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Apply firewall rules.

        Returns:
            Result dict with at least ``success`` (bool) and
            ``message`` (str).
        """

    @abc.abstractmethod
    def remove_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Remove previously applied rules.

        Returns:
            Result dict with at least ``success`` (bool) and
            ``message`` (str).
        """

    @abc.abstractmethod
    def translate_rules(
        self, rules: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Translate generic SENTINEL rules to the vendor-specific
        representation *without* applying them.

        Returns:
            List of vendor-specific rule dicts.
        """

    @abc.abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        Return vendor availability and health info.

        Must include at least an ``available`` (bool) key.
        """
