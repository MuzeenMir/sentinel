"""
Base vendor class for firewall integrations.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any


class BaseVendor(ABC):
    """
    Abstract base class for firewall vendor integrations.
    
    All vendor implementations must inherit from this class
    and implement the required methods.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self._connected = False
    
    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Return vendor identifier."""
        pass
    
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the firewall."""
        pass
    
    @abstractmethod
    def disconnect(self):
        """Close connection to the firewall."""
        pass
    
    @abstractmethod
    def apply_rules(self, rules: List[Dict]) -> Dict[str, Any]:
        """
        Apply rules to the firewall.
        
        Args:
            rules: List of rules to apply
            
        Returns:
            Result dict with 'success' and 'message' keys
        """
        pass
    
    @abstractmethod
    def remove_rules(self, rules: List[Dict]) -> Dict[str, Any]:
        """
        Remove rules from the firewall.
        
        Args:
            rules: List of rules to remove
            
        Returns:
            Result dict with 'success' and 'message' keys
        """
        pass
    
    @abstractmethod
    def translate_rules(self, rules: List[Dict]) -> List[str]:
        """
        Translate generic rules to vendor-specific format.
        
        Args:
            rules: List of generic rules
            
        Returns:
            List of vendor-specific rule strings/commands
        """
        pass
    
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        Get vendor connection and status information.
        
        Returns:
            Status dict with connection info and statistics
        """
        pass
    
    def is_connected(self) -> bool:
        """Check if connected to the firewall."""
        return self._connected
