"""
Vendor Factory for creating firewall vendor instances.
"""
import os
import logging
from typing import Dict, List, Any, Optional
from .base_vendor import BaseVendor
from .iptables_vendor import IptablesVendor
from .aws_vendor import AWSSecurityGroupVendor

logger = logging.getLogger(__name__)


class VendorFactory:
    """
    Factory for creating and managing firewall vendor instances.
    """
    
    # Registry of available vendors
    VENDOR_REGISTRY = {
        'iptables': IptablesVendor,
        'aws_security_group': AWSSecurityGroupVendor,
        'aws_sg': AWSSecurityGroupVendor,  # Alias
    }
    
    def __init__(self):
        self._instances: Dict[str, BaseVendor] = {}
        self._configs = self._load_configs()
    
    def _load_configs(self) -> Dict[str, Dict]:
        """Load vendor configurations from environment."""
        configs = {
            'iptables': {
                'chain': os.environ.get('IPTABLES_CHAIN', 'SENTINEL'),
                'table': os.environ.get('IPTABLES_TABLE', 'filter')
            },
            'aws_security_group': {
                'region': os.environ.get('AWS_REGION', 'us-east-1'),
                'security_group_id': os.environ.get('AWS_SECURITY_GROUP_ID')
            }
        }
        return configs
    
    def get_vendor(self, vendor_name: str) -> Optional[BaseVendor]:
        """
        Get or create a vendor instance.
        
        Args:
            vendor_name: Name of the vendor
            
        Returns:
            Vendor instance or None if not found
        """
        # Check for existing instance
        if vendor_name in self._instances:
            return self._instances[vendor_name]
        
        # Create new instance
        vendor_class = self.VENDOR_REGISTRY.get(vendor_name.lower())
        if not vendor_class:
            logger.warning(f"Unknown vendor: {vendor_name}")
            return None
        
        try:
            config = self._configs.get(vendor_name, {})
            vendor = vendor_class(config)
            
            # Attempt to connect
            if vendor.connect():
                self._instances[vendor_name] = vendor
                logger.info(f"Created vendor instance: {vendor_name}")
                return vendor
            else:
                logger.warning(f"Failed to connect to vendor: {vendor_name}")
                return vendor  # Return anyway for translation purposes
        
        except Exception as e:
            logger.error(f"Failed to create vendor {vendor_name}: {e}")
            return None
    
    def get_available_vendors(self) -> List[Dict[str, Any]]:
        """Get list of available vendors with status."""
        vendors = []
        
        for name, vendor_class in self.VENDOR_REGISTRY.items():
            if name.endswith('_sg'):  # Skip aliases
                continue
            
            status = 'available'
            connected = False
            
            if name in self._instances:
                connected = self._instances[name].is_connected()
                status = 'connected' if connected else 'disconnected'
            
            vendors.append({
                'name': name,
                'status': status,
                'connected': connected,
                'class': vendor_class.__name__
            })
        
        return vendors
    
    def disconnect_all(self):
        """Disconnect all vendor instances."""
        for vendor in self._instances.values():
            try:
                vendor.disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting vendor: {e}")
        
        self._instances.clear()
