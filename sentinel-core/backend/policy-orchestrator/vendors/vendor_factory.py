"""
Vendor Factory for creating firewall vendor instances.
Uses AdapterVendor (firewall-adapters package) for all five adapter types when available.
Falls back to legacy IptablesVendor/AWSSecurityGroupVendor if firewall_adapters not installed.
"""
import os
import logging
from typing import Dict, List, Any, Optional
from .base_vendor import BaseVendor
from .iptables_vendor import IptablesVendor
from .aws_vendor import AWSSecurityGroupVendor

logger = logging.getLogger(__name__)

try:
    from .adapter_vendor import AdapterVendor
    HAS_ADAPTER_VENDOR = True
except ImportError:
    AdapterVendor = None
    HAS_ADAPTER_VENDOR = False


def _build_registry() -> Dict[str, type]:
    """Build vendor registry: prefer AdapterVendor for all five when available."""
    registry = {}
    if HAS_ADAPTER_VENDOR and AdapterVendor is not None:
        registry['iptables'] = AdapterVendor
        registry['nftables'] = AdapterVendor
        registry['aws'] = AdapterVendor
        registry['aws_security_group'] = AdapterVendor  # Alias
        registry['aws_sg'] = AdapterVendor  # Alias
        registry['azure'] = AdapterVendor
        registry['gcp'] = AdapterVendor
    else:
        registry['iptables'] = IptablesVendor
        registry['aws_security_group'] = AWSSecurityGroupVendor
        registry['aws_sg'] = AWSSecurityGroupVendor
    return registry


class VendorFactory:
    """
    Factory for creating and managing firewall vendor instances.
    """

    VENDOR_REGISTRY = _build_registry()

    def __init__(self):
        self._instances: Dict[str, BaseVendor] = {}
        self._configs = self._load_configs()

    def _load_configs(self) -> Dict[str, Dict]:
        """Load vendor configurations from environment."""
        configs = {
            'iptables': {
                'adapter_type': 'iptables',
                'chain': os.environ.get('IPTABLES_CHAIN', 'SENTINEL'),
                'table': os.environ.get('IPTABLES_TABLE', 'filter')
            },
            'nftables': {'adapter_type': 'nftables'},
            'aws': {
                'adapter_type': 'aws',
                'region': os.environ.get('AWS_REGION', 'us-east-1'),
                'security_group_id': os.environ.get('AWS_SECURITY_GROUP_ID')
            },
            'aws_security_group': {
                'adapter_type': 'aws',
                'region': os.environ.get('AWS_REGION', 'us-east-1'),
                'security_group_id': os.environ.get('AWS_SECURITY_GROUP_ID')
            },
            'aws_sg': {
                'adapter_type': 'aws',
                'region': os.environ.get('AWS_REGION', 'us-east-1'),
                'security_group_id': os.environ.get('AWS_SECURITY_GROUP_ID')
            },
            'azure': {
                'adapter_type': 'azure',
                'subscription_id': os.environ.get('AZURE_SUBSCRIPTION_ID'),
                'resource_group': os.environ.get('AZURE_RESOURCE_GROUP'),
                'nsg_name': os.environ.get('AZURE_NSG_NAME'),
            },
            'gcp': {
                'adapter_type': 'gcp',
                'project_id': os.environ.get('GCP_PROJECT_ID'),
                'network': os.environ.get('GCP_NETWORK', 'default'),
                'credentials_path': os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'),
            },
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
