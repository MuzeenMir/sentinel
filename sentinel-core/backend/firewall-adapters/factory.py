"""
Firewall Adapter Factory

Factory for creating appropriate firewall adapters based on environment.
"""
import os
import logging
from typing import Optional, Dict, Any

from .base import FirewallAdapter
from .iptables_adapter import IptablesAdapter
from .nftables_adapter import NftablesAdapter
from .aws_sg_adapter import AWSSecurityGroupAdapter
from .azure_nsg_adapter import AzureNSGAdapter
from .gcp_firewall_adapter import GCPFirewallAdapter

logger = logging.getLogger(__name__)


def get_adapter(
    adapter_type: Optional[str] = None,
    **kwargs
) -> FirewallAdapter:
    """
    Get appropriate firewall adapter.
    
    Args:
        adapter_type: Specific adapter type to use. If None, auto-detect.
        **kwargs: Adapter-specific configuration
        
    Returns:
        FirewallAdapter instance
        
    Adapter types:
        - 'iptables': Linux iptables
        - 'nftables': Modern Linux nftables
        - 'aws': AWS Security Groups
        - 'azure': Azure NSGs
        - 'gcp': GCP Firewall
        - 'auto': Auto-detect (default)
    """
    adapter_type = adapter_type or os.environ.get('SENTINEL_FIREWALL_TYPE', 'auto')
    
    if adapter_type == 'iptables':
        return IptablesAdapter()
    
    elif adapter_type == 'nftables':
        return NftablesAdapter()
    
    elif adapter_type == 'aws':
        return AWSSecurityGroupAdapter(
            security_group_id=kwargs.get('security_group_id') or os.environ.get('AWS_SECURITY_GROUP_ID'),
            region=kwargs.get('region') or os.environ.get('AWS_REGION', 'us-east-1'),
            aws_access_key=kwargs.get('aws_access_key') or os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_key=kwargs.get('aws_secret_key') or os.environ.get('AWS_SECRET_ACCESS_KEY'),
        )
    
    elif adapter_type == 'azure':
        return AzureNSGAdapter(
            subscription_id=kwargs.get('subscription_id') or os.environ.get('AZURE_SUBSCRIPTION_ID'),
            resource_group=kwargs.get('resource_group') or os.environ.get('AZURE_RESOURCE_GROUP'),
            nsg_name=kwargs.get('nsg_name') or os.environ.get('AZURE_NSG_NAME'),
        )
    
    elif adapter_type == 'gcp':
        return GCPFirewallAdapter(
            project_id=kwargs.get('project_id') or os.environ.get('GCP_PROJECT_ID'),
            network=kwargs.get('network') or os.environ.get('GCP_NETWORK', 'default'),
            credentials_path=kwargs.get('credentials_path') or os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'),
        )
    
    elif adapter_type == 'auto':
        return _auto_detect_adapter()
    
    else:
        raise ValueError(f"Unknown adapter type: {adapter_type}")


def _auto_detect_adapter() -> FirewallAdapter:
    """
    Auto-detect the appropriate firewall adapter.
    
    Detection order:
    1. Check for cloud provider metadata
    2. Check for nftables
    3. Fall back to iptables
    """
    # Check for cloud environment
    cloud = _detect_cloud_provider()
    
    if cloud == 'aws':
        sg_id = os.environ.get('AWS_SECURITY_GROUP_ID')
        if sg_id:
            adapter = AWSSecurityGroupAdapter(security_group_id=sg_id)
            if adapter.is_available:
                logger.info("Auto-detected AWS environment")
                return adapter
    
    elif cloud == 'azure':
        subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID')
        resource_group = os.environ.get('AZURE_RESOURCE_GROUP')
        nsg_name = os.environ.get('AZURE_NSG_NAME')
        if subscription_id and resource_group and nsg_name:
            adapter = AzureNSGAdapter(subscription_id, resource_group, nsg_name)
            if adapter.is_available:
                logger.info("Auto-detected Azure environment")
                return adapter
    
    elif cloud == 'gcp':
        project_id = os.environ.get('GCP_PROJECT_ID')
        if project_id:
            adapter = GCPFirewallAdapter(project_id=project_id)
            if adapter.is_available:
                logger.info("Auto-detected GCP environment")
                return adapter
    
    # Try local firewalls
    nftables = NftablesAdapter()
    if nftables.is_available:
        logger.info("Auto-detected nftables")
        return nftables
    
    iptables = IptablesAdapter()
    if iptables.is_available:
        logger.info("Auto-detected iptables")
        return iptables
    
    # Return iptables anyway (will fail gracefully)
    logger.warning("No firewall detected, using iptables (may not work)")
    return iptables


def _detect_cloud_provider() -> Optional[str]:
    """Detect cloud provider from metadata or environment."""
    import subprocess
    
    # Check environment variables first
    if os.environ.get('AWS_EXECUTION_ENV') or os.environ.get('AWS_REGION'):
        return 'aws'
    
    if os.environ.get('AZURE_SUBSCRIPTION_ID'):
        return 'azure'
    
    if os.environ.get('GCP_PROJECT_ID') or os.environ.get('GOOGLE_CLOUD_PROJECT'):
        return 'gcp'
    
    # Try metadata services
    try:
        # AWS
        result = subprocess.run(
            ['curl', '-s', '-m', '1', 'http://169.254.169.254/latest/meta-data/'],
            capture_output=True,
            timeout=2
        )
        if result.returncode == 0:
            return 'aws'
    except:
        pass
    
    try:
        # Azure
        result = subprocess.run(
            ['curl', '-s', '-m', '1', '-H', 'Metadata:true',
             'http://169.254.169.254/metadata/instance?api-version=2021-02-01'],
            capture_output=True,
            timeout=2
        )
        if result.returncode == 0 and b'azEnvironment' in result.stdout:
            return 'azure'
    except:
        pass
    
    try:
        # GCP
        result = subprocess.run(
            ['curl', '-s', '-m', '1', '-H', 'Metadata-Flavor: Google',
             'http://169.254.169.254/computeMetadata/v1/project/project-id'],
            capture_output=True,
            timeout=2
        )
        if result.returncode == 0:
            return 'gcp'
    except:
        pass
    
    return None
