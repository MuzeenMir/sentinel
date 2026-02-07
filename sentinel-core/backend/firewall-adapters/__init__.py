"""
SENTINEL Firewall Adapters

Multi-platform firewall integration for automated threat response.

Supported platforms:
- iptables (Linux)
- nftables (Modern Linux)
- AWS Security Groups
- Azure NSGs
- GCP Firewall Rules
"""

from .base import FirewallAdapter, FirewallRule, FirewallAction
from .iptables_adapter import IptablesAdapter
from .nftables_adapter import NftablesAdapter
from .aws_sg_adapter import AWSSecurityGroupAdapter
from .azure_nsg_adapter import AzureNSGAdapter
from .gcp_firewall_adapter import GCPFirewallAdapter
from .factory import get_adapter

__all__ = [
    "FirewallAdapter",
    "FirewallRule",
    "FirewallAction",
    "IptablesAdapter",
    "NftablesAdapter",
    "AWSSecurityGroupAdapter",
    "AzureNSGAdapter",
    "GCPFirewallAdapter",
    "get_adapter",
]
