"""
Azure Network Security Group Adapter

Adapter for Azure NSGs.
"""
import logging
from typing import Dict, List, Any, Optional

from .base import FirewallAdapter, FirewallRule, FirewallAction

logger = logging.getLogger(__name__)


class AzureNSGAdapter(FirewallAdapter):
    """
    Azure Network Security Group firewall adapter.
    
    Manages NSG rules via Azure SDK.
    """
    
    def __init__(
        self,
        subscription_id: str,
        resource_group: str,
        nsg_name: str,
        credentials: Optional[Any] = None
    ):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.nsg_name = nsg_name
        self._client = None
        self._rules_cache: Dict[str, FirewallRule] = {}
        self._priority_counter = 1000  # Starting priority for SENTINEL rules
        
        self._init_client(credentials)
    
    def _init_client(self, credentials: Optional[Any]):
        """Initialize Azure Network Management client."""
        try:
            from azure.mgmt.network import NetworkManagementClient
            from azure.identity import DefaultAzureCredential
            
            creds = credentials or DefaultAzureCredential()
            self._client = NetworkManagementClient(creds, self.subscription_id)
            
            logger.info(f"Azure Network client initialized for NSG {self.nsg_name}")
            
        except ImportError:
            logger.warning("Azure SDK not installed, adapter disabled")
        except Exception as e:
            logger.error(f"Azure client init failed: {e}")
    
    @property
    def name(self) -> str:
        return "azure_nsg"
    
    @property
    def is_available(self) -> bool:
        """Check if Azure client is available."""
        return self._client is not None
    
    def add_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """Add an NSG rule."""
        if not self.is_available:
            return {'success': False, 'error': 'Azure client not available'}
        
        try:
            # Build Azure rule
            azure_rule = self._build_azure_rule(rule)
            
            # Create or update rule
            operation = self._client.security_rules.begin_create_or_update(
                self.resource_group,
                self.nsg_name,
                f"sentinel-{rule.id}",
                azure_rule
            )
            
            operation.result()  # Wait for completion
            
            self._rules_cache[rule.id] = rule
            self._priority_counter += 1
            
            logger.info(f"Added Azure NSG rule: {rule.name}")
            
            return {
                'success': True,
                'rule_id': rule.id,
                'nsg_name': self.nsg_name
            }
            
        except Exception as e:
            logger.error(f"Azure NSG error: {e}")
            return {'success': False, 'error': str(e)}
    
    def remove_rule(self, rule_id: str) -> Dict[str, Any]:
        """Remove an NSG rule."""
        if not self.is_available:
            return {'success': False, 'error': 'Azure client not available'}
        
        if rule_id not in self._rules_cache:
            return {'success': False, 'error': f'Rule {rule_id} not found'}
        
        try:
            operation = self._client.security_rules.begin_delete(
                self.resource_group,
                self.nsg_name,
                f"sentinel-{rule_id}"
            )
            
            operation.result()  # Wait for completion
            
            del self._rules_cache[rule_id]
            logger.info(f"Removed Azure NSG rule: sentinel-{rule_id}")
            
            return {'success': True, 'rule_id': rule_id}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_rules(self) -> List[FirewallRule]:
        """List all SENTINEL-managed rules."""
        return list(self._rules_cache.values())
    
    def clear_sentinel_rules(self) -> Dict[str, Any]:
        """Clear all SENTINEL rules."""
        if not self.is_available:
            return {'success': False, 'error': 'Azure client not available'}
        
        count = 0
        errors = []
        
        for rule_id in list(self._rules_cache.keys()):
            result = self.remove_rule(rule_id)
            if result['success']:
                count += 1
            else:
                errors.append(result.get('error'))
        
        return {
            'success': len(errors) == 0,
            'rules_removed': count,
            'errors': errors
        }
    
    def _build_azure_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """Build Azure security rule parameters."""
        # Map our actions to Azure access
        access_map = {
            FirewallAction.ALLOW: 'Allow',
            FirewallAction.DENY: 'Deny',
            FirewallAction.DROP: 'Deny',
            FirewallAction.REJECT: 'Deny',
            FirewallAction.RATE_LIMIT: 'Allow',  # Azure doesn't support rate limiting
        }
        
        # Map direction
        direction = 'Inbound' if rule.direction == 'ingress' else 'Outbound'
        
        # Protocol
        protocol_map = {
            'tcp': 'Tcp',
            'udp': 'Udp',
            'icmp': 'Icmp',
            'all': '*'
        }
        
        params = {
            'protocol': protocol_map.get(rule.protocol, '*'),
            'source_address_prefix': rule.source_ip or '*',
            'destination_address_prefix': rule.destination_ip or '*',
            'source_port_range': rule.source_port or '*',
            'destination_port_range': rule.destination_port or '*',
            'access': access_map.get(rule.action, 'Deny'),
            'priority': self._priority_counter,
            'direction': direction,
            'description': f'SENTINEL: {rule.description}'
        }
        
        return params
