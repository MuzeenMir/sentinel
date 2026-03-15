"""
GCP Firewall Adapter

Adapter for Google Cloud Platform VPC Firewall rules.
"""
import logging
from typing import Dict, List, Any, Optional

from .base import FirewallAdapter, FirewallRule, FirewallAction

logger = logging.getLogger(__name__)


class GCPFirewallAdapter(FirewallAdapter):
    """
    GCP Firewall adapter.
    
    Manages VPC firewall rules via Google Cloud SDK.
    """
    
    def __init__(
        self,
        project_id: str,
        network: str = "default",
        credentials_path: Optional[str] = None
    ):
        self.project_id = project_id
        self.network = network
        self._client = None
        self._rules_cache: Dict[str, FirewallRule] = {}
        
        self._init_client(credentials_path)
    
    def _init_client(self, credentials_path: Optional[str]):
        """Initialize GCP Compute client."""
        try:
            from google.cloud import compute_v1
            
            if credentials_path:
                import os
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_path
            
            self._client = compute_v1.FirewallsClient()
            logger.info(f"GCP Compute client initialized for project {self.project_id}")
            
        except ImportError:
            logger.warning("Google Cloud SDK not installed, adapter disabled")
        except Exception as e:
            logger.error(f"GCP client init failed: {e}")
    
    @property
    def name(self) -> str:
        return "gcp_firewall"
    
    @property
    def is_available(self) -> bool:
        """Check if GCP client is available."""
        return self._client is not None
    
    def add_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """Add a GCP firewall rule."""
        if not self.is_available:
            return {'success': False, 'error': 'GCP client not available'}
        
        try:
            from google.cloud import compute_v1
            
            firewall_rule = self._build_gcp_rule(rule)
            
            operation = self._client.insert(
                project=self.project_id,
                firewall_resource=firewall_rule
            )
            
            # Wait for operation
            self._wait_for_operation(operation.name)
            
            self._rules_cache[rule.id] = rule
            logger.info(f"Added GCP firewall rule: {rule.name}")
            
            return {
                'success': True,
                'rule_id': rule.id,
                'project': self.project_id
            }
            
        except Exception as e:
            logger.error(f"GCP firewall error: {e}")
            return {'success': False, 'error': str(e)}
    
    def remove_rule(self, rule_id: str) -> Dict[str, Any]:
        """Remove a GCP firewall rule."""
        if not self.is_available:
            return {'success': False, 'error': 'GCP client not available'}
        
        if rule_id not in self._rules_cache:
            return {'success': False, 'error': f'Rule {rule_id} not found'}
        
        try:
            operation = self._client.delete(
                project=self.project_id,
                firewall=f"sentinel-{rule_id}"
            )
            
            self._wait_for_operation(operation.name)
            
            del self._rules_cache[rule_id]
            logger.info(f"Removed GCP firewall rule: sentinel-{rule_id}")
            
            return {'success': True, 'rule_id': rule_id}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_rules(self) -> List[FirewallRule]:
        """List all SENTINEL-managed rules."""
        return list(self._rules_cache.values())
    
    def clear_sentinel_rules(self) -> Dict[str, Any]:
        """Clear all SENTINEL rules."""
        if not self.is_available:
            return {'success': False, 'error': 'GCP client not available'}
        
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
    
    def _build_gcp_rule(self, rule: FirewallRule) -> Any:
        """Build GCP firewall rule resource."""
        from google.cloud import compute_v1
        
        firewall = compute_v1.Firewall()
        firewall.name = f"sentinel-{rule.id}"
        firewall.description = f"SENTINEL: {rule.description}"
        firewall.network = f"projects/{self.project_id}/global/networks/{self.network}"
        
        # Direction
        if rule.direction == 'ingress':
            firewall.direction = 'INGRESS'
        else:
            firewall.direction = 'EGRESS'
        
        # Priority (lower = higher priority in GCP)
        firewall.priority = rule.priority
        
        # Source/destination ranges
        if rule.source_ip:
            firewall.source_ranges = [rule.source_ip]
        if rule.destination_ip:
            firewall.destination_ranges = [rule.destination_ip]
        
        # Protocol and ports
        allowed = compute_v1.Allowed()
        
        if rule.protocol == 'all':
            allowed.I_p_protocol = 'all'
        else:
            allowed.I_p_protocol = rule.protocol
            
            if rule.destination_port:
                allowed.ports = [rule.destination_port]
        
        # GCP uses allowed/denied lists
        if rule.action in [FirewallAction.ALLOW, FirewallAction.RATE_LIMIT]:
            firewall.allowed = [allowed]
        else:
            firewall.denied = [allowed]
        
        # Target tags (optional, for scoping)
        firewall.target_tags = ['sentinel-protected']
        
        return firewall
    
    def _wait_for_operation(self, operation_name: str, timeout: int = 120):
        """Wait for a GCP operation to complete."""
        try:
            from google.cloud import compute_v1
            
            operations_client = compute_v1.GlobalOperationsClient()
            
            import time
            start = time.time()
            
            while time.time() - start < timeout:
                result = operations_client.get(
                    project=self.project_id,
                    operation=operation_name
                )
                
                if result.status == compute_v1.Operation.Status.DONE:
                    if result.error:
                        raise Exception(f"Operation failed: {result.error}")
                    return
                
                time.sleep(2)
            
            raise TimeoutError(f"Operation {operation_name} timed out")
            
        except Exception as e:
            logger.warning(f"Could not wait for operation: {e}")
