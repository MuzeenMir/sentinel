"""
AWS Security Group Adapter

Adapter for AWS EC2 Security Groups.
"""
import logging
from typing import Dict, List, Any, Optional

from .base import FirewallAdapter, FirewallRule, FirewallAction

logger = logging.getLogger(__name__)


class AWSSecurityGroupAdapter(FirewallAdapter):
    """
    AWS Security Group firewall adapter.
    
    Manages security group rules via AWS SDK (boto3).
    """
    
    def __init__(
        self,
        security_group_id: str,
        region: str = "us-east-1",
        aws_access_key: Optional[str] = None,
        aws_secret_key: Optional[str] = None
    ):
        self.security_group_id = security_group_id
        self.region = region
        self._client = None
        self._rules_cache: Dict[str, FirewallRule] = {}
        
        self._init_client(aws_access_key, aws_secret_key)
    
    def _init_client(self, access_key: Optional[str], secret_key: Optional[str]):
        """Initialize boto3 EC2 client."""
        try:
            import boto3
            
            kwargs = {'region_name': self.region}
            if access_key and secret_key:
                kwargs['aws_access_key_id'] = access_key
                kwargs['aws_secret_access_key'] = secret_key
            
            self._client = boto3.client('ec2', **kwargs)
            logger.info(f"AWS EC2 client initialized for {self.region}")
            
        except ImportError:
            logger.warning("boto3 not installed, AWS adapter disabled")
        except Exception as e:
            logger.error(f"AWS client init failed: {e}")
    
    @property
    def name(self) -> str:
        return "aws_security_group"
    
    @property
    def is_available(self) -> bool:
        """Check if AWS client is available."""
        return self._client is not None
    
    def add_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """Add a security group rule."""
        if not self.is_available:
            return {'success': False, 'error': 'AWS client not available'}
        
        try:
            # Build AWS rule
            ip_permission = self._build_ip_permission(rule)
            
            if rule.direction == 'ingress':
                self._client.authorize_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=[ip_permission]
                )
            else:
                self._client.authorize_security_group_egress(
                    GroupId=self.security_group_id,
                    IpPermissions=[ip_permission]
                )
            
            self._rules_cache[rule.id] = rule
            logger.info(f"Added AWS SG rule: {rule.name}")
            
            return {
                'success': True,
                'rule_id': rule.id,
                'security_group_id': self.security_group_id
            }
            
        except Exception as e:
            logger.error(f"AWS SG error: {e}")
            return {'success': False, 'error': str(e)}
    
    def remove_rule(self, rule_id: str) -> Dict[str, Any]:
        """Remove a security group rule."""
        if not self.is_available:
            return {'success': False, 'error': 'AWS client not available'}
        
        rule = self._rules_cache.get(rule_id)
        if not rule:
            return {'success': False, 'error': f'Rule {rule_id} not found'}
        
        try:
            ip_permission = self._build_ip_permission(rule)
            
            if rule.direction == 'ingress':
                self._client.revoke_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=[ip_permission]
                )
            else:
                self._client.revoke_security_group_egress(
                    GroupId=self.security_group_id,
                    IpPermissions=[ip_permission]
                )
            
            del self._rules_cache[rule_id]
            logger.info(f"Removed AWS SG rule: {rule.name}")
            
            return {'success': True, 'rule_id': rule_id}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_rules(self) -> List[FirewallRule]:
        """List all SENTINEL-managed rules."""
        return list(self._rules_cache.values())
    
    def clear_sentinel_rules(self) -> Dict[str, Any]:
        """Clear all SENTINEL rules."""
        if not self.is_available:
            return {'success': False, 'error': 'AWS client not available'}
        
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
    
    def _build_ip_permission(self, rule: FirewallRule) -> Dict[str, Any]:
        """Build AWS IP permission from rule."""
        # Note: AWS SGs don't support DENY rules directly
        # They're implicitly deny, so we only add ALLOW rules
        
        permission = {}
        
        # Protocol
        if rule.protocol == 'all':
            permission['IpProtocol'] = '-1'
        else:
            permission['IpProtocol'] = rule.protocol
        
        # Ports
        if rule.destination_port and rule.protocol in ['tcp', 'udp']:
            if '-' in rule.destination_port:
                from_port, to_port = rule.destination_port.split('-')
                permission['FromPort'] = int(from_port)
                permission['ToPort'] = int(to_port)
            else:
                permission['FromPort'] = int(rule.destination_port)
                permission['ToPort'] = int(rule.destination_port)
        elif rule.protocol == 'icmp':
            permission['FromPort'] = -1
            permission['ToPort'] = -1
        
        # Source/Destination IP
        ip = rule.source_ip or rule.destination_ip or '0.0.0.0/0'
        
        permission['IpRanges'] = [{
            'CidrIp': ip,
            'Description': f'SENTINEL:{rule.id} - {rule.description}'
        }]
        
        return permission
    
    def get_security_group_info(self) -> Dict[str, Any]:
        """Get information about the managed security group."""
        if not self.is_available:
            return {'error': 'AWS client not available'}
        
        try:
            response = self._client.describe_security_groups(
                GroupIds=[self.security_group_id]
            )
            
            if response['SecurityGroups']:
                sg = response['SecurityGroups'][0]
                return {
                    'id': sg['GroupId'],
                    'name': sg['GroupName'],
                    'description': sg['Description'],
                    'vpc_id': sg.get('VpcId'),
                    'ingress_rules': len(sg.get('IpPermissions', [])),
                    'egress_rules': len(sg.get('IpPermissionsEgress', [])),
                }
            
            return {'error': 'Security group not found'}
            
        except Exception as e:
            return {'error': str(e)}
