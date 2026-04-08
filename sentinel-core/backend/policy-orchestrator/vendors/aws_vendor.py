"""
AWS Security Group vendor integration.
"""
import logging
from typing import Dict, List, Any
from .base_vendor import BaseVendor

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
    logger.warning("boto3 not available - AWS integration disabled")


class AWSSecurityGroupVendor(BaseVendor):
    """
    AWS Security Group integration.
    
    Manages AWS Security Group rules for EC2 instances.
    """
    
    @property
    def vendor_name(self) -> str:
        return "aws_security_group"
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.region = config.get('region', 'us-east-1') if config else 'us-east-1'
        self.security_group_id = config.get('security_group_id') if config else None
        self.ec2_client = None
    
    def connect(self) -> bool:
        """Establish connection to AWS."""
        if not HAS_BOTO3:
            logger.error("boto3 not installed")
            return False
        
        try:
            self.ec2_client = boto3.client('ec2', region_name=self.region)
            
            # Verify connection
            self.ec2_client.describe_security_groups(MaxResults=5)
            
            self._connected = True
            logger.info(f"Connected to AWS EC2 in {self.region}")
            return True
        
        except Exception as e:
            logger.error(f"AWS connection failed: {e}")
            self._connected = False
            return False
    
    def disconnect(self):
        """Close AWS connection."""
        self.ec2_client = None
        self._connected = False
    
    def apply_rules(self, rules: List[Dict]) -> Dict[str, Any]:
        """Apply rules to AWS Security Group."""
        if not self._connected or not self.ec2_client:
            return {'success': False, 'message': 'Not connected to AWS'}
        
        if not self.security_group_id:
            return {'success': False, 'message': 'No security group ID configured'}
        
        ingress_rules = []
        egress_rules = []
        
        for rule in rules:
            aws_rule = self._translate_rule(rule)
            if aws_rule:
                if rule.get('direction', 'inbound') == 'inbound':
                    ingress_rules.append(aws_rule)
                else:
                    egress_rules.append(aws_rule)
        
        try:
            applied = 0
            
            if ingress_rules:
                self.ec2_client.authorize_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=ingress_rules
                )
                applied += len(ingress_rules)
            
            if egress_rules:
                self.ec2_client.authorize_security_group_egress(
                    GroupId=self.security_group_id,
                    IpPermissions=egress_rules
                )
                applied += len(egress_rules)
            
            return {
                'success': True,
                'applied': applied,
                'security_group': self.security_group_id
            }
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidPermission.Duplicate':
                return {'success': True, 'message': 'Rules already exist'}
            
            logger.error(f"AWS apply rules error: {e}")
            return {'success': False, 'message': str(e)}
        
        except Exception as e:
            logger.error(f"AWS apply rules error: {e}")
            return {'success': False, 'message': str(e)}
    
    def remove_rules(self, rules: List[Dict]) -> Dict[str, Any]:
        """Remove rules from AWS Security Group."""
        if not self._connected or not self.ec2_client:
            return {'success': False, 'message': 'Not connected to AWS'}
        
        if not self.security_group_id:
            return {'success': False, 'message': 'No security group ID configured'}
        
        ingress_rules = []
        egress_rules = []
        
        for rule in rules:
            aws_rule = self._translate_rule(rule)
            if aws_rule:
                if rule.get('direction', 'inbound') == 'inbound':
                    ingress_rules.append(aws_rule)
                else:
                    egress_rules.append(aws_rule)
        
        try:
            removed = 0
            
            if ingress_rules:
                self.ec2_client.revoke_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=ingress_rules
                )
                removed += len(ingress_rules)
            
            if egress_rules:
                self.ec2_client.revoke_security_group_egress(
                    GroupId=self.security_group_id,
                    IpPermissions=egress_rules
                )
                removed += len(egress_rules)
            
            return {
                'success': True,
                'removed': removed,
                'security_group': self.security_group_id
            }
        
        except Exception as e:
            logger.error(f"AWS remove rules error: {e}")
            return {'success': False, 'message': str(e)}
    
    def translate_rules(self, rules: List[Dict]) -> List[str]:
        """Translate rules to AWS format description."""
        descriptions = []
        
        for rule in rules:
            aws_rule = self._translate_rule(rule)
            if aws_rule:
                descriptions.append(str(aws_rule))
        
        return descriptions
    
    def get_status(self) -> Dict[str, Any]:
        """Get AWS Security Group status."""
        status = {
            'vendor': self.vendor_name,
            'connected': self._connected,
            'region': self.region,
            'security_group_id': self.security_group_id
        }
        
        if self._connected and self.ec2_client and self.security_group_id:
            try:
                response = self.ec2_client.describe_security_groups(
                    GroupIds=[self.security_group_id]
                )
                
                if response['SecurityGroups']:
                    sg = response['SecurityGroups'][0]
                    status['security_group_name'] = sg['GroupName']
                    status['inbound_rules'] = len(sg.get('IpPermissions', []))
                    status['outbound_rules'] = len(sg.get('IpPermissionsEgress', []))
            
            except Exception as e:
                status['error'] = str(e)
        
        return status
    
    def _translate_rule(self, rule: Dict) -> Dict[str, Any]:
        """Translate generic rule to AWS format."""
        # Map protocol
        protocol_map = {
            'TCP': 'tcp',
            'UDP': 'udp',
            'ICMP': 'icmp',
            'ANY': '-1',
            'ALL': '-1'
        }
        
        protocol = rule.get('protocol', 'tcp').upper()
        aws_protocol = protocol_map.get(protocol, 'tcp')
        
        aws_rule = {
            'IpProtocol': aws_protocol
        }
        
        # Port range
        port = rule.get('dest_port')
        if port and aws_protocol not in ['-1', 'icmp']:
            aws_rule['FromPort'] = int(port)
            aws_rule['ToPort'] = int(port)
        elif aws_protocol == '-1':
            aws_rule['FromPort'] = -1
            aws_rule['ToPort'] = -1
        
        # IP range
        source = rule.get('source_cidr') or rule.get('source_ip', '0.0.0.0/0')
        if '/' not in source:
            source = f"{source}/32"
        
        aws_rule['IpRanges'] = [{
            'CidrIp': source,
            'Description': f"SENTINEL: {rule.get('id', 'unknown')}"
        }]
        
        return aws_rule
