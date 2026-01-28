"""
Policy Validator for validating firewall rules.
"""
import logging
from typing import Dict, List, Any
from netaddr import IPNetwork, AddrFormatError

logger = logging.getLogger(__name__)


class PolicyValidator:
    """
    Validate firewall policies and rules.
    
    Checks for:
    - Valid IP addresses and CIDR notation
    - Valid port ranges
    - Valid protocols
    - Rule completeness
    - Security best practices
    """
    
    VALID_ACTIONS = ['ALLOW', 'DENY', 'DROP', 'REJECT', 'RATE_LIMIT', 'MONITOR', 'QUARANTINE']
    VALID_PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'ANY', 'ALL']
    RESERVED_PORTS = {22, 80, 443, 3306, 5432, 6379, 27017}  # Common service ports
    
    def __init__(self):
        self._ready = True
    
    def is_ready(self) -> bool:
        """Check if validator is ready."""
        return self._ready
    
    def validate(self, rules: List[Dict]) -> Dict[str, Any]:
        """
        Validate a list of rules.
        
        Args:
            rules: List of rules to validate
            
        Returns:
            Validation result dict
        """
        issues = []
        warnings = []
        
        for i, rule in enumerate(rules):
            rule_issues = self._validate_rule(rule, i)
            issues.extend([iss for iss in rule_issues if iss['severity'] == 'error'])
            warnings.extend([iss for iss in rule_issues if iss['severity'] == 'warning'])
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'rules_validated': len(rules)
        }
    
    def _validate_rule(self, rule: Dict, index: int) -> List[Dict]:
        """Validate a single rule."""
        issues = []
        
        # Required fields
        if 'action' not in rule:
            issues.append({
                'rule_index': index,
                'field': 'action',
                'message': 'Action is required',
                'severity': 'error'
            })
        elif rule['action'].upper() not in self.VALID_ACTIONS:
            issues.append({
                'rule_index': index,
                'field': 'action',
                'message': f"Invalid action: {rule['action']}",
                'severity': 'error'
            })
        
        # Protocol validation
        protocol = rule.get('protocol', 'any').upper()
        if protocol not in self.VALID_PROTOCOLS:
            issues.append({
                'rule_index': index,
                'field': 'protocol',
                'message': f"Invalid protocol: {protocol}",
                'severity': 'error'
            })
        
        # Source IP validation
        source_ip = rule.get('source_cidr') or rule.get('source_ip')
        if source_ip and source_ip != '0.0.0.0/0':
            if not self._validate_ip_or_cidr(source_ip):
                issues.append({
                    'rule_index': index,
                    'field': 'source_ip',
                    'message': f"Invalid IP/CIDR: {source_ip}",
                    'severity': 'error'
                })
        
        # Destination IP validation
        dest_ip = rule.get('dest_ip')
        if dest_ip:
            if not self._validate_ip_or_cidr(dest_ip):
                issues.append({
                    'rule_index': index,
                    'field': 'dest_ip',
                    'message': f"Invalid IP/CIDR: {dest_ip}",
                    'severity': 'error'
                })
        
        # Port validation
        port = rule.get('dest_port')
        if port:
            if not self._validate_port(port):
                issues.append({
                    'rule_index': index,
                    'field': 'dest_port',
                    'message': f"Invalid port: {port}",
                    'severity': 'error'
                })
            
            # Warn about blocking common service ports
            if rule.get('action', '').upper() in ['DENY', 'DROP', 'REJECT']:
                if int(port) in self.RESERVED_PORTS:
                    issues.append({
                        'rule_index': index,
                        'field': 'dest_port',
                        'message': f"Blocking common service port {port}",
                        'severity': 'warning'
                    })
        
        # Security warnings
        if source_ip == '0.0.0.0/0' and rule.get('action', '').upper() == 'ALLOW':
            issues.append({
                'rule_index': index,
                'field': 'source_ip',
                'message': 'Allowing traffic from any source (0.0.0.0/0)',
                'severity': 'warning'
            })
        
        return issues
    
    def _validate_ip_or_cidr(self, value: str) -> bool:
        """Validate IP address or CIDR notation."""
        try:
            IPNetwork(value)
            return True
        except (AddrFormatError, ValueError):
            return False
    
    def _validate_port(self, port: Any) -> bool:
        """Validate port number."""
        try:
            p = int(port)
            return 0 < p <= 65535
        except (ValueError, TypeError):
            return False
    
    def check_security_best_practices(self, rules: List[Dict]) -> List[Dict]:
        """Check rules against security best practices."""
        recommendations = []
        
        # Check for overly permissive rules
        allow_all_count = sum(
            1 for r in rules 
            if r.get('action', '').upper() == 'ALLOW' 
            and r.get('source_cidr') == '0.0.0.0/0'
        )
        
        if allow_all_count > 0:
            recommendations.append({
                'type': 'security',
                'message': f'{allow_all_count} rules allow traffic from any source',
                'recommendation': 'Restrict source IPs where possible'
            })
        
        # Check for rules without expiration
        no_expiry = sum(1 for r in rules if not r.get('duration') and not r.get('expires_at'))
        if no_expiry > 5:
            recommendations.append({
                'type': 'maintenance',
                'message': f'{no_expiry} rules have no expiration',
                'recommendation': 'Consider adding expiration to temporary rules'
            })
        
        return recommendations
