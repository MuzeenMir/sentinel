"""
Rule Generator for creating firewall rules from policy definitions.
"""
import uuid
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from netaddr import IPNetwork, IPAddress, cidr_merge

logger = logging.getLogger(__name__)


class RuleGenerator:
    """
    Generate firewall rules from policy definitions.
    
    Converts high-level policy specifications into granular
    firewall rules that can be translated to vendor-specific formats.
    """
    
    # Valid actions
    VALID_ACTIONS = ['ALLOW', 'DENY', 'DROP', 'REJECT', 'RATE_LIMIT', 'MONITOR', 'QUARANTINE']
    
    # Valid protocols
    VALID_PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'ANY', 'ALL']
    
    def __init__(self):
        pass
    
    def generate(self, policy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate rules from policy data.
        
        Args:
            policy_data: Policy definition
            
        Returns:
            List of generated rules
        """
        rules = []
        
        action = policy_data.get('action', 'DENY').upper()
        if action not in self.VALID_ACTIONS:
            raise ValueError(f"Invalid action: {action}")
        
        # Parse source specification
        source = policy_data.get('source', {})
        source_ips = self._parse_source(source)
        
        # Parse destination specification
        destination = policy_data.get('destination', {})
        dest_ports = self._parse_destination(destination)
        
        # Parse protocol
        protocols = self._parse_protocol(policy_data.get('protocol', 'any'))
        
        # Generate rules for each combination
        for src_ip in source_ips:
            for dest_port in dest_ports:
                for protocol in protocols:
                    rule = self._create_rule(
                        action=action,
                        source_ip=src_ip,
                        dest_port=dest_port,
                        protocol=protocol,
                        policy_data=policy_data
                    )
                    rules.append(rule)
        
        # If no source specified, create a generic rule
        if not rules:
            rule = self._create_rule(
                action=action,
                source_ip=source.get('ip'),
                dest_port=destination.get('port'),
                protocol=protocols[0] if protocols else 'any',
                policy_data=policy_data
            )
            rules.append(rule)
        
        logger.info(f"Generated {len(rules)} rules for policy")
        return rules
    
    def _parse_source(self, source: Dict) -> List[str]:
        """Parse source specification into IP list."""
        ips = []
        
        if 'ip' in source:
            ip = source['ip']
            cidr = source.get('cidr', '/32')
            
            # Handle CIDR notation
            if '/' not in ip:
                ip = f"{ip}{cidr}"
            
            ips.append(ip)
        
        if 'ips' in source:
            for ip in source['ips']:
                ips.append(ip if '/' in ip else f"{ip}/32")
        
        if 'network' in source:
            ips.append(source['network'])
        
        return ips if ips else [None]
    
    def _parse_destination(self, destination: Dict) -> List[Optional[int]]:
        """Parse destination specification into port list."""
        ports = []
        
        if 'port' in destination:
            ports.append(destination['port'])
        
        if 'ports' in destination:
            ports.extend(destination['ports'])
        
        if 'port_range' in destination:
            start, end = destination['port_range']
            ports.extend(range(start, end + 1))
        
        return ports if ports else [None]
    
    def _parse_protocol(self, protocol: Any) -> List[str]:
        """Parse protocol specification."""
        if protocol is None:
            return ['any']
        
        if isinstance(protocol, str):
            proto = protocol.upper()
            if proto in ['ANY', 'ALL']:
                return ['TCP', 'UDP', 'ICMP']
            return [proto]
        
        if isinstance(protocol, list):
            return [p.upper() for p in protocol]
        
        return ['any']
    
    def _create_rule(self, action: str, source_ip: Optional[str],
                     dest_port: Optional[int], protocol: str,
                     policy_data: Dict) -> Dict[str, Any]:
        """Create a single firewall rule."""
        rule_id = f"rule_{uuid.uuid4().hex[:8]}"
        
        rule = {
            'id': rule_id,
            'action': action,
            'protocol': protocol,
            'direction': 'inbound',  # Default to inbound
            'priority': policy_data.get('priority', 100),
            'enabled': True,
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Source specification
        if source_ip:
            rule['source_ip'] = source_ip
            rule['source_cidr'] = source_ip if '/' in source_ip else f"{source_ip}/32"
        else:
            rule['source_ip'] = '0.0.0.0/0'
            rule['source_cidr'] = '0.0.0.0/0'
        
        # Destination specification
        if dest_port:
            rule['dest_port'] = dest_port
        
        if policy_data.get('destination', {}).get('ip'):
            rule['dest_ip'] = policy_data['destination']['ip']
        
        # Duration for temporary rules
        if policy_data.get('duration'):
            rule['duration'] = policy_data['duration']
            rule['expires_at'] = datetime.utcnow().timestamp() + policy_data['duration']
        
        # Rate limiting parameters
        if action == 'RATE_LIMIT':
            rule['rate_limit'] = {
                'packets_per_second': policy_data.get('rate_limit', {}).get('pps', 100),
                'burst': policy_data.get('rate_limit', {}).get('burst', 50)
            }
        
        # Metadata
        rule['metadata'] = {
            'policy_name': policy_data.get('name', 'Unknown'),
            'description': policy_data.get('description', ''),
            'tags': policy_data.get('tags', [])
        }
        
        return rule
    
    def expand_cidr(self, cidr: str, max_hosts: int = 256) -> List[str]:
        """Expand CIDR to individual IPs (with limit)."""
        try:
            network = IPNetwork(cidr)
            
            # Limit expansion to prevent memory issues
            if network.size > max_hosts:
                return [cidr]
            
            return [str(ip) for ip in network]
        
        except Exception as e:
            logger.error(f"CIDR expansion error: {e}")
            return [cidr]
    
    def merge_rules(self, rules: List[Dict]) -> List[Dict]:
        """Merge overlapping rules for optimization."""
        # Group by action, protocol, destination, and rule attributes
        groups = {}
        for rule in rules:
            key = (
                rule.get('action'),
                rule.get('protocol'),
                rule.get('dest_port'),
                rule.get('dest_ip'),
                rule.get('direction'),
                rule.get('priority'),
                json.dumps(rule.get('rate_limit'), sort_keys=True),
            )
            if key not in groups:
                groups[key] = []
            groups[key].append(rule)
        
        merged = []
        for _, group_rules in groups.items():
            source_cidrs = []
            base_rule = group_rules[0]
            for rule in group_rules:
                src = rule.get('source_cidr') or rule.get('source_ip')
                if not src:
                    merged.append(rule)
                    continue
                try:
                    source_cidrs.append(IPNetwork(src))
                except Exception:
                    merged.append(rule)
            
            if not source_cidrs:
                continue
            
            merged_cidrs = list(IPNetwork(c) for c in [str(n) for n in cidr_merge(source_cidrs)])
            for network in merged_cidrs:
                new_rule = dict(base_rule)
                new_rule['source_cidr'] = str(network)
                new_rule['source_ip'] = str(network)
                merged.append(new_rule)
        
        return merged
