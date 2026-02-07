"""
iptables Firewall Adapter

Adapter for Linux iptables firewall.
"""
import logging
import subprocess
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

from .base import FirewallAdapter, FirewallRule, FirewallAction

logger = logging.getLogger(__name__)


class IptablesAdapter(FirewallAdapter):
    """
    iptables firewall adapter.
    
    Uses a dedicated chain (SENTINEL) for managed rules.
    """
    
    CHAIN_NAME = "SENTINEL"
    
    def __init__(self):
        self._rules_cache: Dict[str, FirewallRule] = {}
        self._ensure_chain()
    
    @property
    def name(self) -> str:
        return "iptables"
    
    @property
    def is_available(self) -> bool:
        """Check if iptables is available."""
        try:
            result = subprocess.run(
                ['iptables', '--version'],
                capture_output=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _ensure_chain(self):
        """Ensure SENTINEL chain exists."""
        if not self.is_available:
            return
        
        # Check if chain exists
        result = subprocess.run(
            ['iptables', '-L', self.CHAIN_NAME, '-n'],
            capture_output=True
        )
        
        if result.returncode != 0:
            # Create chain
            subprocess.run(['iptables', '-N', self.CHAIN_NAME], capture_output=True)
            
            # Add jump to SENTINEL chain from INPUT
            subprocess.run(
                ['iptables', '-I', 'INPUT', '-j', self.CHAIN_NAME],
                capture_output=True
            )
            
            # Add jump from OUTPUT for egress rules
            subprocess.run(
                ['iptables', '-I', 'OUTPUT', '-j', self.CHAIN_NAME],
                capture_output=True
            )
            
            logger.info("Created SENTINEL iptables chain")
    
    def add_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """Add an iptables rule."""
        if not self.is_available:
            return {'success': False, 'error': 'iptables not available'}
        
        cmd = self._build_add_command(rule)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self._rules_cache[rule.id] = rule
                logger.info(f"Added iptables rule: {rule.name}")
                return {
                    'success': True,
                    'rule_id': rule.id,
                    'command': ' '.join(cmd)
                }
            else:
                logger.error(f"iptables error: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr,
                    'command': ' '.join(cmd)
                }
                
        except Exception as e:
            logger.error(f"iptables exception: {e}")
            return {'success': False, 'error': str(e)}
    
    def remove_rule(self, rule_id: str) -> Dict[str, Any]:
        """Remove an iptables rule."""
        if not self.is_available:
            return {'success': False, 'error': 'iptables not available'}
        
        rule = self._rules_cache.get(rule_id)
        if not rule:
            return {'success': False, 'error': f'Rule {rule_id} not found'}
        
        cmd = self._build_delete_command(rule)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                del self._rules_cache[rule_id]
                logger.info(f"Removed iptables rule: {rule.name}")
                return {'success': True, 'rule_id': rule_id}
            else:
                return {'success': False, 'error': result.stderr}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_rules(self) -> List[FirewallRule]:
        """List all SENTINEL rules."""
        if not self.is_available:
            return []
        
        # Return cached rules
        return list(self._rules_cache.values())
    
    def clear_sentinel_rules(self) -> Dict[str, Any]:
        """Clear all SENTINEL rules."""
        if not self.is_available:
            return {'success': False, 'error': 'iptables not available'}
        
        try:
            # Flush SENTINEL chain
            subprocess.run(
                ['iptables', '-F', self.CHAIN_NAME],
                capture_output=True
            )
            
            count = len(self._rules_cache)
            self._rules_cache.clear()
            
            logger.info(f"Cleared {count} SENTINEL rules")
            return {'success': True, 'rules_removed': count}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _build_add_command(self, rule: FirewallRule) -> List[str]:
        """Build iptables add command from rule."""
        cmd = ['iptables', '-A', self.CHAIN_NAME]
        
        # Protocol
        if rule.protocol and rule.protocol != 'all':
            cmd.extend(['-p', rule.protocol])
        
        # Source
        if rule.source_ip:
            cmd.extend(['-s', rule.source_ip])
        
        if rule.source_port and rule.protocol in ['tcp', 'udp']:
            cmd.extend(['--sport', rule.source_port])
        
        # Destination
        if rule.destination_ip:
            cmd.extend(['-d', rule.destination_ip])
        
        if rule.destination_port and rule.protocol in ['tcp', 'udp']:
            cmd.extend(['--dport', rule.destination_port])
        
        # Rate limiting
        if rule.action == FirewallAction.RATE_LIMIT and rule.rate_limit:
            cmd.extend([
                '-m', 'limit',
                '--limit', f'{rule.rate_limit}/sec',
                '--limit-burst', str(rule.rate_limit_burst or rule.rate_limit)
            ])
        
        # Action
        action_map = {
            FirewallAction.ALLOW: 'ACCEPT',
            FirewallAction.DENY: 'DROP',
            FirewallAction.DROP: 'DROP',
            FirewallAction.REJECT: 'REJECT',
            FirewallAction.LOG: 'LOG',
            FirewallAction.RATE_LIMIT: 'ACCEPT',  # Accept within limit
        }
        cmd.extend(['-j', action_map.get(rule.action, 'DROP')])
        
        # Comment with rule ID
        cmd.extend(['-m', 'comment', '--comment', f'SENTINEL:{rule.id}'])
        
        return cmd
    
    def _build_delete_command(self, rule: FirewallRule) -> List[str]:
        """Build iptables delete command from rule."""
        # Build the same command but with -D instead of -A
        cmd = self._build_add_command(rule)
        cmd[1] = '-D'  # Replace -A with -D
        return cmd
