"""
nftables Firewall Adapter

Adapter for modern Linux nftables firewall.
"""
import logging
import subprocess
import json
from typing import Dict, List, Any, Optional

from .base import FirewallAdapter, FirewallRule, FirewallAction

logger = logging.getLogger(__name__)


class NftablesAdapter(FirewallAdapter):
    """
    nftables firewall adapter.
    
    Uses a dedicated table and chain for SENTINEL rules.
    """
    
    TABLE_NAME = "sentinel"
    INPUT_CHAIN = "sentinel_input"
    OUTPUT_CHAIN = "sentinel_output"
    
    def __init__(self):
        self._rules_cache: Dict[str, FirewallRule] = {}
        self._ensure_table()
    
    @property
    def name(self) -> str:
        return "nftables"
    
    @property
    def is_available(self) -> bool:
        """Check if nftables is available."""
        try:
            result = subprocess.run(
                ['nft', '--version'],
                capture_output=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def _ensure_table(self):
        """Ensure SENTINEL table and chains exist."""
        if not self.is_available:
            return
        
        nft_script = f"""
table inet {self.TABLE_NAME} {{
    chain {self.INPUT_CHAIN} {{
        type filter hook input priority -10; policy accept;
    }}
    chain {self.OUTPUT_CHAIN} {{
        type filter hook output priority -10; policy accept;
    }}
}}
"""
        
        try:
            # Check if table exists
            result = subprocess.run(
                ['nft', 'list', 'table', 'inet', self.TABLE_NAME],
                capture_output=True
            )
            
            if result.returncode != 0:
                # Create table and chains
                process = subprocess.run(
                    ['nft', '-f', '-'],
                    input=nft_script,
                    capture_output=True,
                    text=True
                )
                
                if process.returncode == 0:
                    logger.info("Created SENTINEL nftables table")
                else:
                    logger.error(f"Failed to create nftables table: {process.stderr}")
                    
        except Exception as e:
            logger.error(f"nftables setup error: {e}")
    
    def add_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """Add an nftables rule."""
        if not self.is_available:
            return {'success': False, 'error': 'nftables not available'}
        
        nft_rule = self._build_nft_rule(rule)
        chain = self.INPUT_CHAIN if rule.direction == 'ingress' else self.OUTPUT_CHAIN
        
        cmd = ['nft', 'add', 'rule', 'inet', self.TABLE_NAME, chain] + nft_rule.split()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self._rules_cache[rule.id] = rule
                logger.info(f"Added nftables rule: {rule.name}")
                return {
                    'success': True,
                    'rule_id': rule.id,
                    'nft_rule': nft_rule
                }
            else:
                logger.error(f"nftables error: {result.stderr}")
                return {'success': False, 'error': result.stderr}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def remove_rule(self, rule_id: str) -> Dict[str, Any]:
        """Remove an nftables rule."""
        if not self.is_available:
            return {'success': False, 'error': 'nftables not available'}
        
        rule = self._rules_cache.get(rule_id)
        if not rule:
            return {'success': False, 'error': f'Rule {rule_id} not found in cache'}
        
        # nftables requires handle to delete, so we flush and recreate
        # In production, you'd track handles
        try:
            # For now, remove from cache
            del self._rules_cache[rule_id]
            
            # Recreate chain with remaining rules
            self._rebuild_chain(rule.direction)
            
            return {'success': True, 'rule_id': rule_id}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_rules(self) -> List[FirewallRule]:
        """List all SENTINEL rules."""
        return list(self._rules_cache.values())
    
    def clear_sentinel_rules(self) -> Dict[str, Any]:
        """Clear all SENTINEL rules."""
        if not self.is_available:
            return {'success': False, 'error': 'nftables not available'}
        
        try:
            # Flush chains
            subprocess.run(
                ['nft', 'flush', 'chain', 'inet', self.TABLE_NAME, self.INPUT_CHAIN],
                capture_output=True
            )
            subprocess.run(
                ['nft', 'flush', 'chain', 'inet', self.TABLE_NAME, self.OUTPUT_CHAIN],
                capture_output=True
            )
            
            count = len(self._rules_cache)
            self._rules_cache.clear()
            
            return {'success': True, 'rules_removed': count}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _build_nft_rule(self, rule: FirewallRule) -> str:
        """Build nftables rule string."""
        parts = []
        
        # Protocol
        if rule.protocol and rule.protocol != 'all':
            if rule.protocol == 'icmp':
                parts.append('ip protocol icmp')
            else:
                parts.append(f'meta l4proto {rule.protocol}')
        
        # Source
        if rule.source_ip:
            parts.append(f'ip saddr {rule.source_ip}')
        
        if rule.source_port and rule.protocol in ['tcp', 'udp']:
            parts.append(f'{rule.protocol} sport {rule.source_port}')
        
        # Destination
        if rule.destination_ip:
            parts.append(f'ip daddr {rule.destination_ip}')
        
        if rule.destination_port and rule.protocol in ['tcp', 'udp']:
            parts.append(f'{rule.protocol} dport {rule.destination_port}')
        
        # Rate limiting
        if rule.action == FirewallAction.RATE_LIMIT and rule.rate_limit:
            parts.append(f'limit rate {rule.rate_limit}/second burst {rule.rate_limit_burst or rule.rate_limit} packets')
        
        # Action
        action_map = {
            FirewallAction.ALLOW: 'accept',
            FirewallAction.DENY: 'drop',
            FirewallAction.DROP: 'drop',
            FirewallAction.REJECT: 'reject',
            FirewallAction.LOG: 'log prefix "SENTINEL: "',
            FirewallAction.RATE_LIMIT: 'accept',
        }
        parts.append(action_map.get(rule.action, 'drop'))
        
        # Comment
        parts.append(f'comment "SENTINEL:{rule.id}"')
        
        return ' '.join(parts)
    
    def _rebuild_chain(self, direction: str):
        """Rebuild a chain with current cached rules."""
        chain = self.INPUT_CHAIN if direction == 'ingress' else self.OUTPUT_CHAIN
        
        # Flush chain
        subprocess.run(
            ['nft', 'flush', 'chain', 'inet', self.TABLE_NAME, chain],
            capture_output=True
        )
        
        # Re-add rules
        for rule in self._rules_cache.values():
            if rule.direction == direction:
                nft_rule = self._build_nft_rule(rule)
                subprocess.run(
                    ['nft', 'add', 'rule', 'inet', self.TABLE_NAME, chain] + nft_rule.split(),
                    capture_output=True
                )
