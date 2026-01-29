"""
iptables vendor integration for Linux firewalls.
"""
import subprocess
import logging
from typing import Dict, List, Any
from .base_vendor import BaseVendor

logger = logging.getLogger(__name__)


class IptablesVendor(BaseVendor):
    """
    iptables firewall integration.
    
    Translates and applies firewall rules using iptables commands.
    """
    
    @property
    def vendor_name(self) -> str:
        return "iptables"
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.chain = config.get('chain', 'SENTINEL') if config else 'SENTINEL'
        self.table = config.get('table', 'filter') if config else 'filter'
    
    def connect(self) -> bool:
        """Verify iptables is available."""
        try:
            result = subprocess.run(
                ['iptables', '--version'],
                capture_output=True,
                text=True
            )
            self._connected = result.returncode == 0
            
            if self._connected:
                # Ensure SENTINEL chain exists
                self._ensure_chain_exists()
            
            return self._connected
        except Exception as e:
            logger.error(f"iptables connection failed: {e}")
            self._connected = False
            return False
    
    def disconnect(self):
        """No persistent connection for iptables."""
        self._connected = False
    
    def apply_rules(self, rules: List[Dict]) -> Dict[str, Any]:
        """Apply rules to iptables."""
        if not self._connected:
            return {'success': False, 'message': 'Not connected'}
        
        commands = self.translate_rules(rules)
        applied = 0
        errors = []
        
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd.split(),
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    applied += 1
                else:
                    errors.append(f"Failed: {cmd} - {result.stderr}")
            
            except Exception as e:
                errors.append(f"Error: {cmd} - {str(e)}")
        
        return {
            'success': len(errors) == 0,
            'applied': applied,
            'total': len(commands),
            'errors': errors
        }
    
    def remove_rules(self, rules: List[Dict]) -> Dict[str, Any]:
        """Remove rules from iptables."""
        commands = self.translate_rules(rules)
        # Replace -A (append) with -D (delete)
        delete_commands = [cmd.replace(' -A ', ' -D ') for cmd in commands]
        
        removed = 0
        errors = []
        
        for cmd in delete_commands:
            try:
                result = subprocess.run(
                    cmd.split(),
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    removed += 1
                else:
                    errors.append(f"Failed: {cmd}")
            
            except Exception as e:
                errors.append(f"Error: {str(e)}")
        
        return {
            'success': len(errors) == 0,
            'removed': removed,
            'total': len(delete_commands),
            'errors': errors
        }
    
    def translate_rules(self, rules: List[Dict]) -> List[str]:
        """Translate rules to iptables commands."""
        commands = []
        
        for rule in rules:
            cmd = self._build_iptables_command(rule)
            if cmd:
                commands.append(cmd)
        
        return commands
    
    def get_status(self) -> Dict[str, Any]:
        """Get iptables status."""
        try:
            # Get current rules
            result = subprocess.run(
                ['iptables', '-t', self.table, '-L', self.chain, '-n', '--line-numbers'],
                capture_output=True,
                text=True
            )
            
            rule_count = len(result.stdout.strip().split('\n')) - 2 if result.returncode == 0 else 0
            
            return {
                'vendor': self.vendor_name,
                'connected': self._connected,
                'chain': self.chain,
                'table': self.table,
                'rule_count': max(0, rule_count),
                'status': 'operational' if self._connected else 'disconnected'
            }
        
        except Exception as e:
            return {
                'vendor': self.vendor_name,
                'connected': False,
                'error': str(e)
            }
    
    def _ensure_chain_exists(self):
        """Ensure the SENTINEL chain exists."""
        try:
            # Check if chain exists
            result = subprocess.run(
                ['iptables', '-t', self.table, '-L', self.chain],
                capture_output=True
            )
            
            if result.returncode != 0:
                # Create chain
                subprocess.run(
                    ['iptables', '-t', self.table, '-N', self.chain],
                    capture_output=True
                )
                
                # Add jump to chain from INPUT
                subprocess.run(
                    ['iptables', '-t', self.table, '-I', 'INPUT', '-j', self.chain],
                    capture_output=True
                )
                
                logger.info(f"Created iptables chain: {self.chain}")
        
        except Exception as e:
            logger.error(f"Failed to ensure chain exists: {e}")
    
    def _build_iptables_command(self, rule: Dict) -> str:
        """Build iptables command from rule."""
        parts = ['iptables', '-t', self.table, '-A', self.chain]
        
        # Protocol
        protocol = rule.get('protocol', 'all').lower()
        if protocol != 'any' and protocol != 'all':
            parts.extend(['-p', protocol])
        
        # Source
        source = rule.get('source_cidr') or rule.get('source_ip')
        if source and source != '0.0.0.0/0':
            parts.extend(['-s', source])
        
        # Destination
        dest = rule.get('dest_ip')
        if dest:
            parts.extend(['-d', dest])
        
        # Port
        port = rule.get('dest_port')
        if port and protocol in ['tcp', 'udp']:
            parts.extend(['--dport', str(port)])
        
        # Action
        action = rule.get('action', 'DROP').upper()
        action_map = {
            'ALLOW': 'ACCEPT',
            'DENY': 'DROP',
            'DROP': 'DROP',
            'REJECT': 'REJECT',
            'RATE_LIMIT': 'DROP',  # Simplified
            'MONITOR': 'LOG'
        }
        iptables_action = action_map.get(action, 'DROP')
        
        parts.extend(['-j', iptables_action])
        
        # Add comment
        if rule.get('id'):
            parts.extend(['-m', 'comment', '--comment', f"SENTINEL:{rule['id']}"])
        
        return ' '.join(parts)
