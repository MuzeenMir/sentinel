"""
Vendor that delegates to the shared firewall-adapters package.
Supports iptables, nftables, aws, azure, gcp via a single code path.
"""
import logging
from typing import Dict, List, Any, Optional

from .base_vendor import BaseVendor

logger = logging.getLogger(__name__)

try:
    from firewall_adapters import get_adapter
    from firewall_adapters.base import FirewallRule, FirewallAction
    HAS_ADAPTERS = True
except ImportError:
    HAS_ADAPTERS = False
    get_adapter = None
    FirewallRule = None
    FirewallAction = None


def _policy_rule_to_firewall_rule(rule: Dict[str, Any]) -> Optional[FirewallRule]:
    """Convert policy-orchestrator rule dict to FirewallRule."""
    if not HAS_ADAPTERS or FirewallRule is None or FirewallAction is None:
        return None

    action_str = (rule.get('action') or 'DENY').upper()
    action_map = {
        'ALLOW': FirewallAction.ALLOW,
        'DENY': FirewallAction.DENY,
        'DROP': FirewallAction.DROP,
        'REJECT': FirewallAction.REJECT,
        'RATE_LIMIT': FirewallAction.RATE_LIMIT,
        'LOG': FirewallAction.LOG,
    }
    action = action_map.get(action_str, FirewallAction.DENY)

    protocol = (rule.get('protocol') or 'any').lower()
    if protocol in ('any', 'all'):
        protocol = 'all'
    elif protocol == 'icmp':
        protocol = 'icmp'

    source_ip = rule.get('source_cidr') or rule.get('source_ip') or '0.0.0.0/0'
    dest_port = rule.get('dest_port')
    dest_port_str = str(dest_port) if dest_port is not None else None

    rate_limit = None
    rate_limit_burst = None
    if action == FirewallAction.RATE_LIMIT and isinstance(rule.get('rate_limit'), dict):
        rate_limit = rule['rate_limit'].get('packets_per_second') or rule['rate_limit'].get('pps')
        rate_limit_burst = rule['rate_limit'].get('burst')

    fw_rule = FirewallRule(
        id=rule.get('id', ''),
        name=rule.get('name', '') or f"rule_{rule.get('id', '')}",
        description=rule.get('description', ''),
        direction='ingress' if (rule.get('direction') or 'inbound') == 'inbound' else 'egress',
        source_ip=source_ip,
        destination_ip=rule.get('dest_ip'),
        destination_port=dest_port_str,
        protocol=protocol,
        action=action,
        rate_limit=rate_limit,
        rate_limit_burst=rate_limit_burst,
        priority=rule.get('priority', 100),
    )
    return fw_rule


class AdapterVendor(BaseVendor):
    """
    Vendor that uses the shared firewall-adapters package.
    Config must include 'adapter_type': one of iptables, nftables, aws, azure, gcp.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self._adapter = None
        self._adapter_type = (config or {}).get('adapter_type', 'iptables')

    @property
    def vendor_name(self) -> str:
        return self._adapter_type

    def connect(self) -> bool:
        if not HAS_ADAPTERS:
            logger.error("firewall_adapters package not installed")
            return False
        try:
            self._adapter = get_adapter(self._adapter_type, **self.config)
            self._connected = self._adapter.is_available if hasattr(self._adapter, 'is_available') else True
            return self._connected
        except Exception as e:
            logger.error(f"Adapter connect failed for {self._adapter_type}: {e}")
            self._connected = False
            return False

    def disconnect(self):
        self._adapter = None
        self._connected = False

    def apply_rules(self, rules: List[Dict]) -> Dict[str, Any]:
        if not self._adapter or not HAS_ADAPTERS:
            return {'success': False, 'message': 'Adapter not connected or package missing'}
        applied = 0
        errors = []
        for rule in rules:
            fw_rule = _policy_rule_to_firewall_rule(rule)
            if not fw_rule:
                errors.append(f"Skip invalid rule {rule.get('id')}")
                continue
            result = self._adapter.add_rule(fw_rule)
            if result.get('success'):
                applied += 1
            else:
                errors.append(result.get('error', str(result)))
        return {
            'success': len(errors) == 0,
            'message': f"Applied {applied}/{len(rules)} rules" + ("; " + "; ".join(errors) if errors else ""),
            'applied': applied,
            'total': len(rules),
            'errors': errors,
        }

    def remove_rules(self, rules: List[Dict]) -> Dict[str, Any]:
        if not self._adapter or not HAS_ADAPTERS:
            return {'success': False, 'message': 'Adapter not connected or package missing'}
        removed = 0
        errors = []
        for rule in rules:
            rule_id = rule.get('id')
            if not rule_id:
                continue
            result = self._adapter.remove_rule(rule_id)
            if result.get('success'):
                removed += 1
            else:
                errors.append(result.get('error', str(result)))
        return {
            'success': len(errors) == 0,
            'message': f"Removed {removed}/{len(rules)} rules" + ("; " + "; ".join(errors) if errors else ""),
            'removed': removed,
            'total': len(rules),
            'errors': errors,
        }

    def translate_rules(self, rules: List[Dict]) -> List[str]:
        if not HAS_ADAPTERS:
            return []
        translated = []
        for rule in rules:
            fw_rule = _policy_rule_to_firewall_rule(rule)
            if fw_rule:
                translated.append(f"{fw_rule.action.value} {fw_rule.source_ip} -> {fw_rule.destination_port or '*'}")
        return translated

    def get_status(self) -> Dict[str, Any]:
        if not self._adapter:
            return {
                'vendor': self.vendor_name,
                'connected': False,
                'status': 'disconnected',
                'message': 'Not connected',
            }
        if hasattr(self._adapter, 'list_rules'):
            try:
                rules = self._adapter.list_rules()
                rule_count = len(rules) if rules else 0
            except Exception:
                rule_count = 0
        else:
            rule_count = 0
        return {
            'vendor': self.vendor_name,
            'connected': self._connected,
            'rule_count': rule_count,
            'status': 'operational' if self._connected else 'disconnected',
        }
