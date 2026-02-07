"""
Base Firewall Adapter

Abstract interface for all firewall implementations.
"""
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid


class FirewallAction(Enum):
    """Firewall rule actions."""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    RATE_LIMIT = "rate_limit"


@dataclass
class FirewallRule:
    """
    Universal firewall rule representation.
    
    Adapters translate this to platform-specific syntax.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    
    # Direction
    direction: str = "ingress"  # ingress, egress
    
    # Source
    source_ip: Optional[str] = None  # CIDR notation
    source_port: Optional[str] = None  # Single port or range (e.g., "80", "8000-9000")
    
    # Destination
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    
    # Protocol
    protocol: str = "tcp"  # tcp, udp, icmp, all
    
    # Action
    action: FirewallAction = FirewallAction.DENY
    
    # Rate limiting (if action is RATE_LIMIT)
    rate_limit: Optional[int] = None  # packets per second
    rate_limit_burst: Optional[int] = None
    
    # Priority (lower = higher priority)
    priority: int = 100
    
    # Metadata
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: str = "sentinel"
    expires_at: Optional[str] = None  # ISO format, None = permanent
    
    # Tags for organization
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'direction': self.direction,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'action': self.action.value,
            'rate_limit': self.rate_limit,
            'rate_limit_burst': self.rate_limit_burst,
            'priority': self.priority,
            'created_at': self.created_at,
            'created_by': self.created_by,
            'expires_at': self.expires_at,
            'tags': self.tags,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FirewallRule':
        """Create from dictionary."""
        if 'action' in data and isinstance(data['action'], str):
            data['action'] = FirewallAction(data['action'])
        return cls(**data)
    
    @classmethod
    def block_ip(cls, ip: str, duration_hours: int = 24, reason: str = "") -> 'FirewallRule':
        """Create a rule to block an IP address."""
        from datetime import timedelta
        
        expires_at = None
        if duration_hours > 0:
            expires_at = (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat()
        
        return cls(
            name=f"block_{ip.replace('.', '_').replace('/', '_')}",
            description=reason or f"Block IP {ip}",
            direction="ingress",
            source_ip=ip,
            action=FirewallAction.DROP,
            priority=10,  # High priority
            expires_at=expires_at,
            tags={'type': 'block', 'auto_generated': 'true'}
        )
    
    @classmethod
    def rate_limit_ip(cls, ip: str, pps: int = 10, burst: int = 5) -> 'FirewallRule':
        """Create a rate limiting rule for an IP."""
        return cls(
            name=f"ratelimit_{ip.replace('.', '_').replace('/', '_')}",
            description=f"Rate limit {ip} to {pps} pps",
            direction="ingress",
            source_ip=ip,
            action=FirewallAction.RATE_LIMIT,
            rate_limit=pps,
            rate_limit_burst=burst,
            priority=50,
            tags={'type': 'rate_limit', 'auto_generated': 'true'}
        )


class FirewallAdapter(ABC):
    """
    Abstract base class for firewall adapters.
    
    All platform-specific adapters must implement this interface.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return adapter name."""
        pass
    
    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this firewall is available on the system."""
        pass
    
    @abstractmethod
    def add_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """
        Add a firewall rule.
        
        Args:
            rule: Rule to add
            
        Returns:
            Result dict with 'success' and details
        """
        pass
    
    @abstractmethod
    def remove_rule(self, rule_id: str) -> Dict[str, Any]:
        """
        Remove a firewall rule.
        
        Args:
            rule_id: ID of rule to remove
            
        Returns:
            Result dict with 'success' and details
        """
        pass
    
    @abstractmethod
    def list_rules(self) -> List[FirewallRule]:
        """
        List all firewall rules.
        
        Returns:
            List of FirewallRule objects
        """
        pass
    
    @abstractmethod
    def clear_sentinel_rules(self) -> Dict[str, Any]:
        """
        Remove all SENTINEL-managed rules.
        
        Returns:
            Result dict with count of rules removed
        """
        pass
    
    def block_ip(self, ip: str, duration_hours: int = 24, reason: str = "") -> Dict[str, Any]:
        """Convenience method to block an IP."""
        rule = FirewallRule.block_ip(ip, duration_hours, reason)
        return self.add_rule(rule)
    
    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """Convenience method to unblock an IP."""
        rules = self.list_rules()
        
        results = []
        for rule in rules:
            if rule.source_ip == ip and rule.action in [FirewallAction.DROP, FirewallAction.DENY]:
                result = self.remove_rule(rule.id)
                results.append(result)
        
        return {
            'success': all(r.get('success', False) for r in results),
            'rules_removed': len(results)
        }
    
    def rate_limit_ip(self, ip: str, pps: int = 10, burst: int = 5) -> Dict[str, Any]:
        """Convenience method to rate limit an IP."""
        rule = FirewallRule.rate_limit_ip(ip, pps, burst)
        return self.add_rule(rule)
    
    def get_status(self) -> Dict[str, Any]:
        """Get adapter status."""
        rules = self.list_rules()
        
        return {
            'adapter': self.name,
            'available': self.is_available,
            'total_rules': len(rules),
            'sentinel_rules': len([r for r in rules if r.created_by == 'sentinel']),
        }
