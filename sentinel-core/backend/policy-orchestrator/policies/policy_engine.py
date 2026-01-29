"""
Policy Engine for managing firewall policies.
"""
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import redis

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Core policy management engine.
    
    Handles policy lifecycle including creation, updates,
    conflict detection, versioning, and rollback.
    """
    
    POLICY_PREFIX = "policy:"
    VERSION_PREFIX = "policy_version:"
    RULE_PREFIX = "rule:"
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self._ready = True
    
    def is_ready(self) -> bool:
        """Check if engine is ready."""
        return self._ready
    
    def create_policy(self, policy_data: Dict[str, Any], 
                      rules: List[Dict]) -> Dict[str, Any]:
        """
        Create a new policy.
        
        Args:
            policy_data: Policy configuration
            rules: Generated rules for this policy
            
        Returns:
            Created policy with ID
        """
        policy_id = f"pol_{uuid.uuid4().hex[:12]}"
        
        policy = {
            'id': policy_id,
            'name': policy_data.get('name', 'Unnamed Policy'),
            'description': policy_data.get('description', ''),
            'action': policy_data.get('action', 'DENY'),
            'source': policy_data.get('source', {}),
            'destination': policy_data.get('destination', {}),
            'protocol': policy_data.get('protocol', 'any'),
            'priority': policy_data.get('priority', 100),
            'duration': policy_data.get('duration'),
            'vendors': policy_data.get('vendors', []),
            'metadata': policy_data.get('metadata', {}),
            'rules': rules,
            'status': 'active',
            'version': 1,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'created_by': policy_data.get('created_by', 'system')
        }
        
        # Store policy
        policy_key = f"{self.POLICY_PREFIX}{policy_id}"
        self.redis.set(policy_key, json.dumps(policy))
        
        # Set expiration if duration specified
        if policy.get('duration'):
            self.redis.expire(policy_key, policy['duration'])
        
        # Store version history
        self._save_version(policy_id, policy)
        
        # Index rules for conflict detection
        self._index_rules(policy_id, rules)
        
        # Update statistics
        self.redis.incr('policy_orchestrator:total_policies')
        
        logger.info(f"Created policy {policy_id}: {policy['name']}")
        return policy
    
    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get policy by ID."""
        policy_key = f"{self.POLICY_PREFIX}{policy_id}"
        data = self.redis.get(policy_key)
        
        if data:
            return json.loads(data)
        return None
    
    def get_all_policies(self) -> List[Dict[str, Any]]:
        """Get all active policies."""
        policies = []
        
        for key in self.redis.scan_iter(f"{self.POLICY_PREFIX}*"):
            if not key.decode().startswith(self.VERSION_PREFIX):
                data = self.redis.get(key)
                if data:
                    policy = json.loads(data)
                    # Return summary
                    policies.append({
                        'id': policy['id'],
                        'name': policy['name'],
                        'action': policy['action'],
                        'status': policy['status'],
                        'priority': policy['priority'],
                        'rule_count': len(policy.get('rules', [])),
                        'created_at': policy['created_at']
                    })
        
        return sorted(policies, key=lambda x: x['priority'])
    
    def update_policy(self, policy_id: str, policy_data: Dict[str, Any],
                      rules: List[Dict]) -> Dict[str, Any]:
        """Update an existing policy."""
        existing = self.get_policy(policy_id)
        if not existing:
            raise ValueError(f"Policy {policy_id} not found")
        
        # Save current version
        self._save_version(policy_id, existing)
        
        # Remove old rule indexes
        self._remove_rule_indexes(policy_id)
        
        # Update policy
        updated = {
            **existing,
            'name': policy_data.get('name', existing['name']),
            'description': policy_data.get('description', existing['description']),
            'action': policy_data.get('action', existing['action']),
            'source': policy_data.get('source', existing['source']),
            'destination': policy_data.get('destination', existing['destination']),
            'protocol': policy_data.get('protocol', existing['protocol']),
            'priority': policy_data.get('priority', existing['priority']),
            'rules': rules,
            'version': existing['version'] + 1,
            'updated_at': datetime.utcnow().isoformat()
        }
        
        # Store updated policy
        policy_key = f"{self.POLICY_PREFIX}{policy_id}"
        self.redis.set(policy_key, json.dumps(updated))
        
        # Re-index rules
        self._index_rules(policy_id, rules)
        
        logger.info(f"Updated policy {policy_id} to version {updated['version']}")
        return updated
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy."""
        policy_key = f"{self.POLICY_PREFIX}{policy_id}"
        
        # Remove rule indexes
        self._remove_rule_indexes(policy_id)
        
        # Delete policy
        result = self.redis.delete(policy_key)
        
        if result:
            self.redis.decr('policy_orchestrator:total_policies')
            logger.info(f"Deleted policy {policy_id}")
        
        return result > 0
    
    def check_conflicts(self, rules: List[Dict]) -> List[Dict[str, Any]]:
        """
        Check for conflicts with existing policies.
        
        Args:
            rules: Rules to check
            
        Returns:
            List of conflicts found
        """
        conflicts = []
        
        for rule in rules:
            # Build index key
            index_key = self._build_rule_index_key(rule)
            
            # Check for existing rules with same key
            existing = self.redis.smembers(f"{self.RULE_PREFIX}index:{index_key}")
            
            if existing:
                for policy_id in existing:
                    policy_id = policy_id.decode() if isinstance(policy_id, bytes) else policy_id
                    policy = self.get_policy(policy_id)
                    
                    if policy:
                        conflicts.append({
                            'policy_id': policy_id,
                            'policy_name': policy['name'],
                            'conflicting_rule': rule,
                            'existing_action': policy['action']
                        })
        
        return conflicts
    
    def rollback_policy(self, policy_id: str) -> Dict[str, Any]:
        """Rollback policy to previous version."""
        current = self.get_policy(policy_id)
        if not current:
            return {'success': False, 'message': 'Policy not found'}
        
        if current['version'] <= 1:
            return {'success': False, 'message': 'No previous version available'}
        
        # Get previous version
        version_key = f"{self.VERSION_PREFIX}{policy_id}:{current['version'] - 1}"
        previous_data = self.redis.get(version_key)
        
        if not previous_data:
            return {'success': False, 'message': 'Previous version not found'}
        
        previous = json.loads(previous_data)
        
        # Restore previous version
        policy_key = f"{self.POLICY_PREFIX}{policy_id}"
        previous['version'] = current['version'] + 1
        previous['updated_at'] = datetime.utcnow().isoformat()
        
        self.redis.set(policy_key, json.dumps(previous))
        
        # Update rule indexes
        self._remove_rule_indexes(policy_id)
        self._index_rules(policy_id, previous.get('rules', []))
        
        logger.info(f"Rolled back policy {policy_id} to version {previous['version']}")
        
        return {
            'success': True,
            'previous_version': current['version'],
            'current_version': previous['version']
        }
    
    def test_in_sandbox(self, rules: List[Dict]) -> Dict[str, Any]:
        """Test rules in sandbox environment."""
        # Simulate sandbox testing
        logger.info(f"Testing {len(rules)} rules in sandbox")
        
        # Basic validation
        issues = []
        for rule in rules:
            if not rule.get('action'):
                issues.append({'rule': rule, 'issue': 'Missing action'})
        
        return {
            'success': len(issues) == 0,
            'rules_tested': len(rules),
            'issues': issues
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get policy orchestrator statistics."""
        total_policies = int(self.redis.get('policy_orchestrator:total_policies') or 0)
        
        # Count by action
        action_counts = {'ALLOW': 0, 'DENY': 0, 'RATE_LIMIT': 0, 'MONITOR': 0}
        for key in self.redis.scan_iter(f"{self.POLICY_PREFIX}*"):
            if not key.decode().startswith(self.VERSION_PREFIX):
                data = self.redis.get(key)
                if data:
                    policy = json.loads(data)
                    action = policy.get('action', 'DENY')
                    if action in action_counts:
                        action_counts[action] += 1
        
        return {
            'total_policies': total_policies,
            'policies_by_action': action_counts,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _save_version(self, policy_id: str, policy: Dict[str, Any]):
        """Save policy version for rollback."""
        version = policy.get('version', 1)
        version_key = f"{self.VERSION_PREFIX}{policy_id}:{version}"
        self.redis.set(version_key, json.dumps(policy))
        self.redis.expire(version_key, 86400 * 30)  # Keep 30 days
    
    def _index_rules(self, policy_id: str, rules: List[Dict]):
        """Index rules for conflict detection."""
        for rule in rules:
            index_key = self._build_rule_index_key(rule)
            self.redis.sadd(f"{self.RULE_PREFIX}index:{index_key}", policy_id)
    
    def _remove_rule_indexes(self, policy_id: str):
        """Remove rule indexes for a policy."""
        for key in self.redis.scan_iter(f"{self.RULE_PREFIX}index:*"):
            self.redis.srem(key, policy_id)
    
    def _build_rule_index_key(self, rule: Dict) -> str:
        """Build index key from rule."""
        parts = [
            rule.get('source_ip', '*'),
            rule.get('dest_ip', '*'),
            str(rule.get('dest_port', '*')),
            rule.get('protocol', '*')
        ]
        return ':'.join(parts)
