"""
SENTINEL Policy Orchestrator Service

Translates AI/DRL policy decisions into vendor-specific firewall rules.
Supports multiple firewall vendors and provides policy validation,
conflict detection, and rollback capabilities.
"""
import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
import redis
from functools import wraps
import uuid

from policies.policy_engine import PolicyEngine
from policies.rule_generator import RuleGenerator
from vendors.vendor_factory import VendorFactory
from validation.policy_validator import PolicyValidator

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['POLICY_TTL'] = int(os.environ.get('POLICY_TTL', '3600'))  # 1 hour default
app.config['MAX_RULES_PER_POLICY'] = int(os.environ.get('MAX_RULES_PER_POLICY', '1000'))
app.config['SANDBOX_ENABLED'] = os.environ.get('SANDBOX_ENABLED', 'true').lower() == 'true'
app.config['AUTO_ROLLBACK_THRESHOLD'] = float(os.environ.get('AUTO_ROLLBACK_THRESHOLD', '0.05'))

# Initialize Redis
redis_client = redis.from_url(app.config['REDIS_URL'])

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
policy_engine = PolicyEngine(redis_client)
rule_generator = RuleGenerator()
vendor_factory = VendorFactory()
policy_validator = PolicyValidator()


def require_auth(f):
    """Authentication decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def require_role(role):
    """Role requirement decorator."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # In production, verify role from token
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'components': {
            'policy_engine': policy_engine.is_ready(),
            'validator': policy_validator.is_ready(),
            'vendors': vendor_factory.get_available_vendors()
        }
    }), 200


@app.route('/api/v1/policies', methods=['GET'])
@require_auth
def get_policies():
    """Get all active policies."""
    try:
        policies = policy_engine.get_all_policies()
        return jsonify({
            'policies': policies,
            'total': len(policies)
        }), 200
    except Exception as e:
        logger.error(f"Get policies error: {e}")
        return jsonify({'error': 'Failed to retrieve policies'}), 500


@app.route('/api/v1/policies/<policy_id>', methods=['GET'])
@require_auth
def get_policy(policy_id):
    """Get specific policy details."""
    try:
        policy = policy_engine.get_policy(policy_id)
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        return jsonify(policy), 200
    except Exception as e:
        logger.error(f"Get policy error: {e}")
        return jsonify({'error': 'Failed to retrieve policy'}), 500


@app.route('/api/v1/policies', methods=['POST'])
@require_auth
@require_role('admin')
def create_policy():
    """
    Create a new firewall policy.
    
    Request body:
    {
        "name": "Block suspicious IPs",
        "description": "Block traffic from detected malicious sources",
        "action": "DENY",
        "source": {"ip": "192.168.1.100", "cidr": "/32"},
        "destination": {"port": 22},
        "protocol": "TCP",
        "priority": 100,
        "duration": 3600,  # seconds, optional
        "vendors": ["iptables", "aws_security_group"]
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body required'}), 400
        
        # Validate required fields
        required = ['name', 'action']
        for field in required:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Generate rules from policy
        rules = rule_generator.generate(data)
        
        # Validate policy
        validation_result = policy_validator.validate(rules)
        if not validation_result['valid']:
            return jsonify({
                'error': 'Policy validation failed',
                'issues': validation_result['issues']
            }), 400
        
        # Check for conflicts
        conflicts = policy_engine.check_conflicts(rules)
        if conflicts and not data.get('force', False):
            return jsonify({
                'error': 'Policy conflicts detected',
                'conflicts': conflicts,
                'hint': 'Use force=true to override'
            }), 409
        
        # Create policy
        policy = policy_engine.create_policy(data, rules)
        
        # Apply to vendors if specified
        vendors = data.get('vendors', [])
        if vendors:
            apply_results = []
            for vendor_name in vendors:
                try:
                    vendor = vendor_factory.get_vendor(vendor_name)
                    if vendor:
                        result = vendor.apply_rules(rules)
                        apply_results.append({
                            'vendor': vendor_name,
                            'success': result['success'],
                            'message': result.get('message')
                        })
                except Exception as e:
                    apply_results.append({
                        'vendor': vendor_name,
                        'success': False,
                        'message': str(e)
                    })
            
            policy['apply_results'] = apply_results
        
        return jsonify({
            'message': 'Policy created successfully',
            'policy': policy
        }), 201
    
    except Exception as e:
        logger.error(f"Create policy error: {e}")
        return jsonify({'error': 'Failed to create policy'}), 500


@app.route('/api/v1/policies/<policy_id>', methods=['PUT'])
@require_auth
@require_role('admin')
def update_policy(policy_id):
    """Update an existing policy."""
    try:
        data = request.get_json()
        
        existing = policy_engine.get_policy(policy_id)
        if not existing:
            return jsonify({'error': 'Policy not found'}), 404
        
        # Merge with existing
        updated_data = {**existing, **data, 'id': policy_id}
        
        # Regenerate rules
        rules = rule_generator.generate(updated_data)
        
        # Validate
        validation_result = policy_validator.validate(rules)
        if not validation_result['valid']:
            return jsonify({
                'error': 'Policy validation failed',
                'issues': validation_result['issues']
            }), 400
        
        # Update policy
        policy = policy_engine.update_policy(policy_id, updated_data, rules)
        
        return jsonify({
            'message': 'Policy updated successfully',
            'policy': policy
        }), 200
    
    except Exception as e:
        logger.error(f"Update policy error: {e}")
        return jsonify({'error': 'Failed to update policy'}), 500


@app.route('/api/v1/policies/<policy_id>', methods=['DELETE'])
@require_auth
@require_role('admin')
def delete_policy(policy_id):
    """Delete a policy."""
    try:
        existing = policy_engine.get_policy(policy_id)
        if not existing:
            return jsonify({'error': 'Policy not found'}), 404
        
        # Remove from vendors
        vendors = existing.get('vendors', [])
        for vendor_name in vendors:
            try:
                vendor = vendor_factory.get_vendor(vendor_name)
                if vendor:
                    vendor.remove_rules(existing.get('rules', []))
            except Exception as e:
                logger.warning(f"Failed to remove rules from {vendor_name}: {e}")
        
        # Delete policy
        policy_engine.delete_policy(policy_id)
        
        return jsonify({'message': 'Policy deleted successfully'}), 200
    
    except Exception as e:
        logger.error(f"Delete policy error: {e}")
        return jsonify({'error': 'Failed to delete policy'}), 500


@app.route('/api/v1/policies/apply', methods=['POST'])
@require_auth
@require_role('admin')
def apply_drl_decision():
    """
    Apply a DRL policy decision.
    
    Request body:
    {
        "decision_id": "drl_12345",
        "action": "DENY",
        "target": {
            "source_ip": "192.168.1.100",
            "source_cidr": "/32",
            "dest_port": 22,
            "protocol": "TCP"
        },
        "duration": 3600,
        "confidence": 0.95,
        "threat_type": "brute_force",
        "vendors": ["iptables"]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'action' not in data or 'target' not in data:
            return jsonify({'error': 'action and target are required'}), 400
        
        # Convert DRL decision to policy
        policy_data = {
            'name': f"DRL Decision {data.get('decision_id', 'unknown')}",
            'description': f"Auto-generated from DRL decision for {data.get('threat_type', 'unknown')}",
            'action': data['action'],
            'source': {
                'ip': data['target'].get('source_ip'),
                'cidr': data['target'].get('source_cidr', '/32')
            },
            'destination': {
                'port': data['target'].get('dest_port')
            },
            'protocol': data['target'].get('protocol', 'any'),
            'priority': 50,  # High priority for automated decisions
            'duration': data.get('duration', 3600),
            'vendors': data.get('vendors', []),
            'metadata': {
                'drl_decision_id': data.get('decision_id'),
                'confidence': data.get('confidence'),
                'threat_type': data.get('threat_type'),
                'automated': True
            }
        }
        
        # Generate and validate rules
        rules = rule_generator.generate(policy_data)
        
        validation_result = policy_validator.validate(rules)
        if not validation_result['valid']:
            return jsonify({
                'error': 'DRL decision validation failed',
                'issues': validation_result['issues']
            }), 400
        
        # Apply in sandbox mode first if enabled
        if app.config['SANDBOX_ENABLED']:
            sandbox_result = policy_engine.test_in_sandbox(rules)
            if not sandbox_result['success']:
                return jsonify({
                    'error': 'Sandbox test failed',
                    'details': sandbox_result
                }), 400
        
        # Create and apply policy
        policy = policy_engine.create_policy(policy_data, rules)
        
        # Apply to vendors
        apply_results = []
        for vendor_name in data.get('vendors', []):
            vendor = vendor_factory.get_vendor(vendor_name)
            if vendor:
                result = vendor.apply_rules(rules)
                apply_results.append({
                    'vendor': vendor_name,
                    'success': result['success'],
                    'rules_applied': len(rules)
                })
        
        return jsonify({
            'message': 'DRL decision applied successfully',
            'policy_id': policy['id'],
            'rules_generated': len(rules),
            'apply_results': apply_results
        }), 201
    
    except Exception as e:
        logger.error(f"Apply DRL decision error: {e}")
        return jsonify({'error': 'Failed to apply DRL decision'}), 500


@app.route('/api/v1/policies/<policy_id>/rollback', methods=['POST'])
@require_auth
@require_role('admin')
def rollback_policy(policy_id):
    """Rollback a policy to previous version."""
    try:
        result = policy_engine.rollback_policy(policy_id)
        
        if not result['success']:
            return jsonify({
                'error': 'Rollback failed',
                'message': result.get('message')
            }), 400
        
        return jsonify({
            'message': 'Policy rolled back successfully',
            'previous_version': result.get('previous_version'),
            'current_version': result.get('current_version')
        }), 200
    
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        return jsonify({'error': 'Failed to rollback policy'}), 500


@app.route('/api/v1/rules/translate', methods=['POST'])
@require_auth
def translate_rules():
    """
    Translate generic rules to vendor-specific format.
    
    Request body:
    {
        "rules": [...],
        "target_vendor": "iptables"
    }
    """
    try:
        data = request.get_json()
        
        rules = data.get('rules', [])
        target_vendor = data.get('target_vendor')
        
        if not rules or not target_vendor:
            return jsonify({'error': 'rules and target_vendor are required'}), 400
        
        vendor = vendor_factory.get_vendor(target_vendor)
        if not vendor:
            return jsonify({'error': f'Unknown vendor: {target_vendor}'}), 400
        
        translated = vendor.translate_rules(rules)
        
        return jsonify({
            'vendor': target_vendor,
            'translated_rules': translated,
            'count': len(translated)
        }), 200
    
    except Exception as e:
        logger.error(f"Rule translation error: {e}")
        return jsonify({'error': 'Failed to translate rules'}), 500


@app.route('/api/v1/vendors', methods=['GET'])
@require_auth
def get_vendors():
    """Get available firewall vendors."""
    return jsonify({
        'vendors': vendor_factory.get_available_vendors()
    }), 200


@app.route('/api/v1/vendors/<vendor_name>/status', methods=['GET'])
@require_auth
def get_vendor_status(vendor_name):
    """Get vendor connection status."""
    try:
        vendor = vendor_factory.get_vendor(vendor_name)
        if not vendor:
            return jsonify({'error': f'Unknown vendor: {vendor_name}'}), 404
        
        status = vendor.get_status()
        return jsonify(status), 200
    
    except Exception as e:
        logger.error(f"Vendor status error: {e}")
        return jsonify({'error': 'Failed to get vendor status'}), 500


@app.route('/api/v1/validate', methods=['POST'])
@require_auth
def validate_policy():
    """Validate a policy without applying it."""
    try:
        data = request.get_json()
        
        rules = rule_generator.generate(data)
        validation_result = policy_validator.validate(rules)
        conflicts = policy_engine.check_conflicts(rules)
        
        return jsonify({
            'valid': validation_result['valid'] and not conflicts,
            'validation': validation_result,
            'conflicts': conflicts,
            'rules_preview': rules
        }), 200
    
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return jsonify({'error': 'Validation failed'}), 500


@app.route('/api/v1/statistics', methods=['GET'])
@require_auth
def get_statistics():
    """Get policy orchestrator statistics."""
    try:
        stats = policy_engine.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Statistics error: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500


# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5004)),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
