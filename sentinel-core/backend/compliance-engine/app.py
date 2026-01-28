"""
SENTINEL Compliance Engine

Automated compliance assessment and reporting for:
- GDPR (General Data Protection Regulation)
- HIPAA (Health Insurance Portability and Accountability Act)
- PCI-DSS (Payment Card Industry Data Security Standard)
- NIST CSF (Cybersecurity Framework)
- SOC2 (Service Organization Control 2)
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
import redis
from functools import wraps

from frameworks.gdpr import GDPRFramework
from frameworks.hipaa import HIPAAFramework
from frameworks.pci_dss import PCIDSSFramework
from frameworks.nist_csf import NISTCSFFramework
from mappings.policy_mapper import PolicyToControlMapper
from reports.compliance_reporter import ComplianceReporter

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')

# Initialize Redis
redis_client = redis.from_url(app.config['REDIS_URL'])

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize frameworks
frameworks = {
    'GDPR': GDPRFramework(),
    'HIPAA': HIPAAFramework(),
    'PCI-DSS': PCIDSSFramework(),
    'NIST': NISTCSFFramework()
}

policy_mapper = PolicyToControlMapper(frameworks)
reporter = ComplianceReporter(redis_client)


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization required'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'frameworks': list(frameworks.keys())
    }), 200


@app.route('/api/v1/frameworks', methods=['GET'])
@require_auth
def get_frameworks():
    """Get available compliance frameworks."""
    framework_list = []
    for name, framework in frameworks.items():
        framework_list.append({
            'id': name,
            'name': framework.full_name,
            'description': framework.description,
            'control_count': len(framework.controls)
        })
    return jsonify({'frameworks': framework_list}), 200


@app.route('/api/v1/frameworks/<framework_id>', methods=['GET'])
@require_auth
def get_framework_details(framework_id):
    """Get framework details and controls."""
    framework = frameworks.get(framework_id.upper())
    if not framework:
        return jsonify({'error': 'Framework not found'}), 404
    
    return jsonify({
        'id': framework_id.upper(),
        'name': framework.full_name,
        'description': framework.description,
        'controls': framework.get_controls_summary(),
        'categories': framework.get_categories()
    }), 200


@app.route('/api/v1/assess', methods=['POST'])
@require_auth
def assess_compliance():
    """
    Assess compliance status for policies.
    
    Request body:
    {
        "framework": "GDPR",
        "policies": [...],
        "configurations": {...}
    }
    """
    try:
        data = request.get_json()
        framework_id = data.get('framework', 'NIST').upper()
        policies = data.get('policies', [])
        configurations = data.get('configurations', {})
        
        framework = frameworks.get(framework_id)
        if not framework:
            return jsonify({'error': f'Unknown framework: {framework_id}'}), 400
        
        # Map policies to controls
        mappings = policy_mapper.map_policies(policies, framework_id)
        
        # Assess each control
        assessment = framework.assess(policies, configurations)
        
        # Calculate overall score
        score = framework.calculate_score(assessment)
        
        result = {
            'framework': framework_id,
            'assessment_id': f"assess_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            'timestamp': datetime.utcnow().isoformat(),
            'overall_score': score,
            'status': 'compliant' if score >= 80 else 'partially_compliant' if score >= 60 else 'non_compliant',
            'control_assessments': assessment,
            'policy_mappings': mappings,
            'gaps': framework.identify_gaps(assessment),
            'recommendations': framework.get_recommendations(assessment)
        }
        
        # Store assessment
        reporter.store_assessment(result)
        
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f"Assessment error: {e}")
        return jsonify({'error': 'Assessment failed'}), 500


@app.route('/api/v1/gap-analysis', methods=['POST'])
@require_auth
def gap_analysis():
    """Perform gap analysis between current state and target framework."""
    try:
        data = request.get_json()
        framework_id = data.get('framework', 'NIST').upper()
        current_controls = data.get('current_controls', {})
        
        framework = frameworks.get(framework_id)
        if not framework:
            return jsonify({'error': f'Unknown framework: {framework_id}'}), 400
        
        gaps = framework.detailed_gap_analysis(current_controls)
        
        return jsonify({
            'framework': framework_id,
            'timestamp': datetime.utcnow().isoformat(),
            'gaps': gaps,
            'remediation_priority': framework.prioritize_gaps(gaps),
            'estimated_effort': framework.estimate_remediation_effort(gaps)
        }), 200
    
    except Exception as e:
        logger.error(f"Gap analysis error: {e}")
        return jsonify({'error': 'Gap analysis failed'}), 500


@app.route('/api/v1/reports', methods=['POST'])
@require_auth
def generate_report():
    """Generate compliance report."""
    try:
        data = request.get_json()
        framework_id = data.get('framework', 'NIST').upper()
        report_type = data.get('type', 'summary')
        date_range = data.get('date_range')
        
        report = reporter.generate(
            framework_id,
            report_type,
            date_range
        )
        
        return jsonify(report), 200
    
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return jsonify({'error': 'Report generation failed'}), 500


@app.route('/api/v1/reports/history', methods=['GET'])
@require_auth
def get_report_history():
    """Get historical compliance reports."""
    framework = request.args.get('framework')
    limit = int(request.args.get('limit', 10))
    
    history = reporter.get_history(framework, limit)
    return jsonify({'reports': history}), 200


@app.route('/api/v1/map-policy', methods=['POST'])
@require_auth
def map_policy_to_controls():
    """Map a policy to compliance controls."""
    try:
        data = request.get_json()
        policy = data.get('policy', {})
        framework_ids = data.get('frameworks', list(frameworks.keys()))
        
        mappings = {}
        for framework_id in framework_ids:
            if framework_id.upper() in frameworks:
                mappings[framework_id] = policy_mapper.map_single_policy(
                    policy, framework_id.upper()
                )
        
        return jsonify({
            'policy_id': policy.get('id'),
            'mappings': mappings
        }), 200
    
    except Exception as e:
        logger.error(f"Policy mapping error: {e}")
        return jsonify({'error': 'Policy mapping failed'}), 500


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5007)),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
