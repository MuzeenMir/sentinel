import os
import requests
from flask import Flask, request, jsonify, g, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import logging
import time
from urllib.parse import urljoin
import redis
import json

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['AUTH_SERVICE_URL'] = os.environ.get('AUTH_SERVICE_URL', 'http://auth-service:5000')
app.config['DATA_COLLECTOR_URL'] = os.environ.get('DATA_COLLECTOR_URL', 'http://data-collector:5001')
app.config['ALERT_SERVICE_URL'] = os.environ.get('ALERT_SERVICE_URL', 'http://alert-service:5002')
app.config['POLICY_SERVICE_URL'] = os.environ.get('POLICY_SERVICE_URL', 'http://policy-orchestrator:5004')
app.config['COMPLIANCE_ENGINE_URL'] = os.environ.get('COMPLIANCE_ENGINE_URL', 'http://compliance-engine:5007')
app.config['XAI_SERVICE_URL'] = os.environ.get('XAI_SERVICE_URL', 'http://xai-service:5006')
app.config['AI_ENGINE_URL'] = os.environ.get('AI_ENGINE_URL', 'http://ai-engine:5003')
app.config['DRL_ENGINE_URL'] = os.environ.get('DRL_ENGINE_URL', 'http://drl-engine:5005')
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')

# Initialize extensions
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour"]
)

redis_client = redis.from_url(app.config['REDIS_URL'])

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global rate limiting
rate_limit_counter = {}

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        elif request.args.get('token'):
            # Allow token via query param for SSE/EventSource compatibility
            token = request.args.get('token')
        if not token:
            return jsonify({'error': 'Authorization token required'}), 401

        # Verify token with auth service
        try:
            response = requests.post(
                f"{app.config['AUTH_SERVICE_URL']}/api/v1/auth/verify",
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )
            if response.status_code != 200:
                return jsonify({'error': 'Invalid token'}), 401

            user_info = response.json()
            g.current_user = user_info['user']

        except requests.exceptions.RequestException as e:
            logger.error(f"Auth service communication error: {e}")
            return jsonify({'error': 'Authentication service unavailable'}), 503

        return f(*args, **kwargs)

    return decorated_function

def require_role(required_role):
    """Decorator to require specific user role"""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            current_role = g.current_user['role']
            if current_role != required_role:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def track_request(endpoint, method):
    """Track API request metrics"""
    timestamp = int(time.time())
    key = f"api_requests:{endpoint}:{method}:{timestamp}"
    redis_client.incr(key)
    redis_client.expire(key, 3600)  # Expire after 1 hour

def get_request_stats():
    """Get API request statistics"""
    current_time = int(time.time())
    stats = {}

    # Get requests for the last hour
    for i in range(3600):  # Last hour
        timestamp = current_time - i
        keys = redis_client.keys(f"api_requests:*:*:{timestamp}")
        for key in keys:
            count = redis_client.get(key)
            if count:
                parts = key.decode().split(':')
                endpoint = f"{parts[1]}:{parts[2]}"
                if endpoint not in stats:
                    stats[endpoint] = 0
                stats[endpoint] += int(count)

    return stats

# ---------------------------------------------------------------------------
# Configuration persistence
# ---------------------------------------------------------------------------
CONFIG_CACHE_KEY = "sentinel:config"

def _default_config():
    return {
        'ai_engine': {
            'model_path': '/models/current_model.pkl',
            'confidence_threshold': 0.85,
            'batch_size': 1000
        },
        'firewall': {
            'max_rules': 10000,
            'sync_interval': 30
        },
        'monitoring': {
            'alert_threshold': 0.95,
            'retention_days': 90
        }
    }

def _load_config():
    """Load config from Redis if available, else return defaults."""
    try:
        raw = redis_client.get(CONFIG_CACHE_KEY)
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning(f"Config cache read failed: {e}")
    return _default_config()

def _save_config(new_config):
    """Persist config in Redis."""
    redis_client.set(CONFIG_CACHE_KEY, json.dumps(new_config))

@app.before_request
def before_request():
    """Execute before each request"""
    g.start_time = time.time()

    # Track request
    track_request(request.endpoint or 'unknown', request.method)

@app.after_request
def after_request(response):
    """Execute after each request"""
    # Calculate request duration
    duration = time.time() - g.start_time
    response.headers['X-Response-Time'] = f"{duration:.3f}s"

    # Log request
    logger.info(f"{request.method} {request.path} - {response.status_code} - {duration:.3f}s")

    return response

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    stats = get_request_stats()
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'request_stats': stats
    }), 200

# Authentication endpoints (proxy to auth service)
@app.route('/api/v1/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def auth_proxy(path):
    """Proxy authentication requests to auth service"""
    auth_url = f"{app.config['AUTH_SERVICE_URL']}/api/v1/auth/{path}"

    try:
        if request.method == 'GET':
            response = requests.get(auth_url, params=request.args)
        elif request.method == 'POST':
            response = requests.post(auth_url, json=request.json)
        elif request.method == 'PUT':
            response = requests.put(auth_url, json=request.json)
        elif request.method == 'DELETE':
            response = requests.delete(auth_url)

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Auth service proxy error: {e}")
        return jsonify({'error': 'Auth service unavailable'}), 503

# Special route for token verification (needed by require_auth decorator)
@app.route('/api/v1/auth/verify', methods=['POST'])
def auth_verify():
    """Verify authentication token"""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        # Forward to auth service
        response = requests.post(
            f"{app.config['AUTH_SERVICE_URL']}/api/v1/auth/verify",
            headers={'Authorization': f'Bearer {token}'},
            timeout=5
        )
        
        return jsonify(response.json()), response.status_code
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Auth verification error: {e}")
        return jsonify({'error': 'Auth service unavailable'}), 503

# Threat detection endpoints
@app.route('/api/v1/threats', methods=['GET'])
@require_auth
def get_threats():
    """Get detected threats"""
    try:
        # Query data collector for threat data
        response = requests.get(
            f"{app.config['DATA_COLLECTOR_URL']}/api/v1/threats",
            headers={'Authorization': request.headers.get('Authorization')},
            params=request.args
        )

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Data collector service error: {e}")
        return jsonify({'error': 'Data collector service unavailable'}), 503

@app.route('/api/v1/threats/<int:threat_id>', methods=['GET'])
@require_auth
def get_threat(threat_id):
    """Get specific threat details"""
    try:
        response = requests.get(
            f"{app.config['DATA_COLLECTOR_URL']}/api/v1/threats/{threat_id}",
            headers={'Authorization': request.headers.get('Authorization')}
        )

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Data collector service error: {e}")
        return jsonify({'error': 'Data collector service unavailable'}), 503

@app.route('/api/v1/threats', methods=['POST'])
@require_role('admin')
def create_threat():
    """Create a new threat (manual entry)"""
    try:
        response = requests.post(
            f"{app.config['DATA_COLLECTOR_URL']}/api/v1/threats",
            headers={'Authorization': request.headers.get('Authorization')},
            json=request.json
        )

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Data collector service error: {e}")
        return jsonify({'error': 'Data collector service unavailable'}), 503

# Alert endpoints
@app.route('/api/v1/alerts', methods=['GET'])
@require_auth
def get_alerts():
    """Get system alerts"""
    try:
        response = requests.get(
            f"{app.config['ALERT_SERVICE_URL']}/api/v1/alerts",
            headers={'Authorization': request.headers.get('Authorization')},
            params=request.args
        )

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Alert service error: {e}")
        return jsonify({'error': 'Alert service unavailable'}), 503

@app.route('/api/v1/alerts/<int:alert_id>', methods=['GET'])
@require_auth
def get_alert(alert_id):
    """Get specific alert details"""
    try:
        response = requests.get(
            f"{app.config['ALERT_SERVICE_URL']}/api/v1/alerts/{alert_id}",
            headers={'Authorization': request.headers.get('Authorization')}
        )

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Alert service error: {e}")
        return jsonify({'error': 'Alert service unavailable'}), 503

@app.route('/api/v1/alerts', methods=['POST'])
@require_role('admin')
def create_alert():
    """Create a new alert"""
    try:
        response = requests.post(
            f"{app.config['ALERT_SERVICE_URL']}/api/v1/alerts",
            headers={'Authorization': request.headers.get('Authorization')},
            json=request.json
        )

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Alert service error: {e}")
        return jsonify({'error': 'Alert service unavailable'}), 503

@app.route('/api/v1/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@require_auth
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        response = requests.post(
            f"{app.config['ALERT_SERVICE_URL']}/api/v1/alerts/{alert_id}/acknowledge",
            headers={'Authorization': request.headers.get('Authorization')},
            json=request.json
        )

        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Alert service error: {e}")
        return jsonify({'error': 'Alert service unavailable'}), 503

# Configuration endpoints
@app.route('/api/v1/config', methods=['GET'])
@require_role('admin')
def get_config():
    """Get system configuration"""
    try:
        return jsonify(_load_config()), 200

    except Exception as e:
        logger.error(f"Config retrieval error: {e}")
        return jsonify({'error': 'Configuration retrieval failed'}), 500

@app.route('/api/v1/config', methods=['PUT'])
@require_role('admin')
def update_config():
    """Update system configuration"""
    try:
        new_config = request.json
        # Validate configuration
        required_keys = ['ai_engine', 'firewall', 'monitoring']
        for key in required_keys:
            if key not in new_config:
                return jsonify({'error': f'Missing configuration section: {key}'}), 400

        # Persist configuration
        _save_config(new_config)
        logger.info(f"Configuration updated by {g.current_user['username']}: {json.dumps(new_config)}")

        return jsonify({'message': 'Configuration updated successfully'}), 200

    except Exception as e:
        logger.error(f"Config update error: {e}")
        return jsonify({'error': 'Configuration update failed'}), 500

# Statistics endpoints (both /stats and /statistics for API compatibility)
@app.route('/api/v1/stats', methods=['GET'])
@app.route('/api/v1/statistics', methods=['GET'])
@require_auth
def get_statistics():
    """Get system statistics"""
    try:
        # Aggregate statistics from various services
        stats = {
            'requests': get_request_stats(),
            'threats_detected': 0,  # Would come from data collector
            'alerts_generated': 0,  # Would come from alert service
            'system_health': 'healthy',
            'timestamp': time.time()
        }

        return jsonify(stats), 200

    except Exception as e:
        logger.error(f"Stats retrieval error: {e}")
        return jsonify({'error': 'Statistics retrieval failed'}), 500

# Server-Sent Events for real-time updates
@app.route('/api/v1/stream/threats', methods=['GET'])
@require_auth
def stream_threats():
    """Stream threat update events."""
    def event_stream():
        while True:
            payload = {
                'type': 'threat_heartbeat',
                'timestamp': time.time()
            }
            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(5)
    return Response(event_stream(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    })

@app.route('/api/v1/stream/alerts', methods=['GET'])
@require_auth
def stream_alerts():
    """Stream alert update events."""
    def event_stream():
        while True:
            payload = {
                'type': 'alert_heartbeat',
                'timestamp': time.time()
            }
            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(5)
    return Response(event_stream(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    })

# Rate limiting test endpoint
@app.route('/api/v1/test-rate-limit', methods=['GET'])
@limiter.limit("5 per minute")
def test_rate_limit():
    """Test rate limiting functionality"""
    return jsonify({
        'message': 'Rate limit test successful',
        'timestamp': time.time()
    }), 200

# Request validation helper
def validate_json_request(required_fields=None):
    """Validate JSON request body"""
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400
    
    if required_fields:
        data = request.get_json() or {}
        missing = [field for field in required_fields if field not in data]
        if missing:
            return jsonify({'error': f'Missing required fields: {", ".join(missing)}'}), 400
    
    return None

# Helper: proxy request to a backend service
def _proxy_to(base_url, path_suffix, methods=None):
    """Forward request to backend; path_suffix is appended to base_url (no leading slash)."""
    url = urljoin(base_url.rstrip('/') + '/', path_suffix.lstrip('/'))
    headers = {'Authorization': request.headers.get('Authorization', '')}
    try:
        if request.method == 'GET':
            resp = requests.get(url, headers=headers, params=request.args, timeout=30)
        elif request.method == 'POST':
            resp = requests.post(url, headers=headers, json=request.get_json(silent=True), params=request.args, timeout=30)
        elif request.method == 'PUT':
            resp = requests.put(url, headers=headers, json=request.get_json(silent=True), timeout=30)
        elif request.method == 'DELETE':
            resp = requests.delete(url, headers=headers, timeout=30)
        else:
            return jsonify({'error': 'Method not allowed'}), 405
        return jsonify(resp.json() if resp.content else {}), resp.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Proxy error to {url}: {e}")
        return jsonify({'error': 'Backend service unavailable'}), 503

# Policy endpoints (proxy to policy-orchestrator)
@app.route('/api/v1/policies', methods=['GET'])
@require_auth
def get_policies():
    """Get firewall policies"""
    return _proxy_to(app.config['POLICY_SERVICE_URL'], '/api/v1/policies')

@app.route('/api/v1/policies/<policy_id>', methods=['GET'])
@require_auth
def get_policy(policy_id):
    """Get a single policy by ID"""
    return _proxy_to(app.config['POLICY_SERVICE_URL'], f'/api/v1/policies/{policy_id}')

@app.route('/api/v1/policies', methods=['POST'])
@require_role('admin')
def create_policy():
    """Create a new policy"""
    validation_error = validate_json_request(['name', 'action', 'source', 'destination'])
    if validation_error:
        return validation_error
    return _proxy_to(app.config['POLICY_SERVICE_URL'], '/api/v1/policies')

@app.route('/api/v1/policies/<policy_id>', methods=['PUT'])
@require_auth
def update_policy(policy_id):
    """Update a policy"""
    return _proxy_to(app.config['POLICY_SERVICE_URL'], f'/api/v1/policies/{policy_id}')

@app.route('/api/v1/policies/<policy_id>', methods=['DELETE'])
@require_auth
def delete_policy(policy_id):
    """Delete a policy"""
    return _proxy_to(app.config['POLICY_SERVICE_URL'], f'/api/v1/policies/{policy_id}')

# Compliance Engine proxy
@app.route('/api/v1/frameworks', methods=['GET'])
@require_auth
def get_frameworks():
    return _proxy_to(app.config['COMPLIANCE_ENGINE_URL'], '/api/v1/frameworks')

@app.route('/api/v1/frameworks/<framework_id>', methods=['GET'])
@require_auth
def get_framework(framework_id):
    return _proxy_to(app.config['COMPLIANCE_ENGINE_URL'], f'/api/v1/frameworks/{framework_id}')

@app.route('/api/v1/assess', methods=['POST'])
@require_auth
def compliance_assess():
    return _proxy_to(app.config['COMPLIANCE_ENGINE_URL'], '/api/v1/assess')

@app.route('/api/v1/gap-analysis', methods=['POST'])
@require_auth
def compliance_gap_analysis():
    return _proxy_to(app.config['COMPLIANCE_ENGINE_URL'], '/api/v1/gap-analysis')

@app.route('/api/v1/reports', methods=['POST'])
@require_auth
def compliance_reports():
    return _proxy_to(app.config['COMPLIANCE_ENGINE_URL'], '/api/v1/reports')

@app.route('/api/v1/reports/history', methods=['GET'])
@require_auth
def compliance_reports_history():
    return _proxy_to(app.config['COMPLIANCE_ENGINE_URL'], '/api/v1/reports/history')

@app.route('/api/v1/map-policy', methods=['POST'])
@require_auth
def compliance_map_policy():
    return _proxy_to(app.config['COMPLIANCE_ENGINE_URL'], '/api/v1/map-policy')

# XAI Service proxy
@app.route('/api/v1/explain/detection', methods=['POST'])
@require_auth
def xai_explain_detection():
    return _proxy_to(app.config['XAI_SERVICE_URL'], '/api/v1/explain/detection')

@app.route('/api/v1/explain/policy', methods=['POST'])
@require_auth
def xai_explain_policy():
    return _proxy_to(app.config['XAI_SERVICE_URL'], '/api/v1/explain/policy')

@app.route('/api/v1/audit-trail', methods=['GET'])
@require_auth
def xai_audit_trail():
    return _proxy_to(app.config['XAI_SERVICE_URL'], '/api/v1/audit-trail')

@app.route('/api/v1/report/compliance', methods=['POST'])
@require_auth
def xai_report_compliance():
    return _proxy_to(app.config['XAI_SERVICE_URL'], '/api/v1/report/compliance')

@app.route('/api/v1/xai/statistics', methods=['GET'])
@require_auth
def xai_statistics():
    """XAI service statistics (proxied to avoid conflict with gateway /api/v1/statistics)"""
    return _proxy_to(app.config['XAI_SERVICE_URL'], '/api/v1/statistics')

# AI Engine proxy (optional)
@app.route('/api/v1/detect', methods=['POST'])
@require_auth
def ai_detect():
    return _proxy_to(app.config['AI_ENGINE_URL'], '/api/v1/detect')

@app.route('/api/v1/detect/batch', methods=['POST'])
@require_auth
def ai_detect_batch():
    return _proxy_to(app.config['AI_ENGINE_URL'], '/api/v1/detect/batch')

# DRL Engine proxy (optional)
@app.route('/api/v1/decide', methods=['POST'])
@require_auth
def drl_decide():
    return _proxy_to(app.config['DRL_ENGINE_URL'], '/api/v1/decide')

@app.route('/api/v1/decide/batch', methods=['POST'])
@require_auth
def drl_decide_batch():
    return _proxy_to(app.config['DRL_ENGINE_URL'], '/api/v1/decide/batch')

@app.route('/api/v1/action-space', methods=['GET'])
@require_auth
def drl_action_space():
    return _proxy_to(app.config['DRL_ENGINE_URL'], '/api/v1/action-space')

@app.route('/api/v1/state-space', methods=['GET'])
@require_auth
def drl_state_space():
    return _proxy_to(app.config['DRL_ENGINE_URL'], '/api/v1/state-space')

# Error handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'error': 'Endpoint not found',
        'message': f'The requested endpoint {request.path} does not exist'
    }), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred. Please try again later.'
    }), 500

@app.errorhandler(400)
def bad_request(e):
    return jsonify({
        'error': 'Bad request',
        'message': 'Invalid request format or parameters'
    }), 400

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=8080, debug=debug_mode)
