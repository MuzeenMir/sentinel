"""
SENTINEL DRL (Deep Reinforcement Learning) Policy Engine

Autonomous firewall policy generation using Proximal Policy Optimization (PPO).
Learns optimal security policies from network traffic patterns and threat detection.
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
import numpy as np
from functools import wraps

from agent.ppo_agent import PPOAgent
from agent.state_builder import StateBuilder
from agent.action_space import ActionSpace
from agent.reward_function import RewardFunction
from environment.network_env import NetworkSecurityEnv
from training.trainer import DRLTrainer

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['MODEL_PATH'] = os.environ.get('MODEL_PATH', '/models/drl')
app.config['POLICY_SERVICE_URL'] = os.environ.get('POLICY_SERVICE_URL', 'http://policy-orchestrator:5004')
app.config['AI_ENGINE_URL'] = os.environ.get('AI_ENGINE_URL', 'http://ai-engine:5003')

# Initialize Redis
redis_client = redis.from_url(app.config['REDIS_URL'])

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
state_builder = StateBuilder()
action_space = ActionSpace()
reward_function = RewardFunction(redis_client)
ppo_agent = None
trainer = None


def initialize_agent():
    """Initialize the PPO agent."""
    global ppo_agent, trainer
    
    try:
        logger.info("Initializing DRL agent...")
        
        # Create PPO agent
        ppo_agent = PPOAgent(
            state_dim=state_builder.state_dim,
            action_dim=action_space.action_dim,
            model_path=app.config['MODEL_PATH']
        )
        
        # Create trainer
        trainer = DRLTrainer(
            agent=ppo_agent,
            state_builder=state_builder,
            action_space=action_space,
            reward_function=reward_function,
            redis_client=redis_client
        )
        
        # Load existing model if available
        if ppo_agent.load_model():
            logger.info("Loaded existing DRL model")
        else:
            logger.info("Initialized new DRL model")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize DRL agent: {e}")
        return False


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
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'agent_ready': ppo_agent is not None and ppo_agent.is_ready(),
        'model_version': ppo_agent.get_version() if ppo_agent else None
    }), 200


@app.route('/api/v1/decide', methods=['POST'])
@require_auth
def get_policy_decision():
    """
    Get a policy decision for a threat detection.
    
    Request body:
    {
        "detection_id": "det_12345",
        "threat_score": 0.95,
        "threat_type": "brute_force",
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "dest_port": 22,
        "protocol": "TCP",
        "asset_criticality": 4,
        "context": {...}
    }
    
    Returns:
    {
        "decision_id": "drl_12345",
        "action": "DENY",
        "confidence": 0.92,
        "parameters": {...},
        "explanation": "..."
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'threat_score' not in data:
            return jsonify({'error': 'threat_score is required'}), 400
        
        # Build state from detection
        state = state_builder.build_state(data)
        
        # Get action from agent
        action, action_probs = ppo_agent.select_action(state)
        
        # Decode action
        decoded_action = action_space.decode_action(action)
        
        # Calculate confidence
        confidence = float(action_probs[action])
        
        # Generate decision ID
        decision_id = f"drl_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{data.get('detection_id', 'unknown')[-6:]}"
        
        # Build response
        decision = {
            'decision_id': decision_id,
            'action': decoded_action['action'],
            'action_code': int(action),
            'confidence': confidence,
            'parameters': {
                'target': {
                    'source_ip': data.get('source_ip'),
                    'dest_port': data.get('dest_port'),
                    'protocol': data.get('protocol', 'TCP')
                },
                **decoded_action.get('parameters', {})
            },
            'state_features': {
                'threat_score': data.get('threat_score'),
                'asset_criticality': data.get('asset_criticality'),
                'threat_type': data.get('threat_type')
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Store decision for learning
        store_decision(decision, data)
        
        return jsonify(decision), 200
    
    except Exception as e:
        logger.error(f"Decision error: {e}")
        return jsonify({'error': 'Failed to generate decision'}), 500


@app.route('/api/v1/decide/batch', methods=['POST'])
@require_auth
def get_batch_decisions():
    """Get policy decisions for multiple detections."""
    try:
        data = request.get_json()
        
        if not data or 'detections' not in data:
            return jsonify({'error': 'detections array is required'}), 400
        
        decisions = []
        for detection in data['detections']:
            state = state_builder.build_state(detection)
            action, action_probs = ppo_agent.select_action(state)
            decoded = action_space.decode_action(action)
            
            decisions.append({
                'detection_id': detection.get('detection_id'),
                'action': decoded['action'],
                'confidence': float(action_probs[action]),
                'parameters': decoded.get('parameters', {})
            })
        
        return jsonify({
            'decisions': decisions,
            'total': len(decisions)
        }), 200
    
    except Exception as e:
        logger.error(f"Batch decision error: {e}")
        return jsonify({'error': 'Failed to generate batch decisions'}), 500


@app.route('/api/v1/feedback', methods=['POST'])
@require_auth
def submit_feedback():
    """
    Submit feedback on a policy decision for learning.
    
    Request body:
    {
        "decision_id": "drl_12345",
        "outcome": "success",  # success, failure, false_positive
        "blocked_threat": true,
        "false_positive": false,
        "latency_impact": 0.02,
        "user_override": false,
        "notes": "..."
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'decision_id' not in data:
            return jsonify({'error': 'decision_id is required'}), 400
        
        decision_id = data['decision_id']
        
        # Retrieve original decision
        decision_data = redis_client.get(f"drl:decision:{decision_id}")
        if not decision_data:
            return jsonify({'error': 'Decision not found'}), 404
        
        decision = json.loads(decision_data)
        
        # Calculate reward
        reward = reward_function.calculate_reward(
            action=decision.get('action_code', 0),
            blocked_threat=data.get('blocked_threat', False),
            false_positive=data.get('false_positive', False),
            latency_impact=data.get('latency_impact', 0),
            compliance_score=data.get('compliance_score', 1.0)
        )
        
        # Store experience for training
        experience = {
            'state': decision.get('state'),
            'action': decision.get('action_code'),
            'reward': reward,
            'outcome': data.get('outcome'),
            'feedback': data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        redis_client.lpush('drl:experiences', json.dumps(experience))
        redis_client.ltrim('drl:experiences', 0, 100000)  # Keep last 100K experiences
        
        # Update statistics
        redis_client.incr('drl:total_feedback')
        if data.get('false_positive'):
            redis_client.incr('drl:false_positives')
        if data.get('blocked_threat'):
            redis_client.incr('drl:blocked_threats')
        
        return jsonify({
            'message': 'Feedback recorded',
            'reward': reward
        }), 200
    
    except Exception as e:
        logger.error(f"Feedback error: {e}")
        return jsonify({'error': 'Failed to record feedback'}), 500


@app.route('/api/v1/train', methods=['POST'])
@require_auth
@require_role('admin')
def trigger_training():
    """Trigger a training iteration."""
    try:
        data = request.get_json() or {}
        
        epochs = data.get('epochs', 10)
        batch_size = data.get('batch_size', 64)
        
        # Get experiences from Redis
        experiences_raw = redis_client.lrange('drl:experiences', 0, batch_size * 10)
        
        if len(experiences_raw) < batch_size:
            return jsonify({
                'error': 'Insufficient training data',
                'available': len(experiences_raw),
                'required': batch_size
            }), 400
        
        experiences = [json.loads(e) for e in experiences_raw]
        
        # Run training
        metrics = trainer.train_on_experiences(experiences, epochs=epochs)
        
        return jsonify({
            'message': 'Training completed',
            'metrics': metrics,
            'experiences_used': len(experiences)
        }), 200
    
    except Exception as e:
        logger.error(f"Training error: {e}")
        return jsonify({'error': 'Training failed'}), 500


@app.route('/api/v1/model/save', methods=['POST'])
@require_auth
@require_role('admin')
def save_model():
    """Save the current model."""
    try:
        success = ppo_agent.save_model()
        
        if success:
            return jsonify({'message': 'Model saved successfully'}), 200
        else:
            return jsonify({'error': 'Failed to save model'}), 500
    
    except Exception as e:
        logger.error(f"Save model error: {e}")
        return jsonify({'error': 'Failed to save model'}), 500


@app.route('/api/v1/model/load', methods=['POST'])
@require_auth
@require_role('admin')
def load_model():
    """Load the model from disk."""
    try:
        success = ppo_agent.load_model()
        
        if success:
            return jsonify({'message': 'Model loaded successfully'}), 200
        else:
            return jsonify({'error': 'Failed to load model'}), 500
    
    except Exception as e:
        logger.error(f"Load model error: {e}")
        return jsonify({'error': 'Failed to load model'}), 500


@app.route('/api/v1/statistics', methods=['GET'])
@require_auth
def get_statistics():
    """Get DRL engine statistics."""
    try:
        total_decisions = int(redis_client.get('drl:total_decisions') or 0)
        total_feedback = int(redis_client.get('drl:total_feedback') or 0)
        false_positives = int(redis_client.get('drl:false_positives') or 0)
        blocked_threats = int(redis_client.get('drl:blocked_threats') or 0)
        
        # Calculate metrics
        fp_rate = false_positives / max(total_feedback, 1)
        block_rate = blocked_threats / max(total_feedback, 1)
        
        return jsonify({
            'total_decisions': total_decisions,
            'total_feedback': total_feedback,
            'blocked_threats': blocked_threats,
            'false_positives': false_positives,
            'false_positive_rate': fp_rate,
            'block_rate': block_rate,
            'model_version': ppo_agent.get_version() if ppo_agent else None,
            'experiences_available': redis_client.llen('drl:experiences'),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Statistics error: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500


@app.route('/api/v1/action-space', methods=['GET'])
@require_auth
def get_action_space():
    """Get available actions and their descriptions."""
    return jsonify({
        'actions': action_space.get_action_descriptions()
    }), 200


@app.route('/api/v1/state-space', methods=['GET'])
@require_auth
def get_state_space():
    """Get state space dimensions and features."""
    return jsonify({
        'state_dim': state_builder.state_dim,
        'features': state_builder.get_feature_descriptions()
    }), 200


def store_decision(decision: Dict, context: Dict):
    """Store decision for later learning."""
    try:
        # Store decision
        key = f"drl:decision:{decision['decision_id']}"
        decision['state'] = state_builder.build_state(context).tolist()
        redis_client.set(key, json.dumps(decision))
        redis_client.expire(key, 86400 * 7)  # 7 days
        
        # Update counter
        redis_client.incr('drl:total_decisions')
        
    except Exception as e:
        logger.error(f"Failed to store decision: {e}")


# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    initialize_agent()
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5005)),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
