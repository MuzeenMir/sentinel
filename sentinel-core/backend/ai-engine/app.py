"""
SENTINEL AI Detection Engine

Enterprise-grade ML-powered threat detection service with ensemble classification.
Supports supervised (XGBoost, LSTM), unsupervised (Isolation Forest, Autoencoder),
and ensemble methods for comprehensive threat detection.
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

from models.supervised.xgboost_detector import XGBoostDetector
from models.supervised.lstm_sequence import LSTMSequenceDetector
from models.unsupervised.isolation_forest import IsolationForestDetector
from models.unsupervised.autoencoder import AutoencoderDetector
from models.ensemble.stacking_classifier import StackingEnsemble
from features.statistical import StatisticalFeatureExtractor
from features.behavioral import BehavioralFeatureExtractor
from features.contextual import ContextualFeatureExtractor
from inference.prediction_service import PredictionService

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['MODEL_PATH'] = os.environ.get('MODEL_PATH', '/models')
app.config['KAFKA_BOOTSTRAP_SERVERS'] = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
app.config['CONFIDENCE_THRESHOLD'] = float(os.environ.get('CONFIDENCE_THRESHOLD', '0.85'))
app.config['BATCH_SIZE'] = int(os.environ.get('BATCH_SIZE', '1000'))

# Initialize Redis
redis_client = redis.from_url(app.config['REDIS_URL'])

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
feature_extractors = {
    'statistical': StatisticalFeatureExtractor(),
    'behavioral': BehavioralFeatureExtractor(),
    'contextual': ContextualFeatureExtractor()
}

# Initialize detectors (lazy loading)
detectors = {}
ensemble = None
prediction_service = None


def initialize_models():
    """Initialize all ML models."""
    global detectors, ensemble, prediction_service
    
    logger.info("Initializing AI detection models...")
    
    try:
        # Initialize supervised models
        detectors['xgboost'] = XGBoostDetector(
            model_path=os.path.join(app.config['MODEL_PATH'], 'xgboost')
        )
        detectors['lstm'] = LSTMSequenceDetector(
            model_path=os.path.join(app.config['MODEL_PATH'], 'lstm')
        )
        
        # Initialize unsupervised models
        detectors['isolation_forest'] = IsolationForestDetector(
            contamination=0.1
        )
        detectors['autoencoder'] = AutoencoderDetector(
            model_path=os.path.join(app.config['MODEL_PATH'], 'autoencoder')
        )
        
        # Initialize ensemble
        ensemble = StackingEnsemble(
            base_detectors=detectors,
            threshold=app.config['CONFIDENCE_THRESHOLD']
        )
        
        # Initialize prediction service
        prediction_service = PredictionService(
            feature_extractors=feature_extractors,
            ensemble=ensemble,
            redis_client=redis_client
        )
        
        logger.info("All AI models initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize models: {e}")
        return False


def require_auth(f):
    """Authentication decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        # In production, verify token with auth service
        return f(*args, **kwargs)
    return decorated_function


# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with model status."""
    model_status = {name: detector.is_ready() for name, detector in detectors.items()}
    
    return jsonify({
        'status': 'healthy' if all(model_status.values()) else 'degraded',
        'timestamp': datetime.utcnow().isoformat(),
        'models': model_status,
        'ensemble_ready': ensemble.is_ready() if ensemble else False,
        'version': '1.0.0'
    }), 200


@app.route('/api/v1/detect', methods=['POST'])
@require_auth
def detect_threat():
    """
    Perform threat detection on network traffic data.
    
    Request body:
    {
        "traffic_data": {...},  # Network traffic features
        "context": {...}        # Optional contextual data
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'traffic_data' not in data:
            return jsonify({'error': 'traffic_data is required'}), 400
        
        traffic_data = data['traffic_data']
        context = data.get('context', {})
        
        # Run prediction
        result = prediction_service.predict(traffic_data, context)
        
        # Log detection for audit
        log_detection(result)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
        return jsonify({'error': 'Detection failed', 'details': str(e)}), 500


@app.route('/api/v1/detect/batch', methods=['POST'])
@require_auth
def detect_batch():
    """
    Perform batch threat detection.
    
    Request body:
    {
        "traffic_batch": [...]  # List of traffic data objects
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'traffic_batch' not in data:
            return jsonify({'error': 'traffic_batch is required'}), 400
        
        traffic_batch = data['traffic_batch']
        
        if len(traffic_batch) > app.config['BATCH_SIZE']:
            return jsonify({
                'error': f'Batch size exceeds limit of {app.config["BATCH_SIZE"]}'
            }), 400
        
        # Run batch prediction
        results = prediction_service.predict_batch(traffic_batch)
        
        # Log detections
        for result in results:
            log_detection(result)
        
        return jsonify({
            'results': results,
            'total': len(results),
            'threats_detected': sum(1 for r in results if r['is_threat'])
        }), 200
        
    except Exception as e:
        logger.error(f"Batch detection error: {e}")
        return jsonify({'error': 'Batch detection failed', 'details': str(e)}), 500


@app.route('/api/v1/features/extract', methods=['POST'])
@require_auth
def extract_features():
    """
    Extract features from raw network data.
    
    Request body:
    {
        "raw_data": {...},
        "feature_types": ["statistical", "behavioral", "contextual"]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'raw_data' not in data:
            return jsonify({'error': 'raw_data is required'}), 400
        
        raw_data = data['raw_data']
        feature_types = data.get('feature_types', ['statistical', 'behavioral', 'contextual'])
        
        features = {}
        for ft in feature_types:
            if ft in feature_extractors:
                features[ft] = feature_extractors[ft].extract(raw_data)
        
        return jsonify({
            'features': features,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Feature extraction error: {e}")
        return jsonify({'error': 'Feature extraction failed', 'details': str(e)}), 500


@app.route('/api/v1/models/status', methods=['GET'])
@require_auth
def get_model_status():
    """Get detailed status of all detection models."""
    try:
        status = {}
        for name, detector in detectors.items():
            status[name] = {
                'ready': detector.is_ready(),
                'version': detector.get_version(),
                'metrics': detector.get_metrics(),
                'last_updated': detector.get_last_updated()
            }
        
        return jsonify({
            'models': status,
            'ensemble': {
                'ready': ensemble.is_ready() if ensemble else False,
                'threshold': app.config['CONFIDENCE_THRESHOLD']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Model status error: {e}")
        return jsonify({'error': 'Failed to get model status'}), 500


@app.route('/api/v1/models/reload', methods=['POST'])
@require_auth
def reload_models():
    """Reload all models from disk."""
    try:
        success = initialize_models()
        
        if success:
            return jsonify({'message': 'Models reloaded successfully'}), 200
        else:
            return jsonify({'error': 'Failed to reload models'}), 500
            
    except Exception as e:
        logger.error(f"Model reload error: {e}")
        return jsonify({'error': 'Model reload failed', 'details': str(e)}), 500


@app.route('/api/v1/statistics', methods=['GET'])
@require_auth
def get_statistics():
    """Get detection statistics."""
    try:
        # Get stats from Redis
        total_detections = int(redis_client.get('ai_engine:total_detections') or 0)
        threats_detected = int(redis_client.get('ai_engine:threats_detected') or 0)
        false_positives = int(redis_client.get('ai_engine:false_positives') or 0)
        
        # Calculate rates
        threat_rate = threats_detected / max(total_detections, 1)
        fp_rate = false_positives / max(threats_detected, 1)
        
        return jsonify({
            'total_detections': total_detections,
            'threats_detected': threats_detected,
            'false_positives': false_positives,
            'threat_rate': threat_rate,
            'false_positive_rate': fp_rate,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Statistics error: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500


@app.route('/api/v1/feedback', methods=['POST'])
@require_auth
def submit_feedback():
    """
    Submit feedback on detection results for model improvement.
    
    Request body:
    {
        "detection_id": "...",
        "is_correct": true/false,
        "actual_label": "benign/malicious",
        "notes": "..."
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'detection_id' not in data or 'is_correct' not in data:
            return jsonify({'error': 'detection_id and is_correct are required'}), 400
        
        # Store feedback for model retraining
        feedback_key = f"ai_engine:feedback:{data['detection_id']}"
        redis_client.hset(feedback_key, mapping={
            'is_correct': str(data['is_correct']),
            'actual_label': data.get('actual_label', ''),
            'notes': data.get('notes', ''),
            'timestamp': datetime.utcnow().isoformat()
        })
        redis_client.expire(feedback_key, 2592000)  # 30 days
        
        # Update false positive counter if applicable
        if not data['is_correct'] and data.get('actual_label') == 'benign':
            redis_client.incr('ai_engine:false_positives')
        
        return jsonify({'message': 'Feedback submitted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Feedback submission error: {e}")
        return jsonify({'error': 'Failed to submit feedback'}), 500


def log_detection(result: Dict[str, Any]):
    """Log detection result for audit trail."""
    try:
        # Increment counters
        redis_client.incr('ai_engine:total_detections')
        if result.get('is_threat'):
            redis_client.incr('ai_engine:threats_detected')
        
        # Store detection record
        detection_key = f"ai_engine:detection:{result.get('detection_id', 'unknown')}"
        redis_client.hset(detection_key, mapping={
            'timestamp': datetime.utcnow().isoformat(),
            'is_threat': str(result.get('is_threat', False)),
            'confidence': str(result.get('confidence', 0)),
            'threat_type': result.get('threat_type', 'unknown'),
            'model_verdicts': json.dumps(result.get('model_verdicts', {}))
        })
        redis_client.expire(detection_key, 604800)  # 7 days
        
    except Exception as e:
        logger.error(f"Failed to log detection: {e}")


# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Initialize models on startup
    initialize_models()
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5003)),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
