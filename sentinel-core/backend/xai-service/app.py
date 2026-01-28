"""
SENTINEL Explainable AI (XAI) Service

Provides explanations for AI detection and DRL policy decisions using:
- SHAP (SHapley Additive exPlanations)
- LIME (Local Interpretable Model-agnostic Explanations)
- Natural language summaries
- Decision audit trails
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
import redis
import numpy as np
from functools import wraps

from explainers.shap_explainer import SHAPExplainer
from explainers.text_explainer import TextExplainer
from reports.audit_trail import AuditTrail
from reports.compliance_report import ComplianceReportGenerator

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['AI_ENGINE_URL'] = os.environ.get('AI_ENGINE_URL', 'http://ai-engine:5003')
app.config['DRL_ENGINE_URL'] = os.environ.get('DRL_ENGINE_URL', 'http://drl-engine:5005')

# Initialize Redis
redis_client = redis.from_url(app.config['REDIS_URL'])

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
shap_explainer = SHAPExplainer()
text_explainer = TextExplainer()
audit_trail = AuditTrail(redis_client)
compliance_reporter = ComplianceReportGenerator()


def require_auth(f):
    """Authentication decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'components': {
            'shap_explainer': shap_explainer.is_ready(),
            'text_explainer': True,
            'audit_trail': True
        }
    }), 200


@app.route('/api/v1/explain/detection', methods=['POST'])
@require_auth
def explain_detection():
    """
    Explain a threat detection decision.
    
    Request body:
    {
        "detection_id": "det_12345",
        "features": {...},
        "prediction": {...},
        "model_verdicts": {...}
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body required'}), 400
        
        detection_id = data.get('detection_id', 'unknown')
        features = data.get('features', {})
        prediction = data.get('prediction', {})
        model_verdicts = data.get('model_verdicts', {})
        
        # Generate SHAP explanation
        shap_explanation = shap_explainer.explain_detection(features, prediction)
        
        # Generate text explanation
        text_explanation = text_explainer.explain_detection(
            features, prediction, model_verdicts
        )
        
        # Create audit record
        audit_trail.record_explanation(
            'detection',
            detection_id,
            {
                'features': features,
                'prediction': prediction,
                'shap_values': shap_explanation.get('feature_importance'),
                'text_explanation': text_explanation
            }
        )
        
        explanation = {
            'detection_id': detection_id,
            'timestamp': datetime.utcnow().isoformat(),
            'summary': text_explanation.get('summary'),
            'detailed_explanation': text_explanation.get('detailed'),
            'feature_contributions': shap_explanation.get('feature_importance', []),
            'top_factors': shap_explanation.get('top_factors', []),
            'model_contributions': _explain_model_verdicts(model_verdicts),
            'confidence_breakdown': _get_confidence_breakdown(prediction),
            'provenance': {
                'models_used': list(model_verdicts.keys()),
                'explanation_method': 'SHAP + NLG'
            }
        }
        
        return jsonify(explanation), 200
    
    except Exception as e:
        logger.error(f"Detection explanation error: {e}")
        return jsonify({'error': 'Failed to generate explanation'}), 500


@app.route('/api/v1/explain/policy', methods=['POST'])
@require_auth
def explain_policy_decision():
    """
    Explain a DRL policy decision.
    
    Request body:
    {
        "decision_id": "drl_12345",
        "action": "DENY",
        "state_features": {...},
        "confidence": 0.92
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body required'}), 400
        
        decision_id = data.get('decision_id', 'unknown')
        action = data.get('action', 'MONITOR')
        state_features = data.get('state_features', {})
        confidence = data.get('confidence', 0.0)
        
        # Generate policy explanation
        text_explanation = text_explainer.explain_policy_decision(
            action, state_features, confidence
        )
        
        # Generate feature importance for policy
        feature_importance = _calculate_policy_feature_importance(state_features, action)
        
        # Audit trail
        audit_trail.record_explanation(
            'policy',
            decision_id,
            {
                'action': action,
                'state_features': state_features,
                'confidence': confidence,
                'text_explanation': text_explanation
            }
        )
        
        explanation = {
            'decision_id': decision_id,
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'summary': text_explanation.get('summary'),
            'reasoning': text_explanation.get('reasoning'),
            'key_factors': feature_importance[:5],
            'confidence': confidence,
            'alternative_actions': _get_alternative_actions(action, state_features),
            'recommendation_basis': text_explanation.get('basis')
        }
        
        return jsonify(explanation), 200
    
    except Exception as e:
        logger.error(f"Policy explanation error: {e}")
        return jsonify({'error': 'Failed to generate explanation'}), 500


@app.route('/api/v1/audit-trail', methods=['GET'])
@require_auth
def get_audit_trail():
    """Get decision audit trail."""
    try:
        entity_type = request.args.get('type')  # detection, policy
        entity_id = request.args.get('id')
        limit = int(request.args.get('limit', 100))
        
        if entity_id:
            trail = audit_trail.get_trail(entity_type, entity_id)
        else:
            trail = audit_trail.get_recent_trails(entity_type, limit)
        
        return jsonify({
            'trails': trail,
            'total': len(trail)
        }), 200
    
    except Exception as e:
        logger.error(f"Audit trail error: {e}")
        return jsonify({'error': 'Failed to retrieve audit trail'}), 500


@app.route('/api/v1/report/compliance', methods=['POST'])
@require_auth
def generate_compliance_report():
    """
    Generate compliance-ready explanation report.
    
    Request body:
    {
        "detection_ids": ["det_1", "det_2"],
        "decision_ids": ["drl_1"],
        "framework": "GDPR",
        "date_range": {...}
    }
    """
    try:
        data = request.get_json()
        
        detection_ids = data.get('detection_ids', [])
        decision_ids = data.get('decision_ids', [])
        framework = data.get('framework', 'general')
        
        # Get explanations for all IDs
        explanations = []
        
        for det_id in detection_ids:
            trail = audit_trail.get_trail('detection', det_id)
            if trail:
                explanations.extend(trail)
        
        for dec_id in decision_ids:
            trail = audit_trail.get_trail('policy', dec_id)
            if trail:
                explanations.extend(trail)
        
        # Generate report
        report = compliance_reporter.generate(
            explanations,
            framework=framework,
            date_range=data.get('date_range')
        )
        
        return jsonify(report), 200
    
    except Exception as e:
        logger.error(f"Compliance report error: {e}")
        return jsonify({'error': 'Failed to generate report'}), 500


@app.route('/api/v1/statistics', methods=['GET'])
@require_auth
def get_statistics():
    """Get XAI service statistics."""
    try:
        stats = audit_trail.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Statistics error: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500


def _explain_model_verdicts(verdicts: Dict) -> List[Dict]:
    """Generate explanation for each model's verdict."""
    contributions = []
    
    for model, verdict in verdicts.items():
        is_threat = verdict.get('is_threat', False)
        confidence = verdict.get('confidence', 0.0)
        
        contribution = {
            'model': model,
            'verdict': 'threat' if is_threat else 'benign',
            'confidence': confidence,
            'contribution': 'positive' if is_threat else 'negative',
            'weight': _get_model_weight(model)
        }
        contributions.append(contribution)
    
    return contributions


def _get_model_weight(model: str) -> float:
    """Get model weight in ensemble."""
    weights = {
        'xgboost': 0.35,
        'lstm': 0.25,
        'isolation_forest': 0.20,
        'autoencoder': 0.20
    }
    return weights.get(model.lower(), 0.25)


def _get_confidence_breakdown(prediction: Dict) -> Dict:
    """Break down confidence score."""
    confidence = prediction.get('confidence', 0.0)
    
    return {
        'overall': confidence,
        'interpretation': _interpret_confidence(confidence),
        'threshold_comparison': {
            'high_confidence': confidence >= 0.9,
            'medium_confidence': 0.7 <= confidence < 0.9,
            'low_confidence': confidence < 0.7
        }
    }


def _interpret_confidence(confidence: float) -> str:
    """Interpret confidence score."""
    if confidence >= 0.95:
        return "Very high confidence - strong evidence of threat"
    elif confidence >= 0.85:
        return "High confidence - significant threat indicators"
    elif confidence >= 0.70:
        return "Moderate confidence - some suspicious patterns"
    elif confidence >= 0.50:
        return "Low confidence - weak threat signals"
    else:
        return "Very low confidence - likely benign"


def _calculate_policy_feature_importance(features: Dict, action: str) -> List[Dict]:
    """Calculate feature importance for policy decision."""
    importance = []
    
    # Weighted importance for different features
    weights = {
        'threat_score': 0.3,
        'asset_criticality': 0.2,
        'src_reputation': 0.15,
        'time_risk': 0.1,
        'geo_risk': 0.1,
        'historical_alert_count': 0.1,
        'protocol_risk': 0.05
    }
    
    for feature, weight in weights.items():
        value = features.get(feature, 0)
        
        # Normalize contribution
        if isinstance(value, (int, float)):
            contribution = value * weight
        else:
            contribution = 0
        
        importance.append({
            'feature': feature,
            'value': value,
            'weight': weight,
            'contribution': contribution,
            'direction': 'supports_action' if contribution > 0.1 else 'neutral'
        })
    
    # Sort by contribution
    importance.sort(key=lambda x: x['contribution'], reverse=True)
    return importance


def _get_alternative_actions(action: str, features: Dict) -> List[Dict]:
    """Suggest alternative actions with reasoning."""
    alternatives = []
    
    threat_score = features.get('threat_score', 0.5)
    
    if action == 'DENY':
        alternatives.append({
            'action': 'RATE_LIMIT',
            'reason': 'Less disruptive mitigation if false positive risk is high',
            'confidence_threshold': 0.75
        })
        alternatives.append({
            'action': 'MONITOR',
            'reason': 'Gather more evidence before blocking',
            'confidence_threshold': 0.6
        })
    
    elif action == 'ALLOW':
        if threat_score > 0.3:
            alternatives.append({
                'action': 'MONITOR',
                'reason': 'Elevated threat score warrants observation',
                'confidence_threshold': 0.4
            })
    
    elif action == 'MONITOR':
        if threat_score > 0.7:
            alternatives.append({
                'action': 'RATE_LIMIT',
                'reason': 'High threat score suggests mitigation needed',
                'confidence_threshold': 0.7
            })
    
    return alternatives


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5006)),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
