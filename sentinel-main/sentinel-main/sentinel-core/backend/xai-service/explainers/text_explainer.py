"""
Natural language explanation generator.
"""
import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class TextExplainer:
    """
    Generate natural language explanations for decisions.
    """
    
    # Explanation templates
    DETECTION_TEMPLATES = {
        'high_threat': (
            "The system detected a {threat_type} threat with {confidence:.0%} confidence. "
            "Key factors include {top_factors}. "
            "The {primary_model} model was the primary contributor to this detection."
        ),
        'medium_threat': (
            "Suspicious activity detected with {confidence:.0%} confidence. "
            "Notable indicators: {top_factors}. "
            "Further monitoring is recommended."
        ),
        'low_threat': (
            "Low-level anomaly detected ({confidence:.0%} confidence). "
            "Minor deviations observed in {top_factors}. "
            "This may be normal variation in traffic patterns."
        )
    }
    
    POLICY_TEMPLATES = {
        'DENY': (
            "Traffic blocked from {source} due to {reason}. "
            "Threat confidence: {confidence:.0%}. Key factors: {factors}."
        ),
        'RATE_LIMIT': (
            "Rate limiting applied to traffic from {source}. "
            "This balances security ({confidence:.0%} threat confidence) with availability."
        ),
        'QUARANTINE': (
            "Source {source} quarantined for {duration}. "
            "High-risk indicators detected: {factors}."
        ),
        'ALLOW': (
            "Traffic allowed based on low threat assessment ({confidence:.0%}). "
            "No significant risk indicators detected."
        ),
        'MONITOR': (
            "Enhanced monitoring enabled for {source}. "
            "Gathering additional evidence before taking action."
        )
    }
    
    def explain_detection(self, features: Dict, prediction: Dict,
                         model_verdicts: Dict) -> Dict[str, Any]:
        """Generate text explanation for detection."""
        confidence = prediction.get('confidence', 0.5)
        is_threat = prediction.get('is_threat', False)
        threat_type = prediction.get('threat_type', 'unknown')
        
        # Determine threat level
        if confidence >= 0.8 and is_threat:
            level = 'high_threat'
        elif confidence >= 0.5 and is_threat:
            level = 'medium_threat'
        else:
            level = 'low_threat'
        
        # Get top factors
        top_factors = self._get_top_factors(features)
        
        # Get primary model
        primary_model = self._get_primary_model(model_verdicts)
        
        # Generate summary
        template = self.DETECTION_TEMPLATES[level]
        summary = template.format(
            threat_type=threat_type,
            confidence=confidence,
            top_factors=', '.join(top_factors),
            primary_model=primary_model
        )
        
        # Generate detailed explanation
        detailed = self._generate_detailed_detection_explanation(
            features, prediction, model_verdicts
        )
        
        return {
            'summary': summary,
            'detailed': detailed,
            'threat_level': level,
            'key_factors': top_factors
        }
    
    def explain_policy_decision(self, action: str, state_features: Dict,
                               confidence: float) -> Dict[str, Any]:
        """Generate text explanation for policy decision."""
        source = state_features.get('source_ip', 'unknown source')
        
        # Get key factors
        factors = self._get_policy_factors(state_features)
        
        # Determine reason
        reason = self._determine_policy_reason(action, state_features)
        
        # Generate summary
        template = self.POLICY_TEMPLATES.get(action, self.POLICY_TEMPLATES['MONITOR'])
        
        summary = template.format(
            source=source,
            reason=reason,
            confidence=confidence,
            factors=', '.join(factors),
            duration='1 hour' if action == 'QUARANTINE' else ''
        )
        
        # Generate reasoning
        reasoning = self._generate_policy_reasoning(action, state_features, confidence)
        
        # Generate basis
        basis = self._generate_decision_basis(action, state_features)
        
        return {
            'summary': summary,
            'reasoning': reasoning,
            'basis': basis,
            'action': action
        }
    
    def _get_top_factors(self, features: Dict, n: int = 3) -> List[str]:
        """Extract top contributing factors."""
        factors = []
        
        # Flatten and analyze features
        for category, values in features.items():
            if isinstance(values, dict):
                for k, v in values.items():
                    if isinstance(v, (int, float)) and v > 0.5:
                        factors.append(f"elevated {k.replace('_', ' ')}")
            elif isinstance(values, (int, float)) and values > 0.5:
                factors.append(f"high {category.replace('_', ' ')}")
        
        return factors[:n] if factors else ['no significant factors']
    
    def _get_primary_model(self, verdicts: Dict) -> str:
        """Determine which model was primary contributor."""
        if not verdicts:
            return 'ensemble'
        
        max_confidence = 0
        primary = 'ensemble'
        
        for model, verdict in verdicts.items():
            conf = verdict.get('confidence', 0)
            if verdict.get('is_threat') and conf > max_confidence:
                max_confidence = conf
                primary = model
        
        return primary
    
    def _generate_detailed_detection_explanation(self, features: Dict,
                                                  prediction: Dict,
                                                  verdicts: Dict) -> str:
        """Generate detailed detection explanation."""
        lines = [
            f"Detection Analysis Report",
            f"Generated: {datetime.utcnow().isoformat()}",
            f"",
            f"VERDICT: {'Threat Detected' if prediction.get('is_threat') else 'Benign'}",
            f"Confidence: {prediction.get('confidence', 0):.1%}",
            f"Threat Type: {prediction.get('threat_type', 'unknown')}",
            f"",
            "MODEL CONTRIBUTIONS:"
        ]
        
        for model, verdict in verdicts.items():
            lines.append(f"  - {model}: {'threat' if verdict.get('is_threat') else 'benign'} "
                        f"({verdict.get('confidence', 0):.1%})")
        
        lines.extend([
            "",
            "KEY INDICATORS:",
            self._format_key_indicators(features)
        ])
        
        return '\n'.join(lines)
    
    def _format_key_indicators(self, features: Dict) -> str:
        """Format key indicators from features."""
        indicators = []
        
        for category, values in features.items():
            if isinstance(values, dict):
                for k, v in list(values.items())[:3]:
                    indicators.append(f"  - {k}: {v}")
            else:
                indicators.append(f"  - {category}: {values}")
        
        return '\n'.join(indicators[:10])
    
    def _get_policy_factors(self, features: Dict) -> List[str]:
        """Get factors influencing policy."""
        factors = []
        
        if features.get('threat_score', 0) > 0.7:
            factors.append('high threat score')
        if features.get('asset_criticality', 0) > 0.8:
            factors.append('critical asset targeted')
        if features.get('time_risk', 0) > 0.5:
            factors.append('suspicious timing')
        if features.get('geo_risk', 0) > 0.6:
            factors.append('high-risk geography')
        
        return factors if factors else ['standard risk assessment']
    
    def _determine_policy_reason(self, action: str, features: Dict) -> str:
        """Determine reason for policy action."""
        threat_score = features.get('threat_score', 0)
        
        if action == 'DENY':
            if threat_score > 0.9:
                return 'extremely high threat confidence'
            return 'elevated threat indicators'
        elif action == 'RATE_LIMIT':
            return 'moderate threat with need to maintain availability'
        elif action == 'QUARANTINE':
            return 'severe threat requiring isolation'
        elif action == 'ALLOW':
            return 'low risk assessment'
        else:
            return 'insufficient evidence for action'
    
    def _generate_policy_reasoning(self, action: str, features: Dict,
                                   confidence: float) -> str:
        """Generate reasoning for policy decision."""
        reasoning = []
        
        threat_score = features.get('threat_score', 0)
        asset_crit = features.get('asset_criticality', 0.5)
        
        if action in ['DENY', 'QUARANTINE']:
            reasoning.append(f"High threat score ({threat_score:.1%}) indicates significant risk.")
            if asset_crit > 0.7:
                reasoning.append("Target asset is classified as critical.")
            reasoning.append(f"Action confidence: {confidence:.1%}")
        elif action == 'RATE_LIMIT':
            reasoning.append("Threat level warrants mitigation but not full block.")
            reasoning.append("Rate limiting reduces risk while maintaining availability.")
        elif action == 'ALLOW':
            reasoning.append(f"Low threat score ({threat_score:.1%}) suggests benign traffic.")
            reasoning.append("No significant risk indicators detected.")
        else:
            reasoning.append("Insufficient evidence for definitive action.")
            reasoning.append("Monitoring will gather additional data.")
        
        return ' '.join(reasoning)
    
    def _generate_decision_basis(self, action: str, features: Dict) -> str:
        """Generate the basis for the decision."""
        basis_points = []
        
        # List relevant factors
        for feature, value in features.items():
            if isinstance(value, (int, float)):
                if value > 0.7:
                    basis_points.append(f"High {feature.replace('_', ' ')}: {value:.2f}")
                elif value < 0.3:
                    basis_points.append(f"Low {feature.replace('_', ' ')}: {value:.2f}")
        
        if not basis_points:
            basis_points.append("Standard risk profile - no extreme indicators")
        
        return "Decision based on: " + "; ".join(basis_points[:5])
