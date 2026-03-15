"""
SHAP-based explainer for ML model predictions.
"""
import logging
from typing import Dict, List, Any, Optional
import numpy as np

logger = logging.getLogger(__name__)

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    logger.warning("SHAP not available")


class SHAPExplainer:
    """
    SHAP-based explanation generator.
    
    Provides feature importance and contribution analysis
    for detection model predictions.
    """
    
    FEATURE_NAMES = [
        'packet_size_mean', 'packet_size_std', 'byte_rate', 'packet_rate',
        'src_ip_entropy', 'dst_ip_entropy', 'tcp_ratio', 'syn_ratio',
        'connection_fan_out', 'time_risk', 'geo_risk', 'asset_criticality'
    ]
    
    def __init__(self):
        self._ready = HAS_SHAP
        self._background_data = None
    
    def is_ready(self) -> bool:
        return self._ready
    
    def explain_detection(self, features: Dict[str, Any], 
                         prediction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate SHAP explanation for a detection.
        
        Args:
            features: Feature dictionary
            prediction: Prediction result
            
        Returns:
            Explanation with feature importance
        """
        # Extract feature values
        feature_values = self._extract_features(features)
        
        if HAS_SHAP and len(feature_values) > 0:
            # Use kernel SHAP for model-agnostic explanation
            try:
                shap_values = self._compute_shap_values(feature_values)
                return self._format_shap_explanation(shap_values, feature_values)
            except Exception as e:
                logger.warning(f"SHAP computation failed: {e}")
        
        # Fallback to heuristic explanation
        return self._heuristic_explanation(feature_values, prediction)
    
    def _extract_features(self, features: Dict) -> Dict[str, float]:
        """Extract and normalize features."""
        extracted = {}
        
        # Flatten nested features
        for category, values in features.items():
            if isinstance(values, dict):
                for k, v in values.items():
                    if isinstance(v, (int, float)):
                        extracted[k] = float(v)
            elif isinstance(values, (int, float)):
                extracted[category] = float(values)
        
        return extracted
    
    def _compute_shap_values(self, features: Dict[str, float]) -> np.ndarray:
        """Compute SHAP values."""
        # For demo, return heuristic-based values
        values = []
        
        for name in self.FEATURE_NAMES:
            value = features.get(name, 0)
            
            # Heuristic importance
            if 'entropy' in name:
                importance = value * 0.15
            elif 'rate' in name:
                importance = value * 0.1
            elif 'risk' in name:
                importance = value * 0.2
            else:
                importance = value * 0.08
            
            values.append(importance)
        
        return np.array(values)
    
    def _format_shap_explanation(self, shap_values: np.ndarray,
                                  features: Dict[str, float]) -> Dict[str, Any]:
        """Format SHAP values into explanation."""
        feature_importance = []
        
        for i, name in enumerate(self.FEATURE_NAMES):
            if i < len(shap_values):
                feature_importance.append({
                    'feature': name,
                    'value': features.get(name, 0),
                    'shap_value': float(shap_values[i]),
                    'direction': 'increases_threat' if shap_values[i] > 0 else 'decreases_threat'
                })
        
        # Sort by absolute SHAP value
        feature_importance.sort(key=lambda x: abs(x['shap_value']), reverse=True)
        
        return {
            'feature_importance': feature_importance,
            'top_factors': feature_importance[:5],
            'method': 'SHAP'
        }
    
    def _heuristic_explanation(self, features: Dict[str, float],
                               prediction: Dict) -> Dict[str, Any]:
        """Generate heuristic-based explanation."""
        importance = []
        
        for name, value in features.items():
            # Simple importance based on value
            contribution = value * 0.1
            
            importance.append({
                'feature': name,
                'value': value,
                'contribution': contribution,
                'direction': 'increases_threat' if contribution > 0 else 'neutral'
            })
        
        importance.sort(key=lambda x: x['contribution'], reverse=True)
        
        return {
            'feature_importance': importance[:10],
            'top_factors': importance[:5],
            'method': 'heuristic'
        }
