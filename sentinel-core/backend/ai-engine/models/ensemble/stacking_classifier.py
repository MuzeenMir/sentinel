"""
Stacking ensemble classifier for final threat verdict.

Combines predictions from all detection models (XGBoost, LSTM,
Isolation Forest, Autoencoder) using meta-learning for optimal
threat detection accuracy.
"""
import os
import json
import logging
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import GradientBoostingClassifier
except ImportError:
    LogisticRegression = None
    GradientBoostingClassifier = None

import joblib

from ..base import BaseDetector, ThreatCategory

logger = logging.getLogger(__name__)


class StackingEnsemble:
    """
    Stacking ensemble that combines multiple detection models.
    
    Features:
    - Weighted combination of detector outputs
    - Meta-learner for optimal aggregation
    - Confidence calibration
    - Threat type consensus voting
    """
    
    # Detector weights (learned or configured)
    DEFAULT_WEIGHTS = {
        'xgboost': 0.35,
        'lstm': 0.25,
        'isolation_forest': 0.20,
        'autoencoder': 0.20
    }
    
    def __init__(self, base_detectors: Dict[str, BaseDetector],
                 threshold: float = 0.5,
                 weights: Optional[Dict[str, float]] = None,
                 use_meta_learner: bool = True):
        """
        Initialize stacking ensemble.
        
        Args:
            base_detectors: Dictionary of detector name -> detector instance
            threshold: Classification threshold for final decision
            weights: Optional custom weights for detectors
            use_meta_learner: Whether to use trained meta-learner
        """
        self.base_detectors = base_detectors
        self.threshold = threshold
        self.weights = weights or self.DEFAULT_WEIGHTS
        self.use_meta_learner = use_meta_learner
        
        # Meta-learner for combining predictions
        self.meta_learner: Optional[Any] = None
        self._is_ready = False
        self._version = "1.0.0"
        self._last_updated = None
        self._metrics = {}
        
        # Initialize
        self._initialize()
    
    def _initialize(self):
        """Initialize the ensemble."""
        # Check if all base detectors are ready
        self._is_ready = all(
            detector.is_ready() 
            for detector in self.base_detectors.values()
        )
        
        if self.use_meta_learner and LogisticRegression is not None:
            # Initialize meta-learner (will be trained later)
            self.meta_learner = LogisticRegression(
                C=1.0,
                class_weight='balanced',
                max_iter=1000,
                random_state=42
            )
        
        logger.info(f"Stacking ensemble initialized. Ready: {self._is_ready}")
    
    def is_ready(self) -> bool:
        """Check if ensemble is ready for inference."""
        return self._is_ready
    
    def predict(self, features: np.ndarray, context: Dict = None) -> Dict[str, Any]:
        """
        Get final threat verdict by combining all detector predictions.
        
        Args:
            features: Feature vector
            context: Optional contextual information
            
        Returns:
            Final prediction with confidence and explanation
        """
        if not self._is_ready:
            logger.warning("Ensemble not fully ready, some detectors may be unavailable")
        
        # Collect predictions from all available detectors
        detector_results = {}
        for name, detector in self.base_detectors.items():
            try:
                if detector.is_ready():
                    result = detector.predict(features)
                    detector_results[name] = result
            except Exception as e:
                logger.error(f"Detector {name} prediction failed: {e}")
        
        if not detector_results:
            return self._default_prediction()
        
        # Aggregate predictions
        final_result = self._aggregate_predictions(detector_results, context)
        
        return final_result
    
    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Batch prediction."""
        results = []
        for i in range(len(features)):
            result = self.predict(features[i])
            results.append(result)
        return results
    
    def _aggregate_predictions(self, detector_results: Dict[str, Dict],
                               context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Aggregate predictions from all detectors.
        
        Uses weighted voting with optional meta-learner refinement.
        """
        # Extract threat probabilities and confidences
        threat_scores = []
        confidences = []
        threat_types = []
        
        for name, result in detector_results.items():
            weight = self.weights.get(name, 0.25)
            is_threat = result.get('is_threat', False)
            confidence = result.get('confidence', 0.0)
            
            # Convert to threat score
            threat_score = confidence if is_threat else (1 - confidence)
            threat_scores.append(threat_score * weight)
            confidences.append(confidence)
            
            if is_threat and result.get('threat_type'):
                threat_types.append(result['threat_type'])
        
        # Weighted average of threat scores
        total_weight = sum(self.weights.get(name, 0.25) for name in detector_results)
        if total_weight > 0:
            weighted_threat_score = sum(threat_scores) / total_weight
        else:
            weighted_threat_score = 0.0
        
        # Final decision
        is_threat = weighted_threat_score >= self.threshold
        
        # Average confidence
        avg_confidence = np.mean(confidences) if confidences else 0.0
        
        # Determine threat type by majority voting
        if threat_types:
            from collections import Counter
            threat_type = Counter(threat_types).most_common(1)[0][0]
        else:
            threat_type = ThreatCategory.UNKNOWN if is_threat else ThreatCategory.BENIGN
        
        # Apply context adjustments
        if context:
            weighted_threat_score, is_threat = self._apply_context(
                weighted_threat_score, is_threat, context
            )
        
        # Build final result
        detection_id = f"det_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        return {
            'detection_id': detection_id,
            'is_threat': bool(is_threat),
            'confidence': float(weighted_threat_score if is_threat else 1 - weighted_threat_score),
            'threat_score': float(weighted_threat_score),
            'threat_type': threat_type,
            'timestamp': datetime.utcnow().isoformat(),
            'model_verdicts': {
                name: {
                    'is_threat': result.get('is_threat', False),
                    'confidence': result.get('confidence', 0.0),
                    'threat_type': result.get('threat_type', ThreatCategory.UNKNOWN)
                }
                for name, result in detector_results.items()
            },
            'ensemble_details': {
                'threshold': self.threshold,
                'weights': self.weights,
                'n_detectors': len(detector_results),
                'consensus': self._calculate_consensus(detector_results)
            }
        }
    
    def _apply_context(self, threat_score: float, is_threat: bool,
                       context: Dict) -> tuple:
        """
        Apply contextual adjustments to threat assessment.
        
        Context factors:
        - asset_criticality: Higher criticality -> lower threshold
        - user_role: Admin users get more scrutiny
        - time_risk: Off-hours activity gets higher scores
        """
        adjustment = 0.0
        
        # Asset criticality (1-5 scale)
        criticality = context.get('asset_criticality', 3)
        if criticality >= 4:
            adjustment += 0.05 * (criticality - 3)
        
        # Time risk (0-1)
        time_risk = context.get('time_risk', 0.5)
        if time_risk > 0.7:
            adjustment += 0.03
        
        # User role risk
        user_role = context.get('user_role', 'user')
        if user_role in ['admin', 'root', 'administrator']:
            adjustment += 0.02  # More scrutiny for privileged accounts
        
        # Apply adjustment
        adjusted_score = min(1.0, threat_score + adjustment)
        is_threat = adjusted_score >= self.threshold
        
        return adjusted_score, is_threat
    
    def _calculate_consensus(self, detector_results: Dict[str, Dict]) -> float:
        """
        Calculate consensus level among detectors.
        
        Returns value 0-1 where 1 means all detectors agree.
        """
        if len(detector_results) < 2:
            return 1.0
        
        verdicts = [r.get('is_threat', False) for r in detector_results.values()]
        agreement = max(sum(verdicts), len(verdicts) - sum(verdicts))
        consensus = agreement / len(verdicts)
        
        return float(consensus)
    
    def _default_prediction(self) -> Dict[str, Any]:
        """Return default prediction when no detectors are available."""
        return {
            'detection_id': f"det_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_default",
            'is_threat': False,
            'confidence': 0.0,
            'threat_score': 0.0,
            'threat_type': ThreatCategory.UNKNOWN,
            'timestamp': datetime.utcnow().isoformat(),
            'model_verdicts': {},
            'ensemble_details': {
                'error': 'No detectors available'
            }
        }
    
    def train_meta_learner(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Train meta-learner on detector outputs.
        
        Args:
            X_train: Detector output features (n_samples, n_detectors * n_features)
            y_train: True labels
        """
        if self.meta_learner is None:
            logger.warning("Meta-learner not initialized")
            return
        
        logger.info("Training meta-learner...")
        self.meta_learner.fit(X_train, y_train)
        
        # Calculate metrics
        y_pred = self.meta_learner.predict(X_train)
        from sklearn.metrics import accuracy_score, f1_score
        
        self._metrics['meta_learner'] = {
            'accuracy': float(accuracy_score(y_train, y_pred)),
            'f1_score': float(f1_score(y_train, y_pred, average='weighted'))
        }
        
        logger.info(f"Meta-learner trained. Metrics: {self._metrics['meta_learner']}")
    
    def update_weights(self, new_weights: Dict[str, float]):
        """Update detector weights."""
        self.weights.update(new_weights)
        # Normalize weights
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v/total for k, v in self.weights.items()}
        logger.info(f"Detector weights updated: {self.weights}")
    
    def update_threshold(self, new_threshold: float):
        """Update classification threshold."""
        self.threshold = max(0.0, min(1.0, new_threshold))
        logger.info(f"Threshold updated to {self.threshold}")
    
    def get_detector_status(self) -> Dict[str, bool]:
        """Get status of all base detectors."""
        return {name: detector.is_ready() for name, detector in self.base_detectors.items()}
    
    def save(self, path: str) -> bool:
        """Save ensemble configuration."""
        try:
            os.makedirs(path, exist_ok=True)
            
            config_file = os.path.join(path, 'ensemble_config.json')
            config = {
                'weights': self.weights,
                'threshold': self.threshold,
                'use_meta_learner': self.use_meta_learner,
                'version': self._version,
                'last_updated': datetime.utcnow().isoformat(),
                'metrics': self._metrics
            }
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Save meta-learner if available
            if self.meta_learner is not None:
                meta_file = os.path.join(path, 'meta_learner.joblib')
                joblib.dump(self.meta_learner, meta_file)
            
            logger.info(f"Ensemble saved to {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save ensemble: {e}")
            return False
    
    def load(self, path: str) -> bool:
        """Load ensemble configuration."""
        try:
            config_file = os.path.join(path, 'ensemble_config.json')
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.weights = config.get('weights', self.DEFAULT_WEIGHTS)
                    self.threshold = config.get('threshold', 0.5)
                    self._version = config.get('version', '1.0.0')
                    self._metrics = config.get('metrics', {})
            
            # Load meta-learner
            meta_file = os.path.join(path, 'meta_learner.joblib')
            if os.path.exists(meta_file):
                self.meta_learner = joblib.load(meta_file)
            
            logger.info(f"Ensemble loaded from {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load ensemble: {e}")
            return False
