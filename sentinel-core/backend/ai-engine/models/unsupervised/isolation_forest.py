"""
Isolation Forest anomaly detector for zero-day threat detection.

Uses ensemble of isolation trees to identify anomalous network traffic
that deviates from normal patterns without requiring labeled data.
"""
import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np
import joblib

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    IsolationForest = None
    StandardScaler = None

from ..base import BaseDetector, ThreatCategory

logger = logging.getLogger(__name__)


class IsolationForestDetector(BaseDetector):
    """
    Isolation Forest-based anomaly detector.
    
    Features:
    - Unsupervised learning - no labeled data required
    - Efficient for high-dimensional data
    - Effective for zero-day attack detection
    - Provides anomaly scores for risk assessment
    """
    
    DEFAULT_PARAMS = {
        'n_estimators': 200,
        'max_samples': 'auto',
        'contamination': 0.1,  # Expected proportion of outliers
        'max_features': 1.0,
        'bootstrap': False,
        'n_jobs': -1,
        'random_state': 42,
        'warm_start': False
    }
    
    def __init__(self, model_path: Optional[str] = None, 
                 contamination: float = 0.1,
                 params: Optional[Dict] = None):
        super().__init__(model_path)
        
        if IsolationForest is None:
            raise ImportError("scikit-learn is required for IsolationForestDetector")
        
        self.params = {**self.DEFAULT_PARAMS, **(params or {})}
        self.params['contamination'] = contamination
        
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._threshold = -0.5  # Decision threshold for anomaly score
        
        # Load or initialize model
        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize default model for immediate use."""
        logger.info("Initializing default Isolation Forest model")
        
        self.model = IsolationForest(**self.params)
        self.scaler = StandardScaler()
        
        # Fit on synthetic normal data for initialization
        np.random.seed(42)
        n_samples = 1000
        n_features = 50
        
        X_normal = np.random.randn(n_samples, n_features)
        
        self.scaler.fit(X_normal)
        X_scaled = self.scaler.transform(X_normal)
        self.model.fit(X_scaled)
        
        self._is_ready = True
        self._version = "1.0.0-default"
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info("Default Isolation Forest model initialized")
    
    def load_model(self) -> bool:
        """Load model from disk."""
        try:
            model_file = os.path.join(self.model_path, 'isolation_forest.joblib')
            scaler_file = os.path.join(self.model_path, 'isolation_forest_scaler.joblib')
            meta_file = os.path.join(self.model_path, 'isolation_forest_meta.json')
            
            if not os.path.exists(model_file):
                logger.warning(f"Model file not found: {model_file}")
                self._initialize_default_model()
                return True
            
            # Load model and scaler
            self.model = joblib.load(model_file)
            
            if os.path.exists(scaler_file):
                self.scaler = joblib.load(scaler_file)
            else:
                self.scaler = StandardScaler()
            
            # Load metadata
            if os.path.exists(meta_file):
                with open(meta_file, 'r') as f:
                    meta = json.load(f)
                    self._version = meta.get('version', '1.0.0')
                    self._last_updated = meta.get('last_updated')
                    self._metrics = meta.get('metrics', {})
                    self._threshold = meta.get('threshold', -0.5)
            
            self._is_ready = True
            logger.info(f"Isolation Forest model loaded from {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load Isolation Forest model: {e}")
            self._initialize_default_model()
            return True
    
    def save_model(self, path: Optional[str] = None) -> bool:
        """Save model to disk."""
        try:
            save_path = path or self.model_path
            os.makedirs(save_path, exist_ok=True)
            
            model_file = os.path.join(save_path, 'isolation_forest.joblib')
            scaler_file = os.path.join(save_path, 'isolation_forest_scaler.joblib')
            meta_file = os.path.join(save_path, 'isolation_forest_meta.json')
            
            # Save model and scaler
            joblib.dump(self.model, model_file)
            if self.scaler:
                joblib.dump(self.scaler, scaler_file)
            
            # Save metadata
            meta = {
                'version': self._version,
                'last_updated': datetime.utcnow().isoformat(),
                'metrics': self._metrics,
                'threshold': self._threshold,
                'params': self.params
            }
            with open(meta_file, 'w') as f:
                json.dump(meta, f, indent=2)
            
            logger.info(f"Isolation Forest model saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save Isolation Forest model: {e}")
            return False
    
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Predict anomaly for a single sample.
        
        Args:
            features: Feature vector
            
        Returns:
            Prediction result with anomaly score
        """
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")
        
        features = self._validate_features(features)
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        try:
            # Scale features
            if self.scaler:
                features = self.scaler.transform(features)
            
            # Get prediction and anomaly score
            prediction = self.model.predict(features)[0]  # -1 for anomaly, 1 for normal
            anomaly_score = self.model.decision_function(features)[0]  # Lower = more anomalous
            
            # Convert to threat detection format
            is_anomaly = prediction == -1
            
            # Normalize anomaly score to confidence (0-1)
            # Score typically ranges from -0.5 (anomaly) to 0.5 (normal)
            confidence = self._score_to_confidence(anomaly_score)
            
            return {
                'detector': 'isolation_forest',
                'is_threat': bool(is_anomaly),
                'confidence': confidence,
                'threat_type': ThreatCategory.UNKNOWN if is_anomaly else ThreatCategory.BENIGN,
                'anomaly_score': float(anomaly_score),
                'details': {
                    'raw_prediction': int(prediction),
                    'threshold': self._threshold,
                    'contamination': self.params['contamination']
                }
            }
            
        except Exception as e:
            logger.error(f"Isolation Forest prediction error: {e}")
            return {
                'detector': 'isolation_forest',
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': ThreatCategory.UNKNOWN,
                'anomaly_score': 0.0,
                'details': {'error': str(e)}
            }
    
    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Predict anomalies for a batch of samples."""
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")
        
        features = self._validate_features(features)
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        try:
            # Scale features
            if self.scaler:
                features = self.scaler.transform(features)
            
            # Batch predictions
            predictions = self.model.predict(features)
            anomaly_scores = self.model.decision_function(features)
            
            results = []
            for pred, score in zip(predictions, anomaly_scores):
                is_anomaly = pred == -1
                confidence = self._score_to_confidence(score)
                
                results.append({
                    'detector': 'isolation_forest',
                    'is_threat': bool(is_anomaly),
                    'confidence': confidence,
                    'threat_type': ThreatCategory.UNKNOWN if is_anomaly else ThreatCategory.BENIGN,
                    'anomaly_score': float(score)
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Isolation Forest batch prediction error: {e}")
            return [{'detector': 'isolation_forest', 'is_threat': False, 
                    'confidence': 0.0, 'threat_type': ThreatCategory.UNKNOWN,
                    'error': str(e)} for _ in range(len(features))]
    
    def train(self, X: np.ndarray, y: np.ndarray = None) -> Dict[str, float]:
        """
        Train/fit the Isolation Forest on normal traffic data.
        
        For unsupervised learning, y is ignored. The model learns
        the distribution of normal traffic.
        
        Args:
            X: Training features (should be mostly normal traffic)
            y: Ignored for unsupervised learning
            
        Returns:
            Training metrics
        """
        logger.info("Training Isolation Forest model...")
        
        X = self._validate_features(X)
        
        # Fit scaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Initialize and fit model
        self.model = IsolationForest(**self.params)
        self.model.fit(X_scaled)
        
        # Calculate metrics on training data
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.decision_function(X_scaled)
        
        n_anomalies = np.sum(predictions == -1)
        anomaly_rate = n_anomalies / len(predictions)
        
        self._metrics = {
            'n_samples': len(X),
            'n_features': X.shape[1],
            'detected_anomalies': int(n_anomalies),
            'anomaly_rate': float(anomaly_rate),
            'mean_anomaly_score': float(np.mean(anomaly_scores)),
            'std_anomaly_score': float(np.std(anomaly_scores))
        }
        
        self._is_ready = True
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info(f"Isolation Forest training complete. Metrics: {self._metrics}")
        return self._metrics
    
    def _score_to_confidence(self, score: float) -> float:
        """
        Convert anomaly score to confidence value (0-1).
        
        Anomaly scores typically range from -0.5 (strong anomaly) to 0.5 (normal).
        """
        # Sigmoid-like transformation
        # Score < 0 -> anomaly, Score > 0 -> normal
        normalized = (score - self._threshold) / 0.5  # Normalize around threshold
        confidence = 1 / (1 + np.exp(-normalized * 3))  # Sigmoid
        
        # Invert for anomaly confidence
        return float(1 - confidence) if score < 0 else float(confidence)
    
    def update_threshold(self, new_threshold: float):
        """Update the decision threshold."""
        self._threshold = new_threshold
        logger.info(f"Isolation Forest threshold updated to {new_threshold}")
