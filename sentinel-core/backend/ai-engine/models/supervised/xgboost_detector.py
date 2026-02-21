"""
XGBoost-based threat detector for known attack patterns.

Trained on CIC-IDS2017 and UNSW-NB15 datasets for multi-class threat classification.
"""
import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np
import joblib

try:
    import xgboost as xgb
except ImportError:
    xgb = None

from ..base import BaseDetector, ThreatCategory

logger = logging.getLogger(__name__)


class XGBoostDetector(BaseDetector):
    """
    XGBoost gradient boosting classifier for threat detection.
    
    Features:
    - Multi-class classification for different attack types
    - Feature importance analysis for explainability
    - Optimized for high throughput inference
    """
    
    # Default XGBoost parameters optimized for network traffic classification
    DEFAULT_PARAMS = {
        'objective': 'multi:softprob',
        'num_class': len(ThreatCategory.all_categories()),
        'max_depth': 8,
        'learning_rate': 0.1,
        'n_estimators': 200,
        'min_child_weight': 1,
        'gamma': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'reg_alpha': 0.1,
        'reg_lambda': 1.0,
        'scale_pos_weight': 1,
        'tree_method': 'hist',  # Fast histogram-based algorithm
        'predictor': 'cpu_predictor',
        'n_jobs': -1,
        'random_state': 42
    }
    
    # Mapping from class index to threat category
    CLASS_MAPPING = {i: cat for i, cat in enumerate(ThreatCategory.all_categories())}
    
    def __init__(self, model_path: Optional[str] = None, params: Optional[Dict] = None):
        super().__init__(model_path)
        
        if xgb is None:
            raise ImportError("XGBoost is required for XGBoostDetector")
        
        self.params = {**self.DEFAULT_PARAMS, **(params or {})}
        self.feature_names: List[str] = []
        self.feature_importance: Dict[str, float] = {}
        self._threshold = 0.5
        
        # Try to load existing model
        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            # Initialize with default model for demo purposes
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize a default model for demonstration."""
        logger.info("Initializing default XGBoost model")
        
        # Create a simple classifier that can be used immediately
        self.model = xgb.XGBClassifier(
            objective='binary:logistic',
            max_depth=6,
            learning_rate=0.1,
            n_estimators=100,
            use_label_encoder=False,
            eval_metric='logloss'
        )
        
        # Train on synthetic data for initialization
        np.random.seed(42)
        n_samples = 1000
        n_features = 50
        
        X_synthetic = np.random.randn(n_samples, n_features)
        y_synthetic = (X_synthetic[:, 0] + X_synthetic[:, 1] > 0).astype(int)
        
        self.model.fit(X_synthetic, y_synthetic)
        self.feature_names = [f"feature_{i}" for i in range(n_features)]
        self._is_ready = True
        self._version = "1.0.0-default"
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info("Default XGBoost model initialized")
    
    def load_model(self) -> bool:
        """Load XGBoost model from disk."""
        try:
            model_file = os.path.join(self.model_path, 'xgboost_model.json')
            meta_file = os.path.join(self.model_path, 'xgboost_meta.json')
            
            if not os.path.exists(model_file):
                logger.warning(f"Model file not found: {model_file}")
                self._initialize_default_model()
                return True
            
            # Load model
            self.model = xgb.XGBClassifier()
            self.model.load_model(model_file)
            
            # Load metadata
            if os.path.exists(meta_file):
                with open(meta_file, 'r') as f:
                    meta = json.load(f)
                    self.feature_names = meta.get('feature_names', [])
                    self.feature_importance = meta.get('feature_importance', {})
                    self._version = meta.get('version', '1.0.0')
                    self._last_updated = meta.get('last_updated')
                    self._metrics = meta.get('metrics', {})
            
            self._is_ready = True
            logger.info(f"XGBoost model loaded from {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load XGBoost model: {e}")
            self._initialize_default_model()
            return True
    
    def save_model(self, path: Optional[str] = None) -> bool:
        """Save model to disk."""
        try:
            save_path = path or self.model_path
            os.makedirs(save_path, exist_ok=True)
            
            model_file = os.path.join(save_path, 'xgboost_model.json')
            meta_file = os.path.join(save_path, 'xgboost_meta.json')
            
            # Save model
            self.model.save_model(model_file)
            
            # Save metadata
            meta = {
                'feature_names': self.feature_names,
                'feature_importance': self.feature_importance,
                'version': self._version,
                'last_updated': datetime.utcnow().isoformat(),
                'metrics': self._metrics
            }
            with open(meta_file, 'w') as f:
                json.dump(meta, f, indent=2)
            
            logger.info(f"XGBoost model saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save XGBoost model: {e}")
            return False
    
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Predict threat for a single sample.
        
        Args:
            features: Feature vector (1D array)
            
        Returns:
            Prediction result dict
        """
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")
        
        features = self._validate_features(features)
        
        # Ensure 2D input
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Get prediction probabilities
        try:
            proba = self.model.predict_proba(features)[0]
            predicted_class = np.argmax(proba)
            confidence = float(proba[predicted_class])
            
            # Binary threat detection
            is_threat = predicted_class != 0  # Class 0 is benign
            threat_proba = 1.0 - proba[0] if len(proba) > 1 else proba[1]
            
            return {
                'detector': 'xgboost',
                'is_threat': bool(is_threat),
                'confidence': float(threat_proba) if is_threat else float(1 - threat_proba),
                'threat_type': self.CLASS_MAPPING.get(predicted_class, ThreatCategory.UNKNOWN),
                'class_probabilities': {
                    self.CLASS_MAPPING.get(i, f'class_{i}'): float(p) 
                    for i, p in enumerate(proba)
                },
                'details': {
                    'predicted_class': int(predicted_class),
                    'max_probability': float(confidence)
                }
            }
            
        except Exception as e:
            logger.error(f"XGBoost prediction error: {e}")
            # Return default prediction on error
            return {
                'detector': 'xgboost',
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': ThreatCategory.UNKNOWN,
                'class_probabilities': {},
                'details': {'error': str(e)}
            }
    
    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Predict threats for a batch of samples."""
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")
        
        features = self._validate_features(features)
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        results = []
        try:
            probas = self.model.predict_proba(features)
            
            for proba in probas:
                predicted_class = np.argmax(proba)
                confidence = float(proba[predicted_class])
                is_threat = predicted_class != 0
                threat_proba = 1.0 - proba[0] if len(proba) > 1 else proba[1]
                
                results.append({
                    'detector': 'xgboost',
                    'is_threat': bool(is_threat),
                    'confidence': float(threat_proba) if is_threat else float(1 - threat_proba),
                    'threat_type': self.CLASS_MAPPING.get(predicted_class, ThreatCategory.UNKNOWN),
                    'class_probabilities': {
                        self.CLASS_MAPPING.get(i, f'class_{i}'): float(p)
                        for i, p in enumerate(proba)
                    }
                })
                
        except Exception as e:
            logger.error(f"XGBoost batch prediction error: {e}")
            results = [{'detector': 'xgboost', 'is_threat': False, 'confidence': 0.0, 
                       'threat_type': ThreatCategory.UNKNOWN, 'error': str(e)}
                      for _ in range(len(features))]
        
        return results
    
    def train(self, X: np.ndarray, y: np.ndarray, 
              feature_names: Optional[List[str]] = None,
              eval_set: Optional[tuple] = None) -> Dict[str, float]:
        """
        Train the XGBoost model.
        
        Args:
            X: Training features
            y: Training labels
            feature_names: Optional feature names
            eval_set: Optional (X_val, y_val) for early stopping
            
        Returns:
            Training metrics
        """
        logger.info("Training XGBoost model...")
        
        X = self._validate_features(X)
        
        if feature_names:
            self.feature_names = feature_names
        
        # Initialize model with parameters
        self.model = xgb.XGBClassifier(**self.params)
        
        # Training arguments (XGBoost 2.x+ no longer accepts early_stopping_rounds in fit())
        fit_params = {}
        if eval_set:
            fit_params['eval_set'] = [eval_set]
            fit_params['verbose'] = False
        
        # Train
        self.model.fit(X, y, **fit_params)
        
        # Calculate feature importance
        if hasattr(self.model, 'feature_importances_'):
            importance = self.model.feature_importances_
            if self.feature_names and len(self.feature_names) == len(importance):
                self.feature_importance = dict(zip(self.feature_names, importance.tolist()))
        
        # Calculate metrics
        y_pred = self.model.predict(X)
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        self._metrics = {
            'accuracy': float(accuracy_score(y, y_pred)),
            'precision': float(precision_score(y, y_pred, average='weighted', zero_division=0)),
            'recall': float(recall_score(y, y_pred, average='weighted', zero_division=0)),
            'f1_score': float(f1_score(y, y_pred, average='weighted', zero_division=0))
        }
        
        self._is_ready = True
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info(f"XGBoost training complete. Metrics: {self._metrics}")
        return self._metrics
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores."""
        return self.feature_importance
