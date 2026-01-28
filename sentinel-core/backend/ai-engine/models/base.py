"""
Base detector class for all SENTINEL detection models.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np
import logging

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """
    Abstract base class for all threat detection models.
    
    All detectors must implement:
    - predict(): Single sample prediction
    - predict_batch(): Batch prediction
    - is_ready(): Check if model is loaded and ready
    - get_version(): Get model version
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.model = None
        self._is_ready = False
        self._version = "1.0.0"
        self._last_updated = None
        self._metrics = {}
        
    @abstractmethod
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Predict threat probability for a single sample.
        
        Args:
            features: Feature vector as numpy array
            
        Returns:
            Dict with keys:
                - is_threat: bool
                - confidence: float (0-1)
                - threat_type: str
                - details: dict
        """
        pass
    
    @abstractmethod
    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """
        Predict threat probability for a batch of samples.
        
        Args:
            features: Feature matrix as numpy array (n_samples, n_features)
            
        Returns:
            List of prediction dicts
        """
        pass
    
    @abstractmethod
    def load_model(self) -> bool:
        """
        Load the model from disk.
        
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """
        Train the model on labeled data.
        
        Args:
            X: Feature matrix
            y: Labels (0 for benign, 1 for malicious)
            
        Returns:
            Training metrics dict
        """
        pass
    
    def is_ready(self) -> bool:
        """Check if model is ready for inference."""
        return self._is_ready
    
    def get_version(self) -> str:
        """Get model version."""
        return self._version
    
    def get_last_updated(self) -> Optional[str]:
        """Get last update timestamp."""
        return self._last_updated
    
    def get_metrics(self) -> Dict[str, float]:
        """Get model performance metrics."""
        return self._metrics
    
    def _validate_features(self, features: np.ndarray) -> np.ndarray:
        """Validate and preprocess features."""
        if features is None:
            raise ValueError("Features cannot be None")
        
        features = np.asarray(features)
        
        # Handle NaN and Inf values
        if np.any(np.isnan(features)):
            logger.warning("NaN values detected in features, replacing with 0")
            features = np.nan_to_num(features, nan=0.0)
        
        if np.any(np.isinf(features)):
            logger.warning("Inf values detected in features, replacing with max float")
            features = np.nan_to_num(features, posinf=1e10, neginf=-1e10)
        
        return features


class ThreatCategory:
    """Enum-like class for threat categories."""
    BENIGN = "benign"
    MALWARE = "malware"
    DOS_ATTACK = "dos_attack"
    DDOS_ATTACK = "ddos_attack"
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    RANSOMWARE = "ransomware"
    UNKNOWN = "unknown"
    
    @classmethod
    def all_categories(cls) -> List[str]:
        """Get all threat categories."""
        return [
            cls.BENIGN, cls.MALWARE, cls.DOS_ATTACK, cls.DDOS_ATTACK,
            cls.BRUTE_FORCE, cls.PORT_SCAN, cls.SQL_INJECTION, cls.XSS,
            cls.DATA_EXFILTRATION, cls.LATERAL_MOVEMENT, cls.C2_COMMUNICATION,
            cls.RANSOMWARE, cls.UNKNOWN
        ]
