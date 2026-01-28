"""
SENTINEL AI Detection Models

This package contains all ML models for threat detection:
- Supervised: XGBoost, LSTM for known threat patterns
- Unsupervised: Isolation Forest, Autoencoder for anomaly detection
- Ensemble: Stacking classifier for final verdict
"""

from .supervised.xgboost_detector import XGBoostDetector
from .supervised.lstm_sequence import LSTMSequenceDetector
from .unsupervised.isolation_forest import IsolationForestDetector
from .unsupervised.autoencoder import AutoencoderDetector
from .ensemble.stacking_classifier import StackingEnsemble

__all__ = [
    'XGBoostDetector',
    'LSTMSequenceDetector',
    'IsolationForestDetector',
    'AutoencoderDetector',
    'StackingEnsemble'
]
