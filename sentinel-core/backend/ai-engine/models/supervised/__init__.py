"""Supervised learning models for known threat detection."""

from .xgboost_detector import XGBoostDetector
from .lstm_sequence import LSTMSequenceDetector

__all__ = ['XGBoostDetector', 'LSTMSequenceDetector']
