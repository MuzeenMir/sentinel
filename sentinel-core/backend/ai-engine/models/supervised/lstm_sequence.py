"""
LSTM-based sequence detector for temporal attack patterns.

Analyzes sequences of network events to detect multi-stage attacks
and temporal anomalies that single-event classifiers might miss.
"""
import os
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import numpy as np

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
except ImportError:
    torch = None
    nn = None

from ..base import BaseDetector, ThreatCategory

logger = logging.getLogger(__name__)


class LSTMNetwork(nn.Module):
    """LSTM neural network for sequence classification."""
    
    def __init__(self, input_size: int, hidden_size: int = 128, 
                 num_layers: int = 2, num_classes: int = 2, dropout: float = 0.3):
        super().__init__()
        
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True
        )
        
        self.attention = nn.MultiheadAttention(
            embed_dim=hidden_size * 2,  # Bidirectional
            num_heads=4,
            dropout=dropout,
            batch_first=True
        )
        
        self.fc = nn.Sequential(
            nn.Linear(hidden_size * 2, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, num_classes)
        )
        
        self.softmax = nn.Softmax(dim=1)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: Input tensor of shape (batch, seq_len, input_size)
            
        Returns:
            logits: Raw predictions
            probabilities: Softmax probabilities
        """
        # LSTM forward
        lstm_out, _ = self.lstm(x)  # (batch, seq_len, hidden*2)
        
        # Self-attention
        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)
        
        # Global average pooling over sequence
        pooled = torch.mean(attn_out, dim=1)  # (batch, hidden*2)
        
        # Classification
        logits = self.fc(pooled)
        probabilities = self.softmax(logits)
        
        return logits, probabilities


class LSTMSequenceDetector(BaseDetector):
    """
    LSTM-based detector for sequential/temporal attack patterns.
    
    Features:
    - Bidirectional LSTM for capturing temporal dependencies
    - Attention mechanism for focusing on relevant events
    - Multi-stage attack detection
    """
    
    DEFAULT_CONFIG = {
        'input_size': 50,
        'hidden_size': 128,
        'num_layers': 2,
        'num_classes': 2,
        'dropout': 0.3,
        'sequence_length': 20,
        'learning_rate': 0.001,
        'batch_size': 64,
        'epochs': 50
    }
    
    def __init__(self, model_path: Optional[str] = None, config: Optional[Dict] = None):
        super().__init__(model_path)
        
        if torch is None:
            raise ImportError("PyTorch is required for LSTMSequenceDetector")
        
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model: Optional[LSTMNetwork] = None
        self._threshold = 0.5
        
        # Try to load existing model
        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize default model architecture."""
        logger.info("Initializing default LSTM model")
        
        self.model = LSTMNetwork(
            input_size=self.config['input_size'],
            hidden_size=self.config['hidden_size'],
            num_layers=self.config['num_layers'],
            num_classes=self.config['num_classes'],
            dropout=self.config['dropout']
        ).to(self.device)
        
        self._is_ready = True
        self._version = "1.0.0-default"
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info(f"LSTM model initialized on {self.device}")
    
    def load_model(self) -> bool:
        """Load LSTM model from disk."""
        try:
            model_file = os.path.join(self.model_path, 'lstm_model.pt')
            config_file = os.path.join(self.model_path, 'lstm_config.json')
            
            if not os.path.exists(model_file):
                logger.warning(f"Model file not found: {model_file}")
                self._initialize_default_model()
                return True
            
            # Load config
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config.get('model_config', {}))
                    self._version = saved_config.get('version', '1.0.0')
                    self._last_updated = saved_config.get('last_updated')
                    self._metrics = saved_config.get('metrics', {})
            
            # Initialize model architecture
            self.model = LSTMNetwork(
                input_size=self.config['input_size'],
                hidden_size=self.config['hidden_size'],
                num_layers=self.config['num_layers'],
                num_classes=self.config['num_classes'],
                dropout=self.config['dropout']
            ).to(self.device)
            
            # Load weights
            self.model.load_state_dict(torch.load(model_file, map_location=self.device))
            self.model.eval()
            
            self._is_ready = True
            logger.info(f"LSTM model loaded from {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load LSTM model: {e}")
            self._initialize_default_model()
            return True
    
    def save_model(self, path: Optional[str] = None) -> bool:
        """Save model to disk."""
        try:
            save_path = path or self.model_path
            os.makedirs(save_path, exist_ok=True)
            
            model_file = os.path.join(save_path, 'lstm_model.pt')
            config_file = os.path.join(save_path, 'lstm_config.json')
            
            # Save model weights
            torch.save(self.model.state_dict(), model_file)
            
            # Save config
            config_data = {
                'model_config': self.config,
                'version': self._version,
                'last_updated': datetime.utcnow().isoformat(),
                'metrics': self._metrics
            }
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"LSTM model saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save LSTM model: {e}")
            return False
    
    def _prepare_sequence(self, features: np.ndarray) -> torch.Tensor:
        """Prepare feature sequence for LSTM input."""
        features = self._validate_features(features)
        
        # Handle different input shapes
        if features.ndim == 1:
            # Single feature vector -> create sequence of 1
            seq_len = self.config['sequence_length']
            # Pad or repeat to create sequence
            features = np.tile(features, (seq_len, 1))
            features = features.reshape(1, seq_len, -1)
        elif features.ndim == 2:
            # Could be (seq_len, features) or (batch, features)
            if features.shape[0] == self.config['sequence_length']:
                # Single sequence
                features = features.reshape(1, *features.shape)
            else:
                # Batch of single vectors, create sequences
                seq_len = self.config['sequence_length']
                features = np.array([np.tile(f, (seq_len, 1)) for f in features])
        
        # Ensure correct input size
        if features.shape[-1] != self.config['input_size']:
            # Pad or truncate features
            if features.shape[-1] < self.config['input_size']:
                pad_width = ((0, 0), (0, 0), (0, self.config['input_size'] - features.shape[-1]))
                features = np.pad(features, pad_width, mode='constant')
            else:
                features = features[..., :self.config['input_size']]
        
        return torch.FloatTensor(features).to(self.device)
    
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Predict threat for a sequence of events.
        
        Args:
            features: Feature array - can be:
                - 1D: Single feature vector
                - 2D: Sequence (seq_len, features)
                
        Returns:
            Prediction result dict
        """
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")
        
        try:
            # Prepare input
            x = self._prepare_sequence(features)
            
            # Inference
            self.model.eval()
            with torch.no_grad():
                logits, proba = self.model(x)
            
            proba = proba.cpu().numpy()[0]
            predicted_class = np.argmax(proba)
            confidence = float(proba[predicted_class])
            
            is_threat = predicted_class == 1
            
            return {
                'detector': 'lstm',
                'is_threat': bool(is_threat),
                'confidence': confidence,
                'threat_type': ThreatCategory.UNKNOWN if is_threat else ThreatCategory.BENIGN,
                'class_probabilities': {
                    'benign': float(proba[0]),
                    'malicious': float(proba[1]) if len(proba) > 1 else 0.0
                },
                'details': {
                    'sequence_length': x.shape[1],
                    'device': str(self.device)
                }
            }
            
        except Exception as e:
            logger.error(f"LSTM prediction error: {e}")
            return {
                'detector': 'lstm',
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': ThreatCategory.UNKNOWN,
                'class_probabilities': {},
                'details': {'error': str(e)}
            }
    
    def predict_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Predict threats for a batch of sequences."""
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")
        
        try:
            # Prepare batch input
            x = self._prepare_sequence(features)
            
            # Batch inference
            self.model.eval()
            with torch.no_grad():
                logits, probas = self.model(x)
            
            probas = probas.cpu().numpy()
            results = []
            
            for proba in probas:
                predicted_class = np.argmax(proba)
                confidence = float(proba[predicted_class])
                is_threat = predicted_class == 1
                
                results.append({
                    'detector': 'lstm',
                    'is_threat': bool(is_threat),
                    'confidence': confidence,
                    'threat_type': ThreatCategory.UNKNOWN if is_threat else ThreatCategory.BENIGN,
                    'class_probabilities': {
                        'benign': float(proba[0]),
                        'malicious': float(proba[1]) if len(proba) > 1 else 0.0
                    }
                })
            
            return results
            
        except Exception as e:
            logger.error(f"LSTM batch prediction error: {e}")
            return [{'detector': 'lstm', 'is_threat': False, 'confidence': 0.0,
                    'threat_type': ThreatCategory.UNKNOWN, 'error': str(e)}
                   for _ in range(len(features))]
    
    def train(self, X: np.ndarray, y: np.ndarray,
              X_val: Optional[np.ndarray] = None,
              y_val: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Train the LSTM model.
        
        Args:
            X: Training sequences (n_samples, seq_len, features)
            y: Training labels
            X_val: Validation sequences
            y_val: Validation labels
            
        Returns:
            Training metrics
        """
        logger.info("Training LSTM model...")
        
        # Initialize model
        self._initialize_default_model()
        
        # Keep tensors on CPU and stream mini-batches to device.
        # Moving full sequence tensors to GPU can OOM on large training sets.
        X = self._validate_features(X)
        X_tensor = torch.FloatTensor(X)
        y_tensor = torch.LongTensor(y)
        
        train_dataset = TensorDataset(X_tensor, y_tensor)
        train_loader = DataLoader(
            train_dataset, 
            batch_size=self.config['batch_size'],
            shuffle=True,
            pin_memory=(self.device.type == "cuda"),
        )
        
        # Loss and optimizer
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(
            self.model.parameters(),
            lr=self.config['learning_rate']
        )
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='min', patience=5, factor=0.5
        )
        
        # Training loop
        best_loss = float('inf')
        for epoch in range(self.config['epochs']):
            self.model.train()
            total_loss = 0
            
            for batch_x, batch_y in train_loader:
                batch_x = batch_x.to(self.device, non_blocking=True)
                batch_y = batch_y.to(self.device, non_blocking=True)
                optimizer.zero_grad()
                logits, _ = self.model(batch_x)
                loss = criterion(logits, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            avg_loss = total_loss / len(train_loader)
            scheduler.step(avg_loss)
            
            if avg_loss < best_loss:
                best_loss = avg_loss
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{self.config['epochs']}, Loss: {avg_loss:.4f}")
        
        # Calculate metrics
        self.model.eval()
        eval_loader = DataLoader(
            train_dataset,
            batch_size=self.config['batch_size'],
            shuffle=False,
            pin_memory=(self.device.type == "cuda"),
        )
        preds = []
        with torch.no_grad():
            for batch_x, _ in eval_loader:
                batch_x = batch_x.to(self.device, non_blocking=True)
                _, probas = self.model(batch_x)
                preds.append(probas.argmax(dim=1).cpu().numpy())
        y_pred = np.concatenate(preds) if preds else np.array([], dtype=np.int64)
        
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        self._metrics = {
            'accuracy': float(accuracy_score(y, y_pred)),
            'precision': float(precision_score(y, y_pred, average='weighted', zero_division=0)),
            'recall': float(recall_score(y, y_pred, average='weighted', zero_division=0)),
            'f1_score': float(f1_score(y, y_pred, average='weighted', zero_division=0)),
            'final_loss': float(best_loss)
        }
        
        self._is_ready = True
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info(f"LSTM training complete. Metrics: {self._metrics}")
        return self._metrics
