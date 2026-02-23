"""
Autoencoder-based anomaly detector using reconstruction error.

Neural network autoencoder trained on normal traffic learns to
reconstruct normal patterns. High reconstruction error indicates anomalies.
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


class AutoencoderNetwork(nn.Module):
    """Deep autoencoder for reconstruction-based anomaly detection."""
    
    def __init__(self, input_dim: int, latent_dim: int = 32, 
                 hidden_dims: List[int] = None):
        super().__init__()
        
        if hidden_dims is None:
            hidden_dims = [128, 64]
        
        # Build encoder
        encoder_layers = []
        prev_dim = input_dim
        for dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, dim),
                nn.BatchNorm1d(dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = dim
        encoder_layers.append(nn.Linear(prev_dim, latent_dim))
        self.encoder = nn.Sequential(*encoder_layers)
        
        # Build decoder (mirror of encoder)
        decoder_layers = []
        prev_dim = latent_dim
        for dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, dim),
                nn.BatchNorm1d(dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = dim
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass through autoencoder.
        
        Returns:
            encoded: Latent representation
            decoded: Reconstructed input
        """
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return encoded, decoded
    
    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Encode input to latent space."""
        return self.encoder(x)
    
    def decode(self, z: torch.Tensor) -> torch.Tensor:
        """Decode latent representation."""
        return self.decoder(z)


class AutoencoderDetector(BaseDetector):
    """
    Autoencoder-based anomaly detector.
    
    Features:
    - Learns compact representation of normal traffic
    - Detects anomalies via reconstruction error
    - Provides interpretable anomaly scores
    - Can identify which features contribute to anomaly
    """
    
    DEFAULT_CONFIG = {
        'input_dim': 50,
        'latent_dim': 16,
        'hidden_dims': [128, 64, 32],
        'learning_rate': 0.001,
        'batch_size': 64,
        'epochs': 100,
        'early_stopping_patience': 10
    }
    
    def __init__(self, model_path: Optional[str] = None, config: Optional[Dict] = None):
        super().__init__(model_path)
        
        if torch is None:
            raise ImportError("PyTorch is required for AutoencoderDetector")
        
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model: Optional[AutoencoderNetwork] = None
        
        # Reconstruction error threshold (learned during training)
        self._threshold = 0.1
        self._mean_error = 0.0
        self._std_error = 0.1
        
        # Feature statistics for normalization
        self._feature_mean: Optional[np.ndarray] = None
        self._feature_std: Optional[np.ndarray] = None
        
        # Load or initialize model
        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize default model architecture."""
        logger.info("Initializing default Autoencoder model")
        
        self.model = AutoencoderNetwork(
            input_dim=self.config['input_dim'],
            latent_dim=self.config['latent_dim'],
            hidden_dims=self.config['hidden_dims']
        ).to(self.device)
        
        # Initialize feature statistics
        self._feature_mean = np.zeros(self.config['input_dim'])
        self._feature_std = np.ones(self.config['input_dim'])
        
        self._is_ready = True
        self._version = "1.0.0-default"
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info(f"Autoencoder model initialized on {self.device}")
    
    def load_model(self) -> bool:
        """Load model from disk."""
        try:
            model_file = os.path.join(self.model_path, 'autoencoder.pt')
            config_file = os.path.join(self.model_path, 'autoencoder_config.json')
            
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
                    self._threshold = saved_config.get('threshold', 0.1)
                    self._mean_error = saved_config.get('mean_error', 0.0)
                    self._std_error = saved_config.get('std_error', 0.1)
                    self._feature_mean = np.array(saved_config.get('feature_mean', []))
                    self._feature_std = np.array(saved_config.get('feature_std', []))
            
            # Initialize model architecture
            self.model = AutoencoderNetwork(
                input_dim=self.config['input_dim'],
                latent_dim=self.config['latent_dim'],
                hidden_dims=self.config['hidden_dims']
            ).to(self.device)
            
            # Load weights
            self.model.load_state_dict(torch.load(model_file, map_location=self.device))
            self.model.eval()
            
            self._is_ready = True
            logger.info(f"Autoencoder model loaded from {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load Autoencoder model: {e}")
            self._initialize_default_model()
            return True
    
    def save_model(self, path: Optional[str] = None) -> bool:
        """Save model to disk."""
        try:
            save_path = path or self.model_path
            os.makedirs(save_path, exist_ok=True)
            
            model_file = os.path.join(save_path, 'autoencoder.pt')
            config_file = os.path.join(save_path, 'autoencoder_config.json')
            
            # Save model weights
            torch.save(self.model.state_dict(), model_file)
            
            # Save config and statistics
            config_data = {
                'model_config': self.config,
                'version': self._version,
                'last_updated': datetime.utcnow().isoformat(),
                'metrics': self._metrics,
                'threshold': self._threshold,
                'mean_error': self._mean_error,
                'std_error': self._std_error,
                'feature_mean': self._feature_mean.tolist() if self._feature_mean is not None else [],
                'feature_std': self._feature_std.tolist() if self._feature_std is not None else []
            }
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Autoencoder model saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save Autoencoder model: {e}")
            return False
    
    def _normalize_features(self, features: np.ndarray) -> np.ndarray:
        """Normalize features using learned statistics."""
        if self._feature_mean is not None and self._feature_std is not None:
            # Avoid division by zero
            std = np.where(self._feature_std == 0, 1, self._feature_std)
            return (features - self._feature_mean) / std
        return features
    
    def _calculate_reconstruction_error(self, original: torch.Tensor, 
                                        reconstructed: torch.Tensor) -> torch.Tensor:
        """Calculate per-sample reconstruction error."""
        # Mean squared error per sample
        mse = torch.mean((original - reconstructed) ** 2, dim=1)
        return mse
    
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Predict anomaly based on reconstruction error.
        
        Args:
            features: Feature vector
            
        Returns:
            Prediction result with reconstruction error
        """
        if not self._is_ready:
            raise RuntimeError("Model not ready for inference")
        
        features = self._validate_features(features)
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        try:
            # Ensure correct input dimension
            if features.shape[-1] != self.config['input_dim']:
                if features.shape[-1] < self.config['input_dim']:
                    features = np.pad(features, ((0, 0), (0, self.config['input_dim'] - features.shape[-1])))
                else:
                    features = features[:, :self.config['input_dim']]
            
            # Normalize
            features_norm = self._normalize_features(features)
            
            # Convert to tensor
            x = torch.FloatTensor(features_norm).to(self.device)
            
            # Inference
            self.model.eval()
            with torch.no_grad():
                _, reconstructed = self.model(x)
                recon_error = self._calculate_reconstruction_error(x, reconstructed)
            
            error = float(recon_error.cpu().numpy()[0])
            
            # Calculate z-score for anomaly detection
            z_score = (error - self._mean_error) / max(self._std_error, 1e-6)
            
            # Anomaly if error exceeds threshold (typically mean + 2*std)
            is_anomaly = error > self._threshold
            
            # Convert to confidence
            confidence = self._error_to_confidence(error)
            
            # Calculate feature-wise reconstruction error for explainability
            feature_errors = (x - reconstructed).abs().cpu().numpy()[0]
            top_features = np.argsort(feature_errors)[-5:][::-1].tolist()
            
            return {
                'detector': 'autoencoder',
                'is_threat': bool(is_anomaly),
                'confidence': confidence,
                'threat_type': ThreatCategory.UNKNOWN if is_anomaly else ThreatCategory.BENIGN,
                'reconstruction_error': error,
                'z_score': float(z_score),
                'details': {
                    'threshold': self._threshold,
                    'mean_error': self._mean_error,
                    'std_error': self._std_error,
                    'top_anomalous_features': top_features
                }
            }
            
        except Exception as e:
            logger.error(f"Autoencoder prediction error: {e}")
            return {
                'detector': 'autoencoder',
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': ThreatCategory.UNKNOWN,
                'reconstruction_error': 0.0,
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
            # Ensure correct input dimension
            if features.shape[-1] != self.config['input_dim']:
                if features.shape[-1] < self.config['input_dim']:
                    features = np.pad(features, ((0, 0), (0, self.config['input_dim'] - features.shape[-1])))
                else:
                    features = features[:, :self.config['input_dim']]
            
            # Normalize
            features_norm = self._normalize_features(features)
            
            # Convert to tensor
            x = torch.FloatTensor(features_norm).to(self.device)
            
            # Batch inference
            self.model.eval()
            with torch.no_grad():
                _, reconstructed = self.model(x)
                recon_errors = self._calculate_reconstruction_error(x, reconstructed)
            
            errors = recon_errors.cpu().numpy()
            
            results = []
            for error in errors:
                is_anomaly = error > self._threshold
                confidence = self._error_to_confidence(error)
                z_score = (error - self._mean_error) / max(self._std_error, 1e-6)
                
                results.append({
                    'detector': 'autoencoder',
                    'is_threat': bool(is_anomaly),
                    'confidence': confidence,
                    'threat_type': ThreatCategory.UNKNOWN if is_anomaly else ThreatCategory.BENIGN,
                    'reconstruction_error': float(error),
                    'z_score': float(z_score)
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Autoencoder batch prediction error: {e}")
            return [{'detector': 'autoencoder', 'is_threat': False,
                    'confidence': 0.0, 'threat_type': ThreatCategory.UNKNOWN,
                    'error': str(e)} for _ in range(len(features))]
    
    def train(self, X: np.ndarray, y: np.ndarray = None,
              X_val: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Train the autoencoder on normal traffic data.
        
        Args:
            X: Training features (should be normal traffic only)
            y: Ignored for unsupervised learning
            X_val: Validation data for early stopping
            
        Returns:
            Training metrics
        """
        logger.info("Training Autoencoder model...")
        
        X = self._validate_features(X)
        
        # Update config based on input dimension
        self.config['input_dim'] = X.shape[1]
        
        # Learn feature statistics
        self._feature_mean = np.mean(X, axis=0)
        self._feature_std = np.std(X, axis=0)
        
        # Normalize
        X_norm = self._normalize_features(X)
        
        # Initialize model
        self.model = AutoencoderNetwork(
            input_dim=self.config['input_dim'],
            latent_dim=self.config['latent_dim'],
            hidden_dims=self.config['hidden_dims']
        ).to(self.device)
        
        # Keep full tensors on CPU and stream mini-batches to device.
        # Moving the entire dataset to GPU at once can OOM on large datasets.
        X_tensor = torch.FloatTensor(X_norm)
        train_dataset = TensorDataset(X_tensor, X_tensor)
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.config['batch_size'],
            shuffle=True,
            pin_memory=(self.device.type == "cuda"),
        )
        
        # Loss and optimizer
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(
            self.model.parameters(),
            lr=self.config['learning_rate']
        )
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='min', patience=5, factor=0.5
        )
        
        # Training loop
        best_loss = float('inf')
        patience_counter = 0
        
        for epoch in range(self.config['epochs']):
            self.model.train()
            total_loss = 0
            
            for batch_x, _ in train_loader:
                batch_x = batch_x.to(self.device, non_blocking=True)
                optimizer.zero_grad()
                _, reconstructed = self.model(batch_x)
                loss = criterion(reconstructed, batch_x)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            avg_loss = total_loss / len(train_loader)
            scheduler.step(avg_loss)
            
            if avg_loss < best_loss:
                best_loss = avg_loss
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= self.config['early_stopping_patience']:
                    logger.info(f"Early stopping at epoch {epoch+1}")
                    break
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{self.config['epochs']}, Loss: {avg_loss:.6f}")
        
        # Calculate reconstruction error statistics in batches (avoid full-tensor GPU eval)
        self.model.eval()
        eval_loader = DataLoader(
            train_dataset,
            batch_size=self.config['batch_size'],
            shuffle=False,
            pin_memory=(self.device.type == "cuda"),
        )
        errors_list = []
        with torch.no_grad():
            for batch_x, _ in eval_loader:
                batch_x = batch_x.to(self.device, non_blocking=True)
                _, reconstructed = self.model(batch_x)
                batch_errors = self._calculate_reconstruction_error(batch_x, reconstructed)
                errors_list.append(batch_errors.detach().cpu())

        errors_np = torch.cat(errors_list, dim=0).numpy()
        self._mean_error = float(np.mean(errors_np))
        self._std_error = float(np.std(errors_np))
        
        # Set threshold as mean + 2*std (captures ~95% of normal data)
        self._threshold = self._mean_error + 2 * self._std_error
        
        self._metrics = {
            'n_samples': len(X),
            'n_features': X.shape[1],
            'final_loss': float(best_loss),
            'mean_reconstruction_error': self._mean_error,
            'std_reconstruction_error': self._std_error,
            'threshold': self._threshold
        }
        
        self._is_ready = True
        self._last_updated = datetime.utcnow().isoformat()
        
        logger.info(f"Autoencoder training complete. Metrics: {self._metrics}")
        return self._metrics
    
    def _error_to_confidence(self, error: float) -> float:
        """Convert reconstruction error to confidence score."""
        # Use sigmoid-like transformation
        z_score = (error - self._mean_error) / max(self._std_error, 1e-6)
        # Clip to reasonable range
        z_score = np.clip(z_score, -10, 10)
        # Convert to confidence
        confidence = 1 / (1 + np.exp(-z_score))
        return float(confidence)
