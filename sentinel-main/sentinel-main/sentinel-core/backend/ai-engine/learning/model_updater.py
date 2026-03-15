"""
Model Updater

Handles hot-reloading of models in production without service restart.
"""
import logging
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class ModelUpdater:
    """
    Manages model hot-reloading and version management.
    
    Features:
    - Hot-reload models without restart
    - Version tracking
    - Health monitoring
    - Automatic rollback on errors
    """
    
    def __init__(
        self,
        models_dir: str = "/models",
        check_interval: int = 60,
        redis_client = None
    ):
        self.models_dir = Path(models_dir)
        self.check_interval = check_interval
        self._redis = redis_client
        
        # Current model versions
        self._versions: Dict[str, str] = {}
        
        # Model loaders
        self._loaders: Dict[str, Callable] = {}
        
        # Active models
        self._models: Dict[str, Any] = {}
        
        # Monitoring
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_check: Optional[datetime] = None
        self._health: Dict[str, bool] = {}
    
    def register_loader(self, model_name: str, loader: Callable):
        """
        Register a model loader function.
        
        Args:
            model_name: Name of the model
            loader: Function that takes model path and returns loaded model
        """
        self._loaders[model_name] = loader
        logger.info(f"Registered loader for {model_name}")
    
    def start(self):
        """Start the model update monitor."""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Model updater started")
        
        # Subscribe to Redis update events
        if self._redis:
            self._subscribe_to_updates()
    
    def stop(self):
        """Stop the model update monitor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Model updater stopped")
    
    def get_model(self, model_name: str) -> Optional[Any]:
        """Get the current model instance."""
        return self._models.get(model_name)
    
    def get_version(self, model_name: str) -> Optional[str]:
        """Get the current model version."""
        return self._versions.get(model_name)
    
    def force_reload(self, model_name: str) -> bool:
        """Force reload a specific model."""
        if model_name not in self._loaders:
            logger.error(f"No loader registered for {model_name}")
            return False
        
        return self._load_model(model_name)
    
    def reload_all(self):
        """Reload all registered models."""
        for model_name in self._loaders.keys():
            self._load_model(model_name)
    
    def get_status(self) -> Dict[str, Any]:
        """Get model updater status."""
        return {
            'running': self._running,
            'last_check': self._last_check.isoformat() if self._last_check else None,
            'models': {
                name: {
                    'version': self._versions.get(name),
                    'healthy': self._health.get(name, False),
                    'loaded': name in self._models
                }
                for name in self._loaders.keys()
            }
        }
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                self._check_for_updates()
            except Exception as e:
                logger.error(f"Update check error: {e}")
            
            time.sleep(self.check_interval)
    
    def _check_for_updates(self):
        """Check for model updates."""
        self._last_check = datetime.utcnow()
        
        for model_name in self._loaders.keys():
            current_version = self._versions.get(model_name)
            new_version = self._get_model_version(model_name)
            
            if new_version and new_version != current_version:
                logger.info(f"New version detected for {model_name}: {new_version}")
                self._load_model(model_name)
    
    def _get_model_version(self, model_name: str) -> Optional[str]:
        """Get version from model metadata."""
        meta_path = self.models_dir / model_name / f"{model_name}_meta.json"
        
        if not meta_path.exists():
            # Try alternative names
            for suffix in ['_meta.json', '_config.json', 'meta.json']:
                alt_path = self.models_dir / model_name / suffix
                if alt_path.exists():
                    meta_path = alt_path
                    break
        
        if meta_path.exists():
            try:
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                return meta.get('version') or meta.get('last_updated')
            except:
                pass
        
        # Use file modification time as fallback
        model_path = self.models_dir / model_name
        if model_path.exists():
            import os
            mtime = os.path.getmtime(model_path)
            return str(int(mtime))
        
        return None
    
    def _load_model(self, model_name: str) -> bool:
        """Load or reload a model."""
        loader = self._loaders.get(model_name)
        if not loader:
            return False
        
        model_path = self.models_dir / model_name
        
        try:
            # Load new model
            new_model = loader(str(model_path))
            
            if new_model is None:
                raise ValueError("Loader returned None")
            
            # Verify model health
            if not self._verify_model_health(model_name, new_model):
                raise ValueError("Model health check failed")
            
            # Update active model
            old_model = self._models.get(model_name)
            self._models[model_name] = new_model
            self._versions[model_name] = self._get_model_version(model_name)
            self._health[model_name] = True
            
            # Cleanup old model if needed
            if old_model and hasattr(old_model, 'close'):
                try:
                    old_model.close()
                except:
                    pass
            
            logger.info(f"Loaded {model_name} version {self._versions[model_name]}")
            
            # Publish update event
            self._publish_update_event(model_name)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load {model_name}: {e}")
            self._health[model_name] = False
            return False
    
    def _verify_model_health(self, model_name: str, model: Any) -> bool:
        """Verify that a loaded model is healthy."""
        try:
            # Check if model has required methods
            if hasattr(model, 'predict'):
                # Try a dummy prediction
                import numpy as np
                dummy_input = np.zeros((1, 50))  # Adjust size as needed
                model.predict(dummy_input)
            
            return True
            
        except Exception as e:
            logger.warning(f"Health check failed for {model_name}: {e}")
            return False
    
    def _subscribe_to_updates(self):
        """Subscribe to Redis update notifications."""
        if not self._redis:
            return
        
        def listener():
            try:
                pubsub = self._redis.pubsub()
                pubsub.subscribe('sentinel:model_update')
                
                for message in pubsub.listen():
                    if message['type'] == 'message':
                        data = json.loads(message['data'])
                        model_name = data.get('model_name')
                        
                        if model_name and model_name in self._loaders:
                            logger.info(f"Received update notification for {model_name}")
                            self._load_model(model_name)
                            
            except Exception as e:
                logger.error(f"Redis listener error: {e}")
        
        thread = threading.Thread(target=listener, daemon=True)
        thread.start()
    
    def _publish_update_event(self, model_name: str):
        """Publish model update event."""
        if self._redis:
            try:
                self._redis.publish('sentinel:model_loaded', json.dumps({
                    'model_name': model_name,
                    'version': self._versions.get(model_name),
                    'timestamp': datetime.utcnow().isoformat()
                }))
            except:
                pass


# Model loader functions for common model types
def load_xgboost_model(model_path: str):
    """Load XGBoost model."""
    import xgboost as xgb
    
    model_file = Path(model_path) / 'xgboost_model.json'
    if model_file.exists():
        model = xgb.XGBClassifier()
        model.load_model(str(model_file))
        return model
    
    return None


def load_sklearn_model(model_path: str):
    """Load sklearn model (joblib)."""
    import joblib
    
    for suffix in ['.joblib', '.pkl']:
        files = list(Path(model_path).glob(f'*{suffix}'))
        if files:
            return joblib.load(files[0])
    
    return None


def load_pytorch_model(model_path: str, model_class):
    """Load PyTorch model."""
    import torch
    
    model_file = Path(model_path) / 'model.pt'
    config_file = Path(model_path) / 'config.json'
    
    if model_file.exists() and config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        model = model_class(**config.get('architecture', {}))
        model.load_state_dict(torch.load(model_file))
        model.eval()
        
        return model
    
    return None
