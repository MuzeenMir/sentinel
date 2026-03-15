"""
Retraining Pipeline

Manages model retraining with new data from feedback and production.
"""
import logging
import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import numpy as np
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RetrainingJob:
    """Retraining job tracking."""
    id: str
    model_name: str
    status: str  # 'pending', 'running', 'completed', 'failed'
    started_at: Optional[str]
    completed_at: Optional[str]
    samples_used: int
    old_metrics: Dict[str, float]
    new_metrics: Dict[str, float]
    promoted: bool  # Whether new model was promoted to production
    error: Optional[str]


class RetrainingPipeline:
    """
    Manages the model retraining pipeline.
    
    Features:
    - Incremental learning with new data
    - A/B testing between old and new models
    - Automatic promotion based on metrics
    - Rollback capability
    """
    
    def __init__(
        self,
        models_dir: str = "/models",
        staging_dir: str = "/models/staging",
        backup_dir: str = "/models/backup",
        improvement_threshold: float = 0.02  # 2% improvement required
    ):
        self.models_dir = Path(models_dir)
        self.staging_dir = Path(staging_dir)
        self.backup_dir = Path(backup_dir)
        self.improvement_threshold = improvement_threshold
        
        # Create directories
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self._jobs: Dict[str, RetrainingJob] = {}
    
    def retrain_xgboost(
        self,
        new_samples: List[Dict[str, Any]],
        existing_model = None
    ) -> RetrainingJob:
        """
        Retrain XGBoost model with new samples.
        
        Uses incremental learning when possible.
        """
        import uuid
        
        job_id = str(uuid.uuid4())[:8]
        job = RetrainingJob(
            id=job_id,
            model_name='xgboost',
            status='running',
            started_at=datetime.utcnow().isoformat(),
            completed_at=None,
            samples_used=len(new_samples),
            old_metrics={},
            new_metrics={},
            promoted=False,
            error=None
        )
        
        self._jobs[job_id] = job
        
        try:
            # Prepare data
            X_new, y_new = self._prepare_samples(new_samples)
            
            if len(X_new) < 50:
                raise ValueError("Not enough samples for retraining (minimum 50)")
            
            # Load existing model or create new
            if existing_model is None:
                existing_model = self._load_existing_model('xgboost')
            
            # Get baseline metrics
            if existing_model:
                job.old_metrics = self._evaluate_model(existing_model, X_new, y_new)
            
            # Retrain
            import xgboost as xgb
            from sklearn.model_selection import train_test_split
            
            X_train, X_val, y_train, y_val = train_test_split(
                X_new, y_new, test_size=0.2, random_state=42
            )
            
            # Create new model with same params
            new_model = xgb.XGBClassifier(
                objective='binary:logistic',
                max_depth=8,
                learning_rate=0.1,
                n_estimators=200,
                random_state=42
            )
            
            new_model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                verbose=False
            )
            
            # Evaluate new model
            job.new_metrics = self._evaluate_model(new_model, X_val, y_val)
            
            # Check if improvement is sufficient
            if self._should_promote(job.old_metrics, job.new_metrics):
                self._promote_model('xgboost', new_model, job)
                job.promoted = True
                logger.info(f"New XGBoost model promoted (F1: {job.new_metrics.get('f1', 0):.4f})")
            else:
                logger.info("New model not promoted (insufficient improvement)")
            
            job.status = 'completed'
            job.completed_at = datetime.utcnow().isoformat()
            
        except Exception as e:
            logger.error(f"XGBoost retraining failed: {e}")
            job.status = 'failed'
            job.error = str(e)
            job.completed_at = datetime.utcnow().isoformat()
        
        return job
    
    def retrain_lstm(
        self,
        new_sequences: np.ndarray,
        new_labels: np.ndarray,
        existing_model = None
    ) -> RetrainingJob:
        """Retrain LSTM model."""
        import uuid
        
        job_id = str(uuid.uuid4())[:8]
        job = RetrainingJob(
            id=job_id,
            model_name='lstm',
            status='running',
            started_at=datetime.utcnow().isoformat(),
            completed_at=None,
            samples_used=len(new_labels),
            old_metrics={},
            new_metrics={},
            promoted=False,
            error=None
        )
        
        self._jobs[job_id] = job
        
        try:
            import torch
            import torch.nn as nn
            import torch.optim as optim
            from torch.utils.data import DataLoader, TensorDataset
            
            # Load existing model
            if existing_model is None:
                existing_model = self._load_existing_model('lstm')
            
            # Prepare data
            X_tensor = torch.FloatTensor(new_sequences)
            y_tensor = torch.LongTensor(new_labels)
            
            dataset = TensorDataset(X_tensor, y_tensor)
            train_size = int(0.8 * len(dataset))
            val_size = len(dataset) - train_size
            train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])
            
            train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
            val_loader = DataLoader(val_dataset, batch_size=64)
            
            # Fine-tune existing model or train new
            if existing_model:
                model = existing_model
                # Use smaller learning rate for fine-tuning
                optimizer = optim.Adam(model.parameters(), lr=0.0001)
            else:
                # Create new model (would need proper initialization)
                raise NotImplementedError("New LSTM model creation not implemented")
            
            criterion = nn.CrossEntropyLoss()
            
            # Train for a few epochs
            device = next(model.parameters()).device
            
            for epoch in range(10):
                model.train()
                for batch_x, batch_y in train_loader:
                    batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                    
                    optimizer.zero_grad()
                    outputs = model(batch_x)
                    loss = criterion(outputs, batch_y)
                    loss.backward()
                    optimizer.step()
            
            # Evaluate
            model.eval()
            correct = 0
            total = 0
            
            with torch.no_grad():
                for batch_x, batch_y in val_loader:
                    batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                    outputs = model(batch_x)
                    _, predicted = torch.max(outputs.data, 1)
                    total += batch_y.size(0)
                    correct += (predicted == batch_y).sum().item()
            
            job.new_metrics = {'accuracy': correct / total}
            job.status = 'completed'
            job.completed_at = datetime.utcnow().isoformat()
            
        except Exception as e:
            logger.error(f"LSTM retraining failed: {e}")
            job.status = 'failed'
            job.error = str(e)
            job.completed_at = datetime.utcnow().isoformat()
        
        return job
    
    def _prepare_samples(
        self,
        samples: List[Dict[str, Any]]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare samples for training."""
        X = []
        y = []
        
        for sample in samples:
            features = sample.get('features', {})
            label = sample.get('label', 0)
            
            # Convert features dict to array
            feature_values = list(features.values())
            X.append(feature_values)
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def _load_existing_model(self, model_name: str):
        """Load existing production model."""
        model_path = self.models_dir / model_name
        
        if model_name == 'xgboost':
            try:
                import xgboost as xgb
                model = xgb.XGBClassifier()
                model.load_model(str(model_path / 'xgboost_model.json'))
                return model
            except:
                return None
        
        elif model_name == 'lstm':
            try:
                import torch
                # Would need model class definition
                return None
            except:
                return None
        
        return None
    
    def _evaluate_model(
        self,
        model,
        X: np.ndarray,
        y: np.ndarray
    ) -> Dict[str, float]:
        """Evaluate model on data."""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        y_pred = model.predict(X)
        
        return {
            'accuracy': float(accuracy_score(y, y_pred)),
            'precision': float(precision_score(y, y_pred, zero_division=0)),
            'recall': float(recall_score(y, y_pred, zero_division=0)),
            'f1': float(f1_score(y, y_pred, zero_division=0)),
        }
    
    def _should_promote(
        self,
        old_metrics: Dict[str, float],
        new_metrics: Dict[str, float]
    ) -> bool:
        """Check if new model should be promoted."""
        if not old_metrics:
            return True  # No old model, always promote
        
        # Check F1 improvement
        old_f1 = old_metrics.get('f1', 0)
        new_f1 = new_metrics.get('f1', 0)
        
        improvement = new_f1 - old_f1
        
        return improvement >= self.improvement_threshold
    
    def _promote_model(self, model_name: str, model, job: RetrainingJob):
        """Promote new model to production."""
        prod_path = self.models_dir / model_name
        backup_path = self.backup_dir / f"{model_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Backup current model
        if prod_path.exists():
            import shutil
            shutil.copytree(prod_path, backup_path)
            logger.info(f"Backed up old model to {backup_path}")
        
        # Save new model
        prod_path.mkdir(parents=True, exist_ok=True)
        
        if model_name == 'xgboost':
            model.save_model(str(prod_path / 'xgboost_model.json'))
            
            # Save metadata
            meta = {
                'version': datetime.now().strftime('%Y%m%d_%H%M%S'),
                'retrain_job': job.id,
                'samples_used': job.samples_used,
                'metrics': job.new_metrics,
                'promoted_at': datetime.utcnow().isoformat()
            }
            with open(prod_path / 'xgboost_meta.json', 'w') as f:
                json.dump(meta, f, indent=2)
    
    def rollback(self, model_name: str) -> bool:
        """Rollback to previous model version."""
        # Find most recent backup
        backups = list(self.backup_dir.glob(f"{model_name}_*"))
        
        if not backups:
            logger.error("No backups found for rollback")
            return False
        
        latest_backup = max(backups, key=lambda p: p.name)
        prod_path = self.models_dir / model_name
        
        import shutil
        
        # Remove current
        if prod_path.exists():
            shutil.rmtree(prod_path)
        
        # Restore backup
        shutil.copytree(latest_backup, prod_path)
        
        logger.info(f"Rolled back {model_name} to {latest_backup.name}")
        return True
    
    def get_job(self, job_id: str) -> Optional[RetrainingJob]:
        """Get retraining job status."""
        return self._jobs.get(job_id)
    
    def list_jobs(self) -> List[RetrainingJob]:
        """List all retraining jobs."""
        return list(self._jobs.values())
