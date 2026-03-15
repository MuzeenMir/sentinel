"""
Feedback Collector

Collects analyst feedback on model predictions for continuous learning.
"""
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import uuid

logger = logging.getLogger(__name__)


@dataclass
class FeedbackEntry:
    """Single feedback entry from analyst."""
    id: str
    detection_id: str
    prediction: Dict[str, Any]  # Original model prediction
    feedback_type: str  # 'confirm', 'false_positive', 'false_negative', 'relabel'
    correct_label: Optional[str]  # For relabeling
    analyst_id: str
    confidence: float  # Analyst confidence in feedback (0-1)
    notes: str
    created_at: str
    features: Optional[Dict[str, float]] = None  # Original features for retraining


class FeedbackCollector:
    """
    Collects and manages feedback for continuous learning.
    
    Features:
    - Store feedback with original predictions
    - Track false positives and false negatives
    - Generate training samples from feedback
    - Export for retraining
    """
    
    def __init__(
        self,
        redis_client = None,
        min_samples_for_retrain: int = 100
    ):
        self._redis = redis_client
        self.min_samples_for_retrain = min_samples_for_retrain
        
        # In-memory storage as fallback
        self._feedback: List[FeedbackEntry] = []
        self._stats = {
            'total': 0,
            'confirmed': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'relabeled': 0
        }
    
    def add_feedback(
        self,
        detection_id: str,
        prediction: Dict[str, Any],
        feedback_type: str,
        analyst_id: str,
        correct_label: Optional[str] = None,
        confidence: float = 1.0,
        notes: str = "",
        features: Optional[Dict[str, float]] = None
    ) -> FeedbackEntry:
        """
        Add feedback for a detection.
        
        Args:
            detection_id: ID of the original detection
            prediction: Original model prediction
            feedback_type: Type of feedback
            analyst_id: ID of analyst providing feedback
            correct_label: Correct label if relabeling
            confidence: Analyst confidence
            notes: Additional notes
            features: Original features (for retraining)
            
        Returns:
            Created FeedbackEntry
        """
        entry = FeedbackEntry(
            id=str(uuid.uuid4()),
            detection_id=detection_id,
            prediction=prediction,
            feedback_type=feedback_type,
            correct_label=correct_label,
            analyst_id=analyst_id,
            confidence=confidence,
            notes=notes,
            created_at=datetime.utcnow().isoformat(),
            features=features
        )
        
        # Store feedback
        self._store_feedback(entry)
        
        # Update stats
        self._stats['total'] += 1
        if feedback_type == 'confirm':
            self._stats['confirmed'] += 1
        elif feedback_type == 'false_positive':
            self._stats['false_positives'] += 1
        elif feedback_type == 'false_negative':
            self._stats['false_negatives'] += 1
        elif feedback_type == 'relabel':
            self._stats['relabeled'] += 1
        
        logger.info(f"Feedback added: {feedback_type} for detection {detection_id}")
        
        # Check if retraining threshold reached
        if self._should_trigger_retrain():
            logger.info("Retraining threshold reached")
            self._trigger_retrain_event()
        
        return entry
    
    def _store_feedback(self, entry: FeedbackEntry):
        """Store feedback entry."""
        self._feedback.append(entry)
        
        if self._redis:
            try:
                key = f"feedback:{entry.id}"
                self._redis.setex(
                    key,
                    86400 * 30,  # 30 day TTL
                    json.dumps(asdict(entry))
                )
                
                # Add to feedback list
                self._redis.lpush("feedback:all", entry.id)
                self._redis.ltrim("feedback:all", 0, 9999)
                
                # Add to type-specific list
                self._redis.lpush(f"feedback:{entry.feedback_type}", entry.id)
                
            except Exception as e:
                logger.error(f"Redis store failed: {e}")
    
    def get_feedback(self, feedback_id: str) -> Optional[FeedbackEntry]:
        """Get feedback by ID."""
        # Check Redis first
        if self._redis:
            try:
                data = self._redis.get(f"feedback:{feedback_id}")
                if data:
                    return FeedbackEntry(**json.loads(data))
            except:
                pass
        
        # Check in-memory
        for entry in self._feedback:
            if entry.id == feedback_id:
                return entry
        
        return None
    
    def get_recent_feedback(
        self,
        limit: int = 100,
        feedback_type: Optional[str] = None
    ) -> List[FeedbackEntry]:
        """Get recent feedback entries."""
        entries = self._feedback
        
        if feedback_type:
            entries = [e for e in entries if e.feedback_type == feedback_type]
        
        return sorted(entries, key=lambda x: x.created_at, reverse=True)[:limit]
    
    def get_training_samples(
        self,
        min_confidence: float = 0.8
    ) -> List[Dict[str, Any]]:
        """
        Get samples suitable for retraining.
        
        Returns samples with features and corrected labels.
        """
        samples = []
        
        for entry in self._feedback:
            if entry.confidence < min_confidence:
                continue
            
            if entry.features is None:
                continue
            
            # Determine label
            if entry.feedback_type == 'confirm':
                # Use original prediction
                label = 1 if entry.prediction.get('is_threat') else 0
            elif entry.feedback_type == 'false_positive':
                # Model said threat, but was benign
                label = 0
            elif entry.feedback_type == 'false_negative':
                # Model said benign, but was threat
                label = 1
            elif entry.feedback_type == 'relabel' and entry.correct_label:
                # Use analyst's label
                label = 0 if entry.correct_label == 'benign' else 1
            else:
                continue
            
            samples.append({
                'features': entry.features,
                'label': label,
                'source': 'feedback',
                'confidence': entry.confidence,
                'feedback_id': entry.id
            })
        
        logger.info(f"Generated {len(samples)} training samples from feedback")
        return samples
    
    def get_stats(self) -> Dict[str, Any]:
        """Get feedback statistics."""
        return {
            **self._stats,
            'ready_for_retrain': self._should_trigger_retrain(),
            'samples_with_features': len([e for e in self._feedback if e.features])
        }
    
    def _should_trigger_retrain(self) -> bool:
        """Check if retraining should be triggered."""
        samples_with_features = len([e for e in self._feedback if e.features])
        return samples_with_features >= self.min_samples_for_retrain
    
    def _trigger_retrain_event(self):
        """Trigger retraining event."""
        if self._redis:
            try:
                self._redis.publish('sentinel:retrain', json.dumps({
                    'event': 'retrain_requested',
                    'samples': self._stats['total'],
                    'timestamp': datetime.utcnow().isoformat()
                }))
            except:
                pass
    
    def export_for_training(self, output_path: str):
        """Export feedback data for training."""
        import csv
        
        samples = self.get_training_samples()
        
        if not samples:
            logger.warning("No samples to export")
            return
        
        # Get feature names from first sample
        feature_names = list(samples[0]['features'].keys())
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(feature_names + ['label', 'confidence', 'source'])
            
            # Data
            for sample in samples:
                row = [sample['features'].get(name, 0) for name in feature_names]
                row.extend([sample['label'], sample['confidence'], sample['source']])
                writer.writerow(row)
        
        logger.info(f"Exported {len(samples)} samples to {output_path}")
