"""
Prediction service for real-time threat detection.

Orchestrates feature extraction, model inference, and result aggregation
for high-throughput, low-latency threat detection.
"""
import logging
import time
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import redis

logger = logging.getLogger(__name__)


class PredictionService:
    """
    High-performance prediction service for threat detection.
    
    Features:
    - Parallel feature extraction
    - Batched model inference
    - Result caching
    - Performance monitoring
    """
    
    def __init__(self, 
                 feature_extractors: Dict[str, Any],
                 ensemble: Any,
                 redis_client: Optional[redis.Redis] = None,
                 max_workers: int = 4):
        """
        Initialize prediction service.
        
        Args:
            feature_extractors: Dict of extractor name -> extractor instance
            ensemble: Stacking ensemble for final prediction
            redis_client: Redis client for caching
            max_workers: Max parallel workers for feature extraction
        """
        self.feature_extractors = feature_extractors
        self.ensemble = ensemble
        self.redis_client = redis_client
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Performance tracking
        self._stats = {
            'total_predictions': 0,
            'total_latency_ms': 0,
            'threats_detected': 0,
            'cache_hits': 0
        }
    
    def predict(self, traffic_data: Dict[str, Any], 
                context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Perform threat detection on traffic data.
        
        Args:
            traffic_data: Network traffic data
            context: Optional contextual information
            
        Returns:
            Detection result with confidence and explanation
        """
        start_time = time.time()
        
        try:
            # Check cache for similar traffic
            cache_key = self._get_cache_key(traffic_data)
            cached_result = self._check_cache(cache_key)
            if cached_result:
                self._stats['cache_hits'] += 1
                return cached_result
            
            # Extract features
            features = self._extract_all_features(traffic_data, context)
            
            # Convert to feature vector
            feature_vector = self._features_to_vector(features)
            
            # Run ensemble prediction
            result = self.ensemble.predict(feature_vector, context)
            
            # Enrich result
            result['features'] = {
                'statistical': self._summarize_features(features.get('statistical', {})),
                'behavioral': self._summarize_features(features.get('behavioral', {})),
                'contextual': self._summarize_features(features.get('contextual', {}))
            }
            
            # Calculate latency
            latency_ms = (time.time() - start_time) * 1000
            result['latency_ms'] = latency_ms
            
            # Update stats
            self._stats['total_predictions'] += 1
            self._stats['total_latency_ms'] += latency_ms
            if result.get('is_threat'):
                self._stats['threats_detected'] += 1
            
            # Cache result
            self._cache_result(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return self._error_result(str(e), time.time() - start_time)
    
    def predict_batch(self, traffic_batch: List[Dict[str, Any]],
                      context: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """
        Perform batch threat detection.
        
        Args:
            traffic_batch: List of traffic data dicts
            context: Optional shared context
            
        Returns:
            List of detection results
        """
        start_time = time.time()
        results = []
        
        try:
            # Extract features for all samples in parallel
            all_features = []
            futures = []
            
            for data in traffic_batch:
                future = self.executor.submit(
                    self._extract_all_features, data, context
                )
                futures.append(future)
            
            for future in as_completed(futures):
                all_features.append(future.result())
            
            # Convert to feature matrix
            feature_matrix = np.array([
                self._features_to_vector(f) for f in all_features
            ])
            
            # Batch prediction
            batch_results = self.ensemble.predict_batch(feature_matrix)
            
            # Enrich results
            total_latency = (time.time() - start_time) * 1000
            per_sample_latency = total_latency / len(traffic_batch)
            
            for i, result in enumerate(batch_results):
                result['features'] = {
                    'statistical': self._summarize_features(all_features[i].get('statistical', {})),
                    'behavioral': self._summarize_features(all_features[i].get('behavioral', {})),
                    'contextual': self._summarize_features(all_features[i].get('contextual', {}))
                }
                result['latency_ms'] = per_sample_latency
                results.append(result)
                
                # Update stats
                self._stats['total_predictions'] += 1
                if result.get('is_threat'):
                    self._stats['threats_detected'] += 1
            
            self._stats['total_latency_ms'] += total_latency
            
            return results
            
        except Exception as e:
            logger.error(f"Batch prediction error: {e}")
            return [self._error_result(str(e), 0) for _ in traffic_batch]
    
    def _extract_all_features(self, data: Dict[str, Any],
                              context: Optional[Dict] = None) -> Dict[str, Dict]:
        """Extract features using all extractors."""
        features = {}
        
        for name, extractor in self.feature_extractors.items():
            try:
                if name == 'contextual':
                    features[name] = extractor.extract(data, context)
                else:
                    features[name] = extractor.extract(data)
            except Exception as e:
                logger.warning(f"Feature extraction failed for {name}: {e}")
                features[name] = {}
        
        return features
    
    def _features_to_vector(self, features: Dict[str, Dict]) -> np.ndarray:
        """Convert feature dicts to numpy vector."""
        vectors = []
        
        for name in ['statistical', 'behavioral', 'contextual']:
            if name in features and features[name]:
                extractor = self.feature_extractors.get(name)
                if extractor:
                    feature_names = extractor.get_feature_names()
                    vec = [features[name].get(fn, 0.0) for fn in feature_names]
                    vectors.extend(vec)
                else:
                    vectors.extend(list(features[name].values()))
            else:
                # Use default vector length
                vectors.extend([0.0] * 50)  # Default feature count
        
        return np.array(vectors, dtype=np.float32)
    
    def _summarize_features(self, features: Dict[str, float]) -> Dict[str, float]:
        """Summarize features for response (top features only)."""
        if not features:
            return {}
        
        # Return top 5 most significant features
        sorted_features = sorted(
            features.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:5]
        
        return dict(sorted_features)
    
    def _get_cache_key(self, data: Dict[str, Any]) -> str:
        """Generate cache key for traffic data."""
        # Create hash from key fields
        key_fields = [
            data.get('source_ip', data.get('src_ip', '')),
            data.get('dest_ip', data.get('destination_ip', '')),
            str(data.get('source_port', data.get('src_port', ''))),
            str(data.get('dest_port', data.get('destination_port', ''))),
            data.get('protocol', '')
        ]
        
        import hashlib
        key_str = ':'.join(key_fields)
        hash_val = hashlib.md5(key_str.encode()).hexdigest()[:16]
        
        return f"pred_cache:{hash_val}"
    
    def _check_cache(self, cache_key: str) -> Optional[Dict]:
        """Check Redis cache for existing prediction."""
        if not self.redis_client:
            return None
        
        try:
            cached = self.redis_client.get(cache_key)
            if cached:
                import json
                return json.loads(cached)
        except Exception as e:
            logger.warning(f"Cache check failed: {e}")
        
        return None
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache prediction result."""
        if not self.redis_client:
            return
        
        try:
            import json
            # Cache for 5 minutes
            self.redis_client.setex(
                cache_key,
                300,
                json.dumps(result, default=str)
            )
        except Exception as e:
            logger.warning(f"Cache write failed: {e}")
    
    def _error_result(self, error: str, duration: float) -> Dict[str, Any]:
        """Generate error result."""
        return {
            'detection_id': f"det_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_error",
            'is_threat': False,
            'confidence': 0.0,
            'threat_score': 0.0,
            'threat_type': 'unknown',
            'timestamp': datetime.utcnow().isoformat(),
            'error': error,
            'latency_ms': duration * 1000,
            'model_verdicts': {}
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get prediction service statistics."""
        avg_latency = (
            self._stats['total_latency_ms'] / max(self._stats['total_predictions'], 1)
        )
        
        return {
            'total_predictions': self._stats['total_predictions'],
            'threats_detected': self._stats['threats_detected'],
            'threat_rate': self._stats['threats_detected'] / max(self._stats['total_predictions'], 1),
            'average_latency_ms': avg_latency,
            'cache_hits': self._stats['cache_hits'],
            'cache_hit_rate': self._stats['cache_hits'] / max(self._stats['total_predictions'], 1)
        }
    
    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            'total_predictions': 0,
            'total_latency_ms': 0,
            'threats_detected': 0,
            'cache_hits': 0
        }
    
    def warmup(self, n_samples: int = 10):
        """
        Warm up models with synthetic data.
        
        Useful for ensuring models are loaded and ready
        before production traffic.
        """
        logger.info(f"Warming up prediction service with {n_samples} samples...")
        
        # Generate synthetic traffic data
        np.random.seed(42)
        
        for i in range(n_samples):
            synthetic_data = {
                'source_ip': f"192.168.1.{np.random.randint(1, 255)}",
                'dest_ip': f"10.0.0.{np.random.randint(1, 255)}",
                'source_port': np.random.randint(1024, 65535),
                'dest_port': np.random.choice([80, 443, 22, 3306]),
                'protocol': np.random.choice(['TCP', 'UDP', 'ICMP']),
                'length': np.random.randint(64, 1500),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            try:
                self.predict(synthetic_data)
            except Exception as e:
                logger.warning(f"Warmup prediction {i} failed: {e}")
        
        # Reset stats after warmup
        self.reset_stats()
        logger.info("Prediction service warmup complete")
