"""
Audit trail for decision provenance tracking.
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import redis

logger = logging.getLogger(__name__)


class AuditTrail:
    """
    Track and store decision audit trails for compliance.
    """
    
    TRAIL_PREFIX = "xai:audit:"
    STATS_KEY = "xai:statistics"
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
    
    def record_explanation(self, entity_type: str, entity_id: str,
                          explanation_data: Dict[str, Any]) -> bool:
        """Record an explanation in the audit trail."""
        try:
            trail_key = f"{self.TRAIL_PREFIX}{entity_type}:{entity_id}"
            
            record = {
                'entity_type': entity_type,
                'entity_id': entity_id,
                'timestamp': datetime.utcnow().isoformat(),
                'data': explanation_data
            }
            
            # Store as list to keep history
            self.redis.lpush(trail_key, json.dumps(record))
            self.redis.ltrim(trail_key, 0, 99)  # Keep last 100 entries
            self.redis.expire(trail_key, 86400 * 90)  # 90 days retention
            
            # Update statistics
            self.redis.hincrby(self.STATS_KEY, f'total_{entity_type}', 1)
            self.redis.hincrby(self.STATS_KEY, 'total_explanations', 1)
            
            return True
        
        except Exception as e:
            logger.error(f"Audit trail record error: {e}")
            return False
    
    def get_trail(self, entity_type: str, entity_id: str) -> List[Dict]:
        """Get audit trail for an entity."""
        try:
            trail_key = f"{self.TRAIL_PREFIX}{entity_type}:{entity_id}"
            records = self.redis.lrange(trail_key, 0, -1)
            
            return [json.loads(r) for r in records]
        
        except Exception as e:
            logger.error(f"Audit trail retrieval error: {e}")
            return []
    
    def get_recent_trails(self, entity_type: Optional[str] = None,
                         limit: int = 100) -> List[Dict]:
        """Get recent audit trails."""
        trails = []
        
        try:
            pattern = f"{self.TRAIL_PREFIX}{entity_type or '*'}:*"
            
            for key in self.redis.scan_iter(pattern, count=limit):
                records = self.redis.lrange(key, 0, 0)  # Get latest
                if records:
                    trails.append(json.loads(records[0]))
            
            # Sort by timestamp
            trails.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            return trails[:limit]
        
        except Exception as e:
            logger.error(f"Recent trails error: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit trail statistics."""
        try:
            stats = self.redis.hgetall(self.STATS_KEY)
            return {
                k.decode(): int(v) for k, v in stats.items()
            }
        except Exception as e:
            logger.error(f"Statistics error: {e}")
            return {}
