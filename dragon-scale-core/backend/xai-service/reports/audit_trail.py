"""Immutable Redis-backed audit trail for AI explanation records."""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_TRAIL_KEY_PREFIX = "xai:trail:"
_TRAIL_INDEX_PREFIX = "xai:trail:index:"
_TRAIL_RECENT_PREFIX = "xai:trail:recent:"
_STATS_KEY = "xai:trail:stats"
_TRAIL_TTL_DAYS = 365


class AuditTrail:
    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    def record_explanation(
        self,
        explanation_type: str,
        entity_id: str,
        data: Dict[str, Any],
    ) -> str:
        record_id = f"xai_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.utcnow().isoformat()

        record: Dict[str, Any] = {
            "record_id": record_id,
            "type": explanation_type,
            "entity_id": entity_id,
            "timestamp": timestamp,
            "data": data,
        }

        serialised = json.dumps(record, default=str)

        try:
            entity_key = f"{_TRAIL_KEY_PREFIX}{explanation_type}:{entity_id}"
            self._redis.rpush(entity_key, serialised)
            self._redis.expire(entity_key, timedelta(days=_TRAIL_TTL_DAYS))

            recent_key = f"{_TRAIL_RECENT_PREFIX}{explanation_type}"
            self._redis.lpush(recent_key, serialised)
            self._redis.ltrim(recent_key, 0, 4999)

            self._increment_stat(explanation_type)

            logger.debug(
                "Recorded %s explanation %s for entity %s",
                explanation_type,
                record_id,
                entity_id,
            )
        except Exception:
            logger.exception(
                "Failed to record audit trail for %s/%s", explanation_type, entity_id
            )
            raise

        return record_id

    def get_trail(
        self, entity_type: Optional[str], entity_id: str
    ) -> List[Dict[str, Any]]:
        if not entity_type:
            return self._search_all_types(entity_id)

        key = f"{_TRAIL_KEY_PREFIX}{entity_type}:{entity_id}"
        try:
            raw_entries = self._redis.lrange(key, 0, -1)
            return [json.loads(entry) for entry in raw_entries]
        except Exception:
            logger.exception(
                "Failed to retrieve trail for %s/%s", entity_type, entity_id
            )
            return []

    def get_recent_trails(
        self, entity_type: Optional[str], limit: int = 100
    ) -> List[Dict[str, Any]]:
        try:
            if entity_type:
                key = f"{_TRAIL_RECENT_PREFIX}{entity_type}"
                raw = self._redis.lrange(key, 0, limit - 1)
                return [json.loads(r) for r in raw]

            combined: List[Dict[str, Any]] = []
            for etype in ("detection", "policy"):
                key = f"{_TRAIL_RECENT_PREFIX}{etype}"
                raw = self._redis.lrange(key, 0, limit - 1)
                combined.extend(json.loads(r) for r in raw)

            combined.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
            return combined[:limit]
        except Exception:
            logger.exception("Failed to retrieve recent trails")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        try:
            raw = self._redis.hgetall(_STATS_KEY)
            stats: Dict[str, int] = {}
            total = 0
            for key, value in raw.items():
                k = key.decode() if isinstance(key, bytes) else key
                v = int(value.decode() if isinstance(value, bytes) else value)
                stats[k] = v
                total += v

            return {
                "total_explanations": total,
                "by_type": stats,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception:
            logger.exception("Failed to retrieve audit trail statistics")
            return {
                "total_explanations": 0,
                "by_type": {},
                "timestamp": datetime.utcnow().isoformat(),
            }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _increment_stat(self, explanation_type: str) -> None:
        try:
            self._redis.hincrby(_STATS_KEY, explanation_type, 1)
            self._redis.hincrby(_STATS_KEY, "total", 1)
        except Exception:
            logger.warning("Failed to update audit trail statistics")

    def _search_all_types(self, entity_id: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for etype in ("detection", "policy"):
            results.extend(self.get_trail(etype, entity_id))
        results.sort(key=lambda r: r.get("timestamp", ""))
        return results
