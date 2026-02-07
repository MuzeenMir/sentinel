"""Pytest fixtures for AI Engine tests. Sets MODEL_PATH and mocks Redis before app import."""
import os
import sys
from pathlib import Path

# Set MODEL_PATH to trained_models before any test imports app
_ai_engine_root = Path(__file__).resolve().parent.parent
_trained_models = _ai_engine_root / "trained_models"
os.environ["MODEL_PATH"] = str(_trained_models)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")


class FakeRedis:
    """Fake Redis so tests don't need a real Redis."""

    def __init__(self, *args, **kwargs):
        self._store = {}

    def get(self, key):
        val = self._store.get(key)
        return str(val).encode() if isinstance(val, int) else val

    def setex(self, key, ttl, value):
        self._store[key] = value

    def incr(self, key):
        self._store[key] = int(self._store.get(key) or 0) + 1
        return self._store[key]

    def expire(self, key, ttl):
        pass

    def hset(self, key, mapping=None, **kwargs):
        if mapping is None:
            mapping = kwargs
        self._store[key] = dict(mapping)

    def keys(self, pattern="*"):
        return list(self._store.keys())


# Patch redis.Redis.from_url so app gets FakeRedis when it imports
import redis
def _fake_from_url(cls, url, **kwargs):
    return FakeRedis()
redis.Redis.from_url = classmethod(_fake_from_url)

# Add ai-engine to path so "from app import app" works when run from backend/
sys.path.insert(0, str(_ai_engine_root))
