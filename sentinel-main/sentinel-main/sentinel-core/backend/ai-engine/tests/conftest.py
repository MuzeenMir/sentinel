"""Pytest fixtures for AI Engine tests. Sets MODEL_PATH and mocks Redis before app import."""
import os
import sys
from pathlib import Path

# Set MODEL_PATH to trained_models before any test imports app
_ai_engine_root = Path(__file__).resolve().parent.parent
_trained_models = _ai_engine_root / "trained_models"
os.environ["MODEL_PATH"] = str(_trained_models)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")

# region agent log
import json as _agent_json
from datetime import datetime as _agent_dt
import time as _agent_time
import importlib.util as _agent_importlib_util


def _agent_log_ai_engine_tests(hypothesis_id, message, data):
    """Lightweight debug logger for ai-engine tests (NDJSON to Cursor debug file)."""
    try:
        payload = {
            "sessionId": "ba9959",
            "id": f"log_{int(_agent_time.time() * 1000)}",
            "timestamp": int(_agent_dt.utcnow().timestamp() * 1000),
            "location": "ai-engine/tests/conftest.py:before_redis_import",
            "message": message,
            "data": data,
            "runId": "pre-fix",
            "hypothesisId": hypothesis_id,
        }
        with open("/home/mir/sentinel/.cursor/debug-ba9959.log", "a") as _f:
            _f.write(_agent_json.dumps(payload) + "\n")
    except Exception:
        # Never let debug logging break tests
        pass


_agent_log_ai_engine_tests(
    "H1",
    "redis_spec_check",
    {"have_redis_spec": _agent_importlib_util.find_spec("redis") is not None},
)
# endregion


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
try:
    import redis  # type: ignore[import]
except ModuleNotFoundError:
    # When the redis library is not installed (e.g. local dev without full deps),
    # provide a minimal shim so the app can still use FakeRedis in tests.
    class _RedisClient:
        @classmethod
        def from_url(cls, url, **kwargs):
            return FakeRedis()

    class _RedisModule:
        Redis = _RedisClient

    redis = _RedisModule()  # type: ignore[assignment]
else:
    def _fake_from_url(cls, url, **kwargs):
        return FakeRedis()

    redis.Redis.from_url = classmethod(_fake_from_url)

# Add ai-engine to path so "from app import app" works when run from backend/
sys.path.insert(0, str(_ai_engine_root))
