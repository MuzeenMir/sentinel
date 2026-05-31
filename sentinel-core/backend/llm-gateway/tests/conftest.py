"""Pytest fixtures for LLM Gateway tests.

The gateway is imported with Redis patched to a fake so tests need no live
Redis, mirroring the api-gateway test pattern. The Anthropic SDK is optional
at import time (lazy import in anthropic_client), so tests run without it.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add backend root and the service dir to the path so `import app` works when
# pytest is invoked from llm-gateway/.
_SERVICE_DIR = Path(__file__).resolve().parent.parent
_BACKEND_ROOT = _SERVICE_DIR.parent
sys.path.insert(0, str(_SERVICE_DIR))
sys.path.insert(0, str(_BACKEND_ROOT))


class FakeRedis:
    """Minimal in-memory fake Redis covering the gateway's usage."""

    def __init__(self):
        self.store = {}

    def setex(self, key, ttl, value):
        self.store[key] = value

    def set(self, key, value, ex=None):
        self.store[key] = value

    def get(self, key):
        return self.store.get(key)

    def rpush(self, key, value):
        self.store.setdefault(key, []).append(value)
        return len(self.store[key])

    def lrange(self, key, start, end):
        items = self.store.get(key, [])
        if end == -1:
            return items[start:]
        return items[start : end + 1]

    def expire(self, key, ttl):
        return True

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1
        return self.store[key]

    def delete(self, *keys):
        for k in keys:
            self.store.pop(k, None)


@pytest.fixture
def fake_redis():
    return FakeRedis()


@pytest.fixture
def app_module(fake_redis):
    """Import the gateway app with Redis patched to the in-memory fake."""
    if "app" in sys.modules:
        del sys.modules["app"]
    with patch("redis.from_url", return_value=fake_redis):
        import app as gateway_app

        gateway_app.app.config["TESTING"] = True
        yield gateway_app


@pytest.fixture
def client(app_module):
    with app_module.app.test_client() as c:
        yield c
