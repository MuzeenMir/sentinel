"""Integration tests for API Gateway health and basic endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient
from limits.storage import MemoryStorage
from limits.strategies import FixedWindowRateLimiter


class FakeRedis:
    """Fake Redis for testing - no actual connection."""

    def incr(self, key):
        return 1

    def expire(self, key, ttl):
        pass

    def keys(self, pattern):
        return []

    def scan_iter(self, pattern, count=100):
        return iter([])

    def get(self, key):
        return None


def test_health_returns_200():
    """Health endpoint returns 200 and healthy status."""
    import asgi_app

    test_storage = MemoryStorage()
    with (
        patch.object(asgi_app.core, "redis_client", FakeRedis()),
        patch.object(asgi_app.limiter, "_storage", test_storage),
        patch.object(
            asgi_app.limiter,
            "_limiter",
            FixedWindowRateLimiter(test_storage),
        ),
    ):
        rv = TestClient(asgi_app.asgi).get("/health")
    assert rv.status_code == 200
    data = rv.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
