"""Integration tests for API Gateway health and basic endpoints."""
import pytest
from unittest.mock import patch


class FakeRedis:
    """Fake Redis for testing - no actual connection."""
    def incr(self, key):
        return 1
    def expire(self, key, ttl):
        pass
    def keys(self, pattern):
        return []
    def get(self, key):
        return None


@pytest.fixture
def client():
    """Create test client with mocked Redis (patch before app import)."""
    import sys
    # Remove app from cache so it reloads with patched redis
    if 'app' in sys.modules:
        del sys.modules['app']
    with patch('redis.from_url', return_value=FakeRedis()):
        import app as gateway_app
        gateway_app.app.config['TESTING'] = True
        with gateway_app.app.test_client() as c:
            yield c


def test_health_returns_200(client):
    """Health endpoint returns 200 and healthy status."""
    rv = client.get('/health')
    assert rv.status_code == 200
    data = rv.get_json()
    assert data['status'] == 'healthy'
    assert 'timestamp' in data

