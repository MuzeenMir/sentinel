"""Pytest fixtures for API Gateway tests."""
import sys
from pathlib import Path

# Add parent to path so tests can import app when run from api-gateway/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


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
