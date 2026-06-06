"""FastAPI parity tests for the auth-service port."""

import os
import sys
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-asgi-auth-tests")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("ADMIN_USERNAME", "")
os.environ.setdefault("ADMIN_EMAIL", "")
os.environ.setdefault("ADMIN_PASSWORD", "")

_backend_root = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(_backend_root, "auth-service"))


with (
    patch("redis.ConnectionPool.from_url", return_value=MagicMock()),
    patch("redis.Redis", return_value=MagicMock()),
    patch.dict(
        "sys.modules",
        {"enterprise_auth": MagicMock(register_enterprise_auth=MagicMock())},
    ),
):
    from asgi_app import asgi  # noqa: E402


def test_health_matches_flask_contract():
    response = TestClient(asgi).get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert isinstance(body["timestamp"], str)


def test_readyz_reports_ready():
    response = TestClient(asgi).get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
