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
    import asgi_app  # noqa: E402
    from asgi_app import asgi  # noqa: E402


db = asgi_app.flask_auth.db

VALID_PASSWORD = "Test@1234"


def _register(
    client: TestClient,
    username: str = "testuser",
    email: str = "test@example.com",
    password: str = VALID_PASSWORD,
    role: str = "viewer",
):
    return client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
            "role": role,
        },
    )


def _reset_db() -> None:
    with asgi_app.flask_auth.app.app_context():
        db.drop_all()
        db.create_all()


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


def test_register_success_matches_flask_contract(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", lambda *a, **k: "audit_stub")
    _reset_db()

    response = _register(TestClient(asgi))

    assert response.status_code == 201
    body = response.json()
    assert body["message"] == "User registered successfully"
    assert body["user"]["username"] == "testuser"
    assert body["user"]["role"] == "viewer"


def test_register_missing_field_returns_400(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", lambda *a, **k: "audit_stub")
    _reset_db()

    response = TestClient(asgi).post(
        "/api/v1/auth/register", json={"username": "testuser"}
    )

    assert response.status_code == 400
    assert response.json() == {"error": "Missing required field: email"}


def test_register_duplicate_user_returns_409(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", lambda *a, **k: "audit_stub")
    _reset_db()
    client = TestClient(asgi)

    assert _register(client).status_code == 201
    response = _register(client, email="other@example.com")

    assert response.status_code == 409
    assert response.json() == {"error": "Username or email already exists"}


def test_register_weak_password_returns_requirements(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", lambda *a, **k: "audit_stub")
    _reset_db()

    response = _register(TestClient(asgi), password="weak")

    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "Password does not meet security requirements"
    assert "Minimum 8 characters" in body["requirements"]
