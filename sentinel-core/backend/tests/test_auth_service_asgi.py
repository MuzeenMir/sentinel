"""FastAPI parity tests for the auth-service port."""

import os
import sys
from datetime import datetime, timedelta
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


def _login(
    client: TestClient,
    username: str = "testuser",
    password=VALID_PASSWORD,
):
    return client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )


def _reset_db() -> None:
    with asgi_app.flask_auth.app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()
    asgi_app.flask_auth.redis_client.reset_mock()
    asgi_app.flask_auth.redis_client.get.return_value = None


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


def test_login_success_matches_flask_contract(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", lambda *a, **k: "audit_stub")
    _reset_db()
    client = TestClient(asgi)
    assert _register(client).status_code == 201

    response = _login(client)

    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 24 * 60 * 60
    assert body["user"]["username"] == "testuser"


def test_login_missing_fields_returns_400(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", lambda *a, **k: "audit_stub")
    _reset_db()

    response = TestClient(asgi).post("/api/v1/auth/login", json={})

    assert response.status_code == 400
    assert response.json() == {"error": "Username and password required"}


def test_login_invalid_password_returns_401(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", lambda *a, **k: "audit_stub")
    _reset_db()
    client = TestClient(asgi)
    assert _register(client).status_code == 201

    response = _login(client, password="wrong")

    assert response.status_code == 401
    assert response.json() == {"error": "Invalid credentials"}


def test_login_locked_account_rejects_before_password_check(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", MagicMock())
    _reset_db()
    client = TestClient(asgi)
    assert _register(client).status_code == 201
    with asgi_app.flask_auth.app.app_context():
        user = asgi_app.flask_auth.User.query.filter_by(username="testuser").first()
        user.failed_login_attempts = 5
        user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()

    with patch.object(
        asgi_app.flask_auth.User,
        "check_password",
        side_effect=AssertionError("password checked for locked user"),
    ):
        response = _login(client)

    assert response.status_code == 403
    body = response.json()
    assert "temporarily locked" in body["error"].lower()
    assert body["retry_after"] >= 0


def test_login_non_string_credentials_return_400(monkeypatch):
    monkeypatch.setattr(asgi_app.flask_auth, "audit_log", lambda *a, **k: "audit_stub")
    _reset_db()

    response = TestClient(asgi).post(
        "/api/v1/auth/login", json={"username": "testuser", "password": 123}
    )

    assert response.status_code == 400
    assert response.json() == {"error": "Username and password must be strings"}
