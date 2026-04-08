"""
Unit tests for the SENTINEL Auth Service.

Uses an in-memory SQLite database and mocked Redis to avoid
external dependencies.
"""
import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Provide required env vars BEFORE importing the app
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("ADMIN_USERNAME", "")
os.environ.setdefault("ADMIN_EMAIL", "")
os.environ.setdefault("ADMIN_PASSWORD", "")

_backend_root = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(_backend_root, "auth-service"))


_mock_redis = MagicMock()

with patch("redis.ConnectionPool.from_url", return_value=MagicMock()), \
     patch("redis.Redis", return_value=_mock_redis), \
     patch.dict("sys.modules", {"enterprise_auth": MagicMock(register_enterprise_auth=MagicMock())}):
    import importlib
    spec = importlib.util.spec_from_file_location(
        "auth_app",
        os.path.join(_backend_root, "auth-service", "app.py"),
    )
    auth_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(auth_mod)

app = auth_mod.app
db = auth_mod.db
User = auth_mod.User
UserRole = auth_mod.UserRole
UserStatus = auth_mod.UserStatus
TokenBlacklist = auth_mod.TokenBlacklist

VALID_PASSWORD = "Test@1234"
WEAK_PASSWORD = "weak"


@pytest.fixture(autouse=True)
def setup_db():
    """Create fresh database tables for each test."""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.app_context():
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()
    _mock_redis.reset_mock()
    _mock_redis.get.return_value = None


@pytest.fixture
def client():
    return app.test_client()


def _register(client, username="testuser", email="test@example.com",
              password=VALID_PASSWORD, role="viewer"):
    return client.post("/api/v1/auth/register", json={
        "username": username,
        "email": email,
        "password": password,
        "role": role,
    })


def _login(client, username="testuser", password=VALID_PASSWORD):
    return client.post("/api/v1/auth/login", json={
        "username": username,
        "password": password,
    })


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestHealthCheck:
    def test_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json["status"] == "healthy"


class TestRegistration:
    def test_success(self, client):
        resp = _register(client)
        assert resp.status_code == 201
        assert resp.json["user"]["username"] == "testuser"

    def test_missing_field(self, client):
        resp = client.post("/api/v1/auth/register", json={"username": "x"})
        assert resp.status_code == 400

    def test_duplicate_username(self, client):
        _register(client)
        resp = _register(client, email="other@example.com")
        assert resp.status_code == 409

    def test_duplicate_email(self, client):
        _register(client)
        resp = _register(client, username="other")
        assert resp.status_code == 409

    def test_invalid_email(self, client):
        resp = _register(client, email="not-an-email")
        assert resp.status_code == 400

    def test_invalid_username(self, client):
        resp = _register(client, username="a")
        assert resp.status_code == 400

    def test_weak_password(self, client):
        resp = _register(client, password=WEAK_PASSWORD)
        assert resp.status_code == 400

    def test_role_assigned(self, client):
        resp = _register(client, role="admin")
        assert resp.status_code == 201
        assert resp.json["user"]["role"] == "admin"


class TestLogin:
    def test_success(self, client):
        _register(client)
        resp = _login(client)
        assert resp.status_code == 200
        assert "access_token" in resp.json
        assert "refresh_token" in resp.json
        assert resp.json["token_type"] == "Bearer"

    def test_invalid_password(self, client):
        _register(client)
        resp = _login(client, password="wrong")
        assert resp.status_code == 401

    def test_unknown_user(self, client):
        resp = _login(client, username="nobody")
        assert resp.status_code == 401

    def test_missing_fields(self, client):
        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 400


class TestTokenVerify:
    def test_valid_token(self, client):
        _register(client)
        login_resp = _login(client)
        token = login_resp.json["access_token"]
        resp = client.post("/api/v1/auth/verify", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json["user"]["username"] == "testuser"

    def test_no_token(self, client):
        resp = client.post("/api/v1/auth/verify")
        assert resp.status_code == 401


class TestTokenRefresh:
    def test_refresh_returns_new_access_token(self, client):
        _register(client)
        login_resp = _login(client)
        refresh = login_resp.json["refresh_token"]
        resp = client.post("/api/v1/auth/refresh", headers=_auth_header(refresh))
        assert resp.status_code == 200
        assert "access_token" in resp.json


class TestLogout:
    def test_logout_blacklists_token(self, client):
        _register(client)
        login_resp = _login(client)
        token = login_resp.json["access_token"]
        resp = client.post("/api/v1/auth/logout", headers=_auth_header(token))
        assert resp.status_code == 200
        _mock_redis.setex.assert_called()


class TestProfile:
    def test_get_profile(self, client):
        _register(client)
        login_resp = _login(client)
        token = login_resp.json["access_token"]
        resp = client.get("/api/v1/auth/profile", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json["user"]["username"] == "testuser"

    def test_requires_auth(self, client):
        resp = client.get("/api/v1/auth/profile")
        assert resp.status_code == 401


class TestChangePassword:
    def test_success(self, client):
        _register(client)
        login_resp = _login(client)
        token = login_resp.json["access_token"]
        resp = client.put("/api/v1/auth/change-password", headers=_auth_header(token), json={
            "current_password": VALID_PASSWORD,
            "new_password": "NewPass@5678",
        })
        assert resp.status_code == 200

        # Verify can login with new password
        resp2 = _login(client, password="NewPass@5678")
        assert resp2.status_code == 200

    def test_wrong_current_password(self, client):
        _register(client)
        login_resp = _login(client)
        token = login_resp.json["access_token"]
        resp = client.put("/api/v1/auth/change-password", headers=_auth_header(token), json={
            "current_password": "WrongPass@1",
            "new_password": "NewPass@5678",
        })
        assert resp.status_code == 401

    def test_missing_fields(self, client):
        _register(client)
        login_resp = _login(client)
        token = login_resp.json["access_token"]
        resp = client.put("/api/v1/auth/change-password", headers=_auth_header(token), json={})
        assert resp.status_code == 400


class TestUserManagement:
    def _admin_token(self, client):
        _register(client, username="admin1", email="admin1@x.com", role="admin")
        return _login(client, username="admin1").json["access_token"]

    def test_list_users_admin(self, client):
        token = self._admin_token(client)
        resp = client.get("/api/v1/auth/users", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json["total"] >= 1

    def test_list_users_non_admin(self, client):
        _register(client, role="viewer")
        token = _login(client).json["access_token"]
        resp = client.get("/api/v1/auth/users", headers=_auth_header(token))
        assert resp.status_code == 403

    def test_update_user_role(self, client):
        _register(client, role="viewer")
        token = self._admin_token(client)
        with app.app_context():
            user = User.query.filter_by(username="testuser").first()
            user_id = user.id
        resp = client.put(
            f"/api/v1/auth/users/{user_id}",
            headers=_auth_header(token),
            json={"role": "operator"},
        )
        assert resp.status_code == 200
        assert resp.json["user"]["role"] == "operator"


class TestPasswordValidation:
    def test_too_short(self):
        assert not User._validate_password_strength("Aa1!xyz")

    def test_no_uppercase(self):
        assert not User._validate_password_strength("abcdefg1!")

    def test_no_lowercase(self):
        assert not User._validate_password_strength("ABCDEFG1!")

    def test_no_digit(self):
        assert not User._validate_password_strength("Abcdefgh!")

    def test_no_special(self):
        assert not User._validate_password_strength("Abcdefg1")

    def test_valid(self):
        assert User._validate_password_strength(VALID_PASSWORD)


class TestAccountLocking:
    def test_account_locks_after_5_failures(self, client):
        _register(client)
        for _ in range(5):
            _login(client, password="wrong")

        with app.app_context():
            user = User.query.filter_by(username="testuser").first()
            assert user.failed_login_attempts >= 5
            assert user.locked_until is not None

    def test_locked_account_returns_403(self, client):
        _register(client)
        with app.app_context():
            user = User.query.filter_by(username="testuser").first()
            user.failed_login_attempts = 5
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()

        resp = _login(client)
        assert resp.status_code == 403


class TestInactiveUser:
    def test_suspended_user_cannot_login(self, client):
        _register(client)
        with app.app_context():
            user = User.query.filter_by(username="testuser").first()
            user.status = UserStatus.SUSPENDED
            db.session.commit()

        resp = _login(client)
        assert resp.status_code == 403


class TestTokenBlacklist:
    def test_revoked_token_blocked(self, client):
        _register(client)
        login_resp = _login(client)
        token = login_resp.json["access_token"]

        client.post("/api/v1/auth/logout", headers=_auth_header(token))

        _mock_redis.get.return_value = b"revoked"
        resp = client.get("/api/v1/auth/profile", headers=_auth_header(token))
        assert resp.status_code == 401
