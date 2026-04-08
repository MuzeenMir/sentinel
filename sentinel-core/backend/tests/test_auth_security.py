"""
Auth-specific security test cases (SEC-01 through SEC-10 from STP).

Validates authentication, authorization, and security mechanisms
against common attack vectors.
"""
import os
import sys
import json
import time
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-security-tests")
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
        "auth_sec_app",
        os.path.join(_backend_root, "auth-service", "app.py"),
    )
    auth_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(auth_mod)

app = auth_mod.app
db = auth_mod.db
User = auth_mod.User
UserRole = auth_mod.UserRole
UserStatus = auth_mod.UserStatus

VALID_PASSWORD = "Secure@Pass1"


@pytest.fixture(autouse=True)
def fresh_db():
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


def _create_user(client, username="secuser", role="viewer"):
    return client.post("/api/v1/auth/register", json={
        "username": username,
        "email": f"{username}@test.local",
        "password": VALID_PASSWORD,
        "role": role,
    })


def _login(client, username="secuser"):
    return client.post("/api/v1/auth/login", json={
        "username": username,
        "password": VALID_PASSWORD,
    })


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


class TestSEC01_PasswordPolicy:
    """SEC-01: Password must meet complexity requirements."""

    @pytest.mark.parametrize("weak", [
        "short1!",           # too short
        "alllowercase1!",    # no uppercase
        "ALLUPPERCASE1!",    # no lowercase
        "NoDigitHere!",      # no digit
        "NoSpecial1234",     # no special char
        "",                  # empty
    ])
    def test_weak_passwords_rejected(self, client, weak):
        resp = client.post("/api/v1/auth/register", json={
            "username": "pwtest",
            "email": "pw@test.local",
            "password": weak,
            "role": "viewer",
        })
        assert resp.status_code == 400

    def test_strong_password_accepted(self, client):
        resp = _create_user(client)
        assert resp.status_code == 201


class TestSEC02_BruteForceProtection:
    """SEC-02: Account locks after repeated failed login attempts."""

    def test_lockout_after_5_failures(self, client):
        _create_user(client)
        for _ in range(5):
            client.post("/api/v1/auth/login", json={
                "username": "secuser",
                "password": "WrongPassword1!",
            })

        # 6th attempt with correct password should be blocked
        resp = _login(client)
        assert resp.status_code in (401, 403, 429)


class TestSEC03_TokenSecurity:
    """SEC-03: JWT tokens are properly signed and validated."""

    def test_no_token_rejected(self, client):
        _create_user(client)
        resp = client.get("/api/v1/auth/profile")
        assert resp.status_code == 401

    def test_forged_token_rejected(self, client):
        resp = client.get("/api/v1/auth/profile",
                          headers=_auth("forged.token.here"))
        assert resp.status_code in (401, 422)

    def test_valid_token_accepted(self, client):
        _create_user(client)
        token = _login(client).json["access_token"]
        resp = client.get("/api/v1/auth/profile", headers=_auth(token))
        assert resp.status_code == 200


class TestSEC04_TokenBlacklist:
    """SEC-04: Revoked tokens cannot be reused."""

    def test_token_revoked_after_logout(self, client):
        _create_user(client)
        token = _login(client).json["access_token"]

        client.post("/api/v1/auth/logout", headers=_auth(token))

        _mock_redis.get.return_value = b"revoked"
        resp = client.get("/api/v1/auth/profile", headers=_auth(token))
        assert resp.status_code == 401


class TestSEC05_RBAC:
    """SEC-05: Role-based access control is enforced."""

    def test_viewer_cannot_access_admin_endpoints(self, client):
        _create_user(client, role="viewer")
        token = _login(client).json["access_token"]
        resp = client.get("/api/v1/auth/users", headers=_auth(token))
        assert resp.status_code == 403

    def test_admin_can_access_admin_endpoints(self, client):
        _create_user(client, username="admin1", role="admin")
        token = _login(client, username="admin1").json["access_token"]
        resp = client.get("/api/v1/auth/users", headers=_auth(token))
        assert resp.status_code == 200


class TestSEC06_InputValidation:
    """SEC-06: All inputs are validated against injection."""

    @pytest.mark.parametrize("payload", [
        {"username": "'; DROP TABLE users; --", "email": "x@x.com",
         "password": VALID_PASSWORD, "role": "viewer"},
        {"username": "<script>alert(1)</script>", "email": "x@x.com",
         "password": VALID_PASSWORD, "role": "viewer"},
        {"username": "test", "email": "not-an-email",
         "password": VALID_PASSWORD, "role": "viewer"},
    ])
    def test_malicious_input_rejected(self, client, payload):
        resp = client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 400


class TestSEC07_AccountStatus:
    """SEC-07: Inactive/suspended accounts cannot authenticate."""

    def test_suspended_user_blocked(self, client):
        _create_user(client)
        with app.app_context():
            user = User.query.filter_by(username="secuser").first()
            user.status = UserStatus.SUSPENDED
            db.session.commit()

        resp = _login(client)
        assert resp.status_code == 403

    def test_inactive_user_blocked(self, client):
        _create_user(client)
        with app.app_context():
            user = User.query.filter_by(username="secuser").first()
            user.status = UserStatus.INACTIVE
            db.session.commit()

        resp = _login(client)
        assert resp.status_code == 403


class TestSEC08_PasswordNotLeaked:
    """SEC-08: Password hashes are never returned in API responses."""

    def test_register_response_excludes_password(self, client):
        resp = _create_user(client)
        body = resp.json
        assert "password" not in json.dumps(body)
        assert "password_hash" not in json.dumps(body)

    def test_profile_excludes_password(self, client):
        _create_user(client)
        token = _login(client).json["access_token"]
        resp = client.get("/api/v1/auth/profile", headers=_auth(token))
        body = resp.json
        assert "password" not in json.dumps(body)
        assert "password_hash" not in json.dumps(body)

    def test_user_list_excludes_password(self, client):
        _create_user(client, username="admin1", role="admin")
        _create_user(client, username="viewer1", role="viewer")
        token = _login(client, username="admin1").json["access_token"]
        resp = client.get("/api/v1/auth/users", headers=_auth(token))
        body_str = json.dumps(resp.json)
        assert "password_hash" not in body_str


class TestSEC09_DuplicateAccounts:
    """SEC-09: Duplicate usernames and emails are rejected."""

    def test_duplicate_username(self, client):
        _create_user(client, username="dup")
        resp = _create_user(client, username="dup")
        assert resp.status_code == 409

    def test_duplicate_email(self, client):
        resp1 = client.post("/api/v1/auth/register", json={
            "username": "user1", "email": "same@test.local",
            "password": VALID_PASSWORD, "role": "viewer",
        })
        assert resp1.status_code == 201

        resp2 = client.post("/api/v1/auth/register", json={
            "username": "user2", "email": "same@test.local",
            "password": VALID_PASSWORD, "role": "viewer",
        })
        assert resp2.status_code == 409


class TestSEC10_PasswordChangeAuth:
    """SEC-10: Password change requires current password verification."""

    def test_wrong_current_password_rejected(self, client):
        _create_user(client)
        token = _login(client).json["access_token"]
        resp = client.put("/api/v1/auth/change-password",
                          headers=_auth(token),
                          json={"current_password": "Wrong@Pass1",
                                "new_password": "NewSecure@2"})
        assert resp.status_code == 401

    def test_correct_current_password_accepted(self, client):
        _create_user(client)
        token = _login(client).json["access_token"]
        resp = client.put("/api/v1/auth/change-password",
                          headers=_auth(token),
                          json={"current_password": VALID_PASSWORD,
                                "new_password": "NewSecure@2"})
        assert resp.status_code == 200
