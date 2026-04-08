"""
Tests for SENTINEL Enterprise Authentication: MFA challenge flow,
OIDC/SAML status, MFA enroll/verify/disable/backup-codes, SCIM provisioning,
and Tenant CRUD.

Uses in-memory SQLite + mocked Redis. No network calls.
"""
import os
import sys
import json
import hashlib
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

# ---------------------------------------------------------------------------
# Environment setup BEFORE any app import
# ---------------------------------------------------------------------------
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-enterprise")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("ADMIN_USERNAME", "")
os.environ.setdefault("ADMIN_EMAIL", "")
os.environ.setdefault("ADMIN_PASSWORD", "")
os.environ["SCIM_BEARER_TOKEN"] = "test-scim-token-12345"

_backend_root = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(_backend_root, "auth-service"))
sys.path.insert(0, _backend_root)

# ---------------------------------------------------------------------------
# Mock Redis so module-level code never touches a real server.
# We use a dict-backed mock so the MFA challenge flow (setex/get/delete)
# works end-to-end without a live Redis.
# ---------------------------------------------------------------------------
_mock_redis = MagicMock()
_mock_redis_store: dict = {}


def _mock_get(key):
    return _mock_redis_store.get(key)


def _mock_setex(key, ttl, value):
    _mock_redis_store[key] = value.encode("utf-8") if isinstance(value, str) else value


def _mock_delete(key):
    _mock_redis_store.pop(key, None)


_mock_redis.get = MagicMock(side_effect=_mock_get)
_mock_redis.setex = MagicMock(side_effect=_mock_setex)
_mock_redis.delete = MagicMock(side_effect=_mock_delete)

# Clear any cached "app" / "enterprise_auth" modules so the import below
# registers them under the correct names and enterprise_auth's
# `from app import db, User, ...` finds the SAME SQLAlchemy instance.
for mod_name in ("app", "enterprise_auth"):
    sys.modules.pop(mod_name, None)

with patch("redis.ConnectionPool.from_url", return_value=MagicMock()), \
     patch("redis.Redis", return_value=_mock_redis):
    # Direct import so the module registers as "app" in sys.modules.
    # enterprise_auth.register_enterprise_auth() does `from app import db, User`
    # — it must find this exact module, not a separate copy.
    import app as auth_mod  # noqa: E402

app = auth_mod.app
db = auth_mod.db
User = auth_mod.User
UserRole = auth_mod.UserRole
UserStatus = auth_mod.UserStatus
Tenant = auth_mod.Tenant

VALID_PASSWORD = "Test@1234"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_db():
    app.config["TESTING"] = True
    with app.app_context():
        # SQLite doesn't support autoincrement on BigInteger; swap to Integer
        # for the test-only in-memory DB so Tenant.id auto-generates.
        from sqlalchemy import Integer as _Int
        Tenant.__table__.columns["id"].type = _Int()
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()
    _mock_redis.reset_mock()
    _mock_redis.get = MagicMock(side_effect=_mock_get)
    _mock_redis.setex = MagicMock(side_effect=_mock_setex)
    _mock_redis.delete = MagicMock(side_effect=_mock_delete)
    _mock_redis_store.clear()


@pytest.fixture
def client():
    return app.test_client()


def _create_user(role=UserRole.VIEWER, mfa=False, tenant_id=None):
    """Create a user directly in the DB and return it."""
    import bcrypt
    user = User(
        username=f"user_{id(role)}",
        email=f"user_{id(role)}@test.com",
        role=role,
        status=UserStatus.ACTIVE,
        tenant_id=tenant_id,
        password_hash=bcrypt.hashpw(VALID_PASSWORD.encode(), bcrypt.gensalt()).decode(),
    )
    if mfa:
        import pyotp
        user.mfa_secret = pyotp.random_base32()
        user.mfa_enabled = True
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, user):
    return client.post("/api/v1/auth/login", json={
        "username": user.username,
        "password": VALID_PASSWORD,
    })


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _get_admin_token(client):
    """Create an admin user, login, and return the bearer token."""
    admin = _create_user(role=UserRole.ADMIN)
    resp = _login(client, admin)
    return resp.json["access_token"]


# ===================================================================
# MFA Challenge Flow
# ===================================================================

class TestMFAChallenge:
    def test_login_returns_mfa_required_when_mfa_enabled(self, client):
        user = _create_user(mfa=True)
        resp = _login(client, user)
        assert resp.status_code == 200
        assert resp.json["mfa_required"] is True
        assert "mfa_token" in resp.json

    def test_mfa_challenge_with_valid_totp(self, client):
        import pyotp
        user = _create_user(mfa=True)
        login_resp = _login(client, user)
        mfa_token = login_resp.json["mfa_token"]

        totp = pyotp.TOTP(user.mfa_secret)
        code = totp.now()

        resp = client.post("/api/v1/auth/mfa/challenge", json={
            "mfa_token": mfa_token,
            "code": code,
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json
        assert "refresh_token" in resp.json
        assert resp.json["token_type"] == "Bearer"

    def test_mfa_challenge_with_invalid_code(self, client):
        user = _create_user(mfa=True)
        login_resp = _login(client, user)
        mfa_token = login_resp.json["mfa_token"]

        resp = client.post("/api/v1/auth/mfa/challenge", json={
            "mfa_token": mfa_token,
            "code": "000000",
        })
        assert resp.status_code == 401

    def test_mfa_challenge_with_expired_token(self, client):
        resp = client.post("/api/v1/auth/mfa/challenge", json={
            "mfa_token": "nonexistent-token",
            "code": "123456",
        })
        assert resp.status_code == 401
        assert "expired" in resp.json["error"].lower() or "invalid" in resp.json["error"].lower()

    def test_mfa_challenge_missing_fields(self, client):
        resp = client.post("/api/v1/auth/mfa/challenge", json={"mfa_token": "x"})
        assert resp.status_code == 400

    def test_mfa_challenge_with_backup_code(self, client):
        import pyotp
        user = _create_user(mfa=True)

        # Generate backup codes
        codes = ["AAAA1111", "BBBB2222", "CCCC3333"]
        hashed = [hashlib.sha256(c.encode()).hexdigest() for c in codes]
        user.mfa_backup_codes = json.dumps(hashed)
        db.session.commit()

        # Login to get mfa_token
        login_resp = _login(client, user)
        mfa_token = login_resp.json["mfa_token"]

        # Use backup code
        resp = client.post("/api/v1/auth/mfa/challenge", json={
            "mfa_token": mfa_token,
            "code": "AAAA1111",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json

        # Verify backup code was consumed
        with app.app_context():
            refreshed = User.query.get(user.id)
            remaining = json.loads(refreshed.mfa_backup_codes)
            assert hashlib.sha256(b"AAAA1111").hexdigest() not in remaining
            assert len(remaining) == 2

    def test_mfa_challenge_consumes_token(self, client):
        """After successful MFA, the same mfa_token cannot be reused."""
        import pyotp
        user = _create_user(mfa=True)
        login_resp = _login(client, user)
        mfa_token = login_resp.json["mfa_token"]

        totp = pyotp.TOTP(user.mfa_secret)
        code = totp.now()

        # First use succeeds
        resp1 = client.post("/api/v1/auth/mfa/challenge", json={
            "mfa_token": mfa_token, "code": code,
        })
        assert resp1.status_code == 200

        # Second use fails
        resp2 = client.post("/api/v1/auth/mfa/challenge", json={
            "mfa_token": mfa_token, "code": code,
        })
        assert resp2.status_code == 401


# ===================================================================
# MFA Enroll / Verify / Disable / Backup-Codes (enterprise_auth.py)
# ===================================================================

class TestMFAEndpoints:
    def _get_token(self, client, user):
        """Get a JWT for a non-MFA user."""
        resp = _login(client, user)
        return resp.json["access_token"]

    def test_enroll(self, client):
        user = _create_user()
        token = self._get_token(client, user)
        resp = client.post("/api/v1/auth/mfa/enroll",
                           headers=_auth_header(token))
        assert resp.status_code == 200
        assert "provisioning_uri" in resp.json
        assert "otpauth://" in resp.json["provisioning_uri"]

    def test_verify_enables_mfa(self, client):
        import pyotp
        user = _create_user()
        token = self._get_token(client, user)

        # Enroll
        client.post("/api/v1/auth/mfa/enroll", headers=_auth_header(token))

        # Read secret from DB
        with app.app_context():
            refreshed = User.query.get(user.id)
            secret = refreshed.mfa_secret

        totp = pyotp.TOTP(secret)
        resp = client.post("/api/v1/auth/mfa/verify",
                           headers=_auth_header(token),
                           json={"code": totp.now()})
        assert resp.status_code == 200
        assert resp.json["valid"] is True

        # Confirm mfa_enabled in DB
        with app.app_context():
            refreshed = User.query.get(user.id)
            assert refreshed.mfa_enabled is True

    def test_verify_rejects_bad_code(self, client):
        user = _create_user()
        token = self._get_token(client, user)
        client.post("/api/v1/auth/mfa/enroll", headers=_auth_header(token))

        resp = client.post("/api/v1/auth/mfa/verify",
                           headers=_auth_header(token),
                           json={"code": "000000"})
        assert resp.status_code == 401

    def test_verify_without_enroll_returns_400(self, client):
        user = _create_user()
        token = self._get_token(client, user)
        resp = client.post("/api/v1/auth/mfa/verify",
                           headers=_auth_header(token),
                           json={"code": "123456"})
        assert resp.status_code == 400

    def test_disable_requires_valid_code(self, client):
        import pyotp
        user = _create_user(mfa=True)
        # Need non-MFA login path: directly create token
        from flask_jwt_extended import create_access_token
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post("/api/v1/auth/mfa/disable",
                           headers=_auth_header(token),
                           json={"code": "000000"})
        assert resp.status_code == 401

    def test_disable_with_valid_code(self, client):
        import pyotp
        user = _create_user(mfa=True)
        from flask_jwt_extended import create_access_token
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        totp = pyotp.TOTP(user.mfa_secret)
        resp = client.post("/api/v1/auth/mfa/disable",
                           headers=_auth_header(token),
                           json={"code": totp.now()})
        assert resp.status_code == 200

        with app.app_context():
            refreshed = User.query.get(user.id)
            assert refreshed.mfa_enabled is False
            assert refreshed.mfa_secret is None

    def test_backup_codes_generation(self, client):
        import pyotp
        user = _create_user(mfa=True)
        from flask_jwt_extended import create_access_token
        with app.app_context():
            token = create_access_token(identity=str(user.id))

        resp = client.post("/api/v1/auth/mfa/backup-codes",
                           headers=_auth_header(token))
        assert resp.status_code == 200
        assert len(resp.json["backup_codes"]) == 10

        # Verify hashes stored in DB
        with app.app_context():
            refreshed = User.query.get(user.id)
            stored = json.loads(refreshed.mfa_backup_codes)
            assert len(stored) == 10
            # First code hash matches
            first_code = resp.json["backup_codes"][0]
            assert hashlib.sha256(first_code.encode()).hexdigest() == stored[0]

    def test_backup_codes_require_mfa_enabled(self, client):
        user = _create_user()
        token = _login(client, user).json["access_token"]
        resp = client.post("/api/v1/auth/mfa/backup-codes",
                           headers=_auth_header(token))
        assert resp.status_code == 400

    def test_mfa_status(self, client):
        user = _create_user()
        token = _login(client, user).json["access_token"]
        resp = client.get("/api/v1/auth/mfa/status",
                          headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json["enabled"] is False
        assert resp.json["method"] == "totp"


# ===================================================================
# OIDC / SAML status endpoints (no IdP needed)
# ===================================================================

class TestSSOStatus:
    def test_oidc_status_disabled(self, client):
        resp = client.get("/api/v1/auth/sso/oidc/status")
        assert resp.status_code == 200
        # OIDC_ISSUER not set in env
        assert resp.json["enabled"] is False

    def test_saml_status_disabled(self, client):
        resp = client.get("/api/v1/auth/sso/saml/status")
        assert resp.status_code == 200
        assert resp.json["enabled"] is False

    def test_saml_metadata_returns_xml(self, client):
        resp = client.get("/api/v1/auth/sso/saml/metadata")
        assert resp.status_code == 200
        assert b"EntityDescriptor" in resp.data

    def test_oidc_login_returns_501_when_not_configured(self, client):
        resp = client.get("/api/v1/auth/sso/oidc/login")
        assert resp.status_code == 501

    def test_saml_login_returns_501_when_not_configured(self, client):
        resp = client.get("/api/v1/auth/sso/saml/login")
        assert resp.status_code == 501


# ===================================================================
# SCIM 2.0 Provisioning
# ===================================================================

class TestSCIM:
    SCIM_HEADERS = {
        "Authorization": "Bearer test-scim-token-12345",
        "Content-Type": "application/json",
    }

    def test_list_users(self, client):
        _create_user()
        resp = client.get("/api/v1/auth/scim/v2/Users", headers=self.SCIM_HEADERS)
        assert resp.status_code == 200
        assert "Resources" in resp.json
        assert resp.json["totalResults"] >= 1

    def test_create_user(self, client):
        resp = client.post("/api/v1/auth/scim/v2/Users",
                           headers=self.SCIM_HEADERS,
                           json={
                               "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                               "userName": "scim_user",
                               "emails": [{"value": "scim@example.com", "primary": True}],
                           })
        assert resp.status_code == 201
        assert resp.json["userName"] == "scim_user"
        assert resp.json["active"] is True

    def test_create_duplicate_user_returns_409(self, client):
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "dup_user",
            "emails": [{"value": "dup@example.com"}],
        }
        client.post("/api/v1/auth/scim/v2/Users", headers=self.SCIM_HEADERS, json=payload)
        resp = client.post("/api/v1/auth/scim/v2/Users", headers=self.SCIM_HEADERS, json=payload)
        assert resp.status_code == 409

    def test_create_user_missing_username(self, client):
        resp = client.post("/api/v1/auth/scim/v2/Users",
                           headers=self.SCIM_HEADERS,
                           json={
                               "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                           })
        assert resp.status_code == 400

    def test_get_user(self, client):
        user = _create_user()
        resp = client.get(f"/api/v1/auth/scim/v2/Users/{user.id}",
                          headers=self.SCIM_HEADERS)
        assert resp.status_code == 200
        assert resp.json["id"] == str(user.id)

    def test_get_user_not_found(self, client):
        resp = client.get("/api/v1/auth/scim/v2/Users/99999",
                          headers=self.SCIM_HEADERS)
        assert resp.status_code == 404

    def test_update_user(self, client):
        user = _create_user()
        resp = client.put(f"/api/v1/auth/scim/v2/Users/{user.id}",
                          headers=self.SCIM_HEADERS,
                          json={
                              "userName": "updated_scim",
                              "active": True,
                          })
        assert resp.status_code == 200
        assert resp.json["userName"] == "updated_scim"

    def test_delete_user_deactivates(self, client):
        user = _create_user()
        resp = client.delete(f"/api/v1/auth/scim/v2/Users/{user.id}",
                             headers=self.SCIM_HEADERS)
        assert resp.status_code == 204

        with app.app_context():
            refreshed = User.query.get(user.id)
            assert refreshed.status == UserStatus.INACTIVE

    def test_unauthorized_scim_request(self, client):
        resp = client.get("/api/v1/auth/scim/v2/Users",
                          headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401

    def test_service_provider_config(self, client):
        resp = client.get("/api/v1/auth/scim/v2/ServiceProviderConfig")
        assert resp.status_code == 200
        assert "authenticationSchemes" in resp.json

    def test_invalid_schema_returns_400(self, client):
        resp = client.post("/api/v1/auth/scim/v2/Users",
                           headers=self.SCIM_HEADERS,
                           json={
                               "schemas": ["urn:wrong:schema"],
                               "userName": "bad",
                           })
        assert resp.status_code == 400


# ===================================================================
# Tenant CRUD
# ===================================================================

class TestTenantCRUD:
    def test_create_tenant(self, client):
        token = _get_admin_token(client)
        resp = client.post("/api/v1/tenants",
                           headers=_auth_header(token),
                           json={"name": "acme-corp", "plan": "enterprise"})
        assert resp.status_code == 201
        assert resp.json["tenant"]["name"] == "acme-corp"
        assert resp.json["tenant"]["plan"] == "enterprise"
        assert resp.json["tenant"]["tenant_id"]  # UUID generated

    def test_create_tenant_missing_name(self, client):
        token = _get_admin_token(client)
        resp = client.post("/api/v1/tenants",
                           headers=_auth_header(token),
                           json={})
        assert resp.status_code == 400

    def test_list_tenants(self, client):
        token = _get_admin_token(client)
        client.post("/api/v1/tenants", headers=_auth_header(token),
                    json={"name": "tenant-a"})
        client.post("/api/v1/tenants", headers=_auth_header(token),
                    json={"name": "tenant-b"})
        resp = client.get("/api/v1/tenants", headers=_auth_header(token))
        assert resp.status_code == 200
        assert len(resp.json["tenants"]) >= 2

    def test_get_tenant(self, client):
        token = _get_admin_token(client)
        create_resp = client.post("/api/v1/tenants",
                                  headers=_auth_header(token),
                                  json={"name": "get-me"})
        pk = create_resp.json["tenant"]["id"]
        resp = client.get(f"/api/v1/tenants/{pk}", headers=_auth_header(token))
        assert resp.status_code == 200
        assert resp.json["tenant"]["name"] == "get-me"

    def test_update_tenant(self, client):
        token = _get_admin_token(client)
        create_resp = client.post("/api/v1/tenants",
                                  headers=_auth_header(token),
                                  json={"name": "updatable"})
        pk = create_resp.json["tenant"]["id"]
        resp = client.put(f"/api/v1/tenants/{pk}",
                          headers=_auth_header(token),
                          json={"plan": "enterprise", "retention_days": 365})
        assert resp.status_code == 200
        assert resp.json["tenant"]["plan"] == "enterprise"
        assert resp.json["tenant"]["retention_days"] == 365

    def test_deactivate_tenant(self, client):
        token = _get_admin_token(client)
        create_resp = client.post("/api/v1/tenants",
                                  headers=_auth_header(token),
                                  json={"name": "deletable"})
        pk = create_resp.json["tenant"]["id"]
        resp = client.delete(f"/api/v1/tenants/{pk}",
                             headers=_auth_header(token))
        assert resp.status_code == 200
        assert "deactivated" in resp.json["message"].lower()

        # Deactivated tenant excluded from list
        list_resp = client.get("/api/v1/tenants", headers=_auth_header(token))
        names = [t["name"] for t in list_resp.json["tenants"]]
        assert "deletable" not in names

    def test_non_admin_cannot_create_tenant(self, client):
        user = _create_user(role=UserRole.VIEWER)
        resp = _login(client, user)
        token = resp.json["access_token"]
        resp = client.post("/api/v1/tenants",
                           headers=_auth_header(token),
                           json={"name": "nope"})
        assert resp.status_code == 403
