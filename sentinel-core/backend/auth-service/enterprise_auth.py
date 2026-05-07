"""Enterprise authentication: OIDC, SAML 2.0, MFA (TOTP), and SCIM provisioning.

Registers additional Flask blueprints on the auth-service for:
- /api/v1/auth/sso/oidc/*   -- OpenID Connect login flow
- /api/v1/auth/sso/saml/*   -- SAML 2.0 SP-initiated flow
- /api/v1/auth/mfa/*        -- TOTP enroll / verify / disable
- /api/v1/auth/scim/v2/*    -- SCIM 2.0 user provisioning (Users endpoint)

These endpoints are opt-in: they only activate when the corresponding
environment variables (OIDC_ISSUER, SAML_IDP_METADATA_URL, etc.) are set.
"""

import hashlib
import json
import logging
import os
import secrets
from datetime import datetime
from urllib.parse import urlencode

import bcrypt
import pyotp
from flask import Blueprint, jsonify, redirect, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)

logger = logging.getLogger(__name__)

# Late-bound references to app.py models — set by register_enterprise_auth()
_db = None
_User = None
_UserRole = None
_UserStatus = None

# SSO group→role mapping (JSON env var: {"admins": "admin", "analysts": "security_analyst"})
SSO_GROUP_ROLE_MAP = json.loads(os.environ.get("SSO_GROUP_ROLE_MAP", "{}"))
SCIM_BEARER_TOKEN = os.environ.get("SCIM_BEARER_TOKEN")


def _map_role_from_groups(groups: list) -> str:
    """Map IdP groups to Sentinel role via SSO_GROUP_ROLE_MAP."""
    for group in groups:
        if group in SSO_GROUP_ROLE_MAP:
            return SSO_GROUP_ROLE_MAP[group]
    return "viewer"


def _find_or_create_sso_user(
    email: str, name: str, groups: list = None, tenant_id=None
):
    """Find existing user by email or create via JIT provisioning."""
    user = _User.query.filter_by(email=email).first()
    if user:
        return user

    role_str = _map_role_from_groups(groups or [])
    role = getattr(_UserRole, role_str.upper(), _UserRole.VIEWER)

    username = email.split("@")[0]
    # Ensure unique username
    base = username
    counter = 1
    while _User.query.filter_by(username=username).first():
        username = f"{base}_{counter}"
        counter += 1

    user = _User(
        username=username,
        email=email,
        role=role,
        status=_UserStatus.ACTIVE,
        tenant_id=tenant_id,
        password_hash=bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt()).decode(
            "utf-8"
        ),
    )
    _db.session.add(user)
    _db.session.commit()
    logger.info("JIT provisioned SSO user: %s (%s)", username, email)
    return user


def _issue_sentinel_tokens(user):
    """Issue Sentinel JWT access + refresh tokens for a user."""
    additional_claims = {
        "tenant_id": user.tenant_id,
        "role": user.role.value,
    }
    access_token = create_access_token(
        identity=str(user.id), additional_claims=additional_claims
    )
    refresh_token = create_refresh_token(
        identity=str(user.id), additional_claims=additional_claims
    )
    user.last_login = datetime.utcnow()
    _db.session.commit()
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict(),
        "token_type": "Bearer",
    }


# ── OIDC Blueprint ───────────────────────────────────────────────────

oidc_bp = Blueprint("oidc", __name__, url_prefix="/api/v1/auth/sso/oidc")

OIDC_ISSUER = os.environ.get("OIDC_ISSUER")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI")
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid email profile")

_oidc_metadata: dict | None = None


def _get_oidc_metadata() -> dict | None:
    global _oidc_metadata
    if _oidc_metadata:
        return _oidc_metadata
    if not OIDC_ISSUER:
        return None
    try:
        import requests as req

        well_known = f"{OIDC_ISSUER.rstrip('/')}/.well-known/openid-configuration"
        resp = req.get(well_known, timeout=10)
        resp.raise_for_status()
        _oidc_metadata = resp.json()
        return _oidc_metadata
    except Exception as exc:
        logger.error("Failed to fetch OIDC metadata from %s: %s", OIDC_ISSUER, exc)
        return None


@oidc_bp.route("/login", methods=["GET"])
def oidc_login():
    """Redirect to the OIDC provider's authorization endpoint."""
    meta = _get_oidc_metadata()
    if not meta:
        return jsonify({"error": "OIDC not configured"}), 501

    state = secrets.token_urlsafe(32)

    params = {
        "client_id": OIDC_CLIENT_ID,
        "response_type": "code",
        "scope": OIDC_SCOPES,
        "redirect_uri": OIDC_REDIRECT_URI,
        "state": state,
    }
    auth_url = f"{meta['authorization_endpoint']}?{urlencode(params)}"
    return jsonify({"redirect_url": auth_url, "state": state}), 200


@oidc_bp.route("/callback", methods=["POST"])
def oidc_callback():
    """Exchange the authorization code for tokens, JIT-provision user, issue Sentinel JWT."""
    meta = _get_oidc_metadata()
    if not meta:
        return jsonify({"error": "OIDC not configured"}), 501

    data = request.get_json() or {}
    code = data.get("code")
    if not code:
        return jsonify({"error": "Authorization code required"}), 400

    try:
        import requests as req

        token_resp = req.post(
            meta["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": OIDC_REDIRECT_URI,
                "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET,
            },
            timeout=10,
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

        userinfo_resp = req.get(
            meta["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()

        email = userinfo.get("email")
        if not email:
            return jsonify({"error": "Email not provided by OIDC provider"}), 400

        groups = userinfo.get("groups", [])
        user = _find_or_create_sso_user(email, userinfo.get("name", ""), groups)
        result = _issue_sentinel_tokens(user)
        result["provider"] = "oidc"
        return jsonify(result), 200

    except Exception as exc:
        logger.error("OIDC callback failed: %s", exc)
        return jsonify({"error": "OIDC authentication failed"}), 401


@oidc_bp.route("/status", methods=["GET"])
def oidc_status():
    return jsonify({"enabled": OIDC_ISSUER is not None, "issuer": OIDC_ISSUER}), 200


# ── SAML Blueprint ───────────────────────────────────────────────────

saml_bp = Blueprint("saml", __name__, url_prefix="/api/v1/auth/sso/saml")

SAML_IDP_METADATA_URL = os.environ.get("SAML_IDP_METADATA_URL")
SAML_SP_ENTITY_ID = os.environ.get(
    "SAML_SP_ENTITY_ID", "https://sentinel.local/saml/metadata"
)
SAML_SP_ACS_URL = os.environ.get("SAML_SP_ACS_URL")
SAML_SP_CERT = os.environ.get("SAML_SP_CERT", "")
SAML_SP_KEY = os.environ.get("SAML_SP_KEY", "")
SAML_GROUP_ATTR = os.environ.get("SAML_GROUP_ATTR", "groups")


def _build_saml_settings() -> dict:
    """Build python3-saml settings dict from environment."""
    return {
        "strict": True,
        "debug": os.environ.get("SAML_DEBUG", "false").lower() == "true",
        "sp": {
            "entityId": SAML_SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": SAML_SP_ACS_URL
                or "https://sentinel.local/api/v1/auth/sso/saml/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "x509cert": SAML_SP_CERT,
            "privateKey": SAML_SP_KEY,
        },
        "idp": {
            "entityId": "",
            "singleSignOnService": {
                "url": "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": "",
        },
        "security": {
            "authnRequestsSigned": bool(SAML_SP_CERT),
            "wantAssertionsSigned": True,
            "wantNameIdEncrypted": False,
        },
    }


def _get_saml_auth():
    """Create a OneLogin_Saml2_Auth instance for the current request."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

    settings = _build_saml_settings()

    # Merge IdP metadata from URL
    if SAML_IDP_METADATA_URL:
        idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(SAML_IDP_METADATA_URL)
        settings = OneLogin_Saml2_IdPMetadataParser.merge_settings(settings, idp_data)

    # Prepare request data for python3-saml
    req_data = {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }

    return OneLogin_Saml2_Auth(req_data, settings)


@saml_bp.route("/login", methods=["GET"])
def saml_login():
    """Initiate SP-initiated SAML login — redirect to IdP."""
    if not SAML_IDP_METADATA_URL:
        return jsonify({"error": "SAML not configured"}), 501

    try:
        auth = _get_saml_auth()
        sso_url = auth.login()
        return redirect(sso_url)
    except Exception as exc:
        logger.error("SAML login initiation failed: %s", exc)
        return jsonify({"error": "SAML login failed", "details": str(exc)}), 500


@saml_bp.route("/acs", methods=["POST"])
def saml_acs():
    """Assertion Consumer Service -- validate SAML response and issue Sentinel JWT."""
    if not SAML_IDP_METADATA_URL:
        return jsonify({"error": "SAML not configured"}), 501

    try:
        auth = _get_saml_auth()
        auth.process_response()

        errors = auth.get_errors()
        if errors:
            logger.error(
                "SAML validation errors: %s (reason: %s)",
                errors,
                auth.get_last_error_reason(),
            )
            return jsonify(
                {
                    "error": "SAML validation failed",
                    "details": errors,
                    "reason": auth.get_last_error_reason(),
                }
            ), 401

        if not auth.is_authenticated():
            return jsonify({"error": "SAML authentication failed"}), 401

        attrs = auth.get_attributes()
        name_id = auth.get_nameid()

        email = (
            attrs.get("email", [None])[0]
            or attrs.get(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                [None],
            )[0]
            or name_id
        )
        name = (
            attrs.get("displayName", [None])[0]
            or attrs.get(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", [""]
            )[0]
        )
        groups = attrs.get(SAML_GROUP_ATTR, [])

        if not email:
            return jsonify({"error": "Email not provided in SAML assertion"}), 400

        user = _find_or_create_sso_user(email, name, groups)
        result = _issue_sentinel_tokens(user)
        result["provider"] = "saml"
        return jsonify(result), 200

    except ImportError:
        logger.error("python3-saml not installed")
        return jsonify({"error": "SAML support requires python3-saml"}), 501
    except Exception as exc:
        logger.error("SAML ACS failed: %s", exc)
        return jsonify(
            {"error": "SAML authentication failed", "details": str(exc)}
        ), 401


@saml_bp.route("/metadata", methods=["GET"])
def saml_metadata():
    """Return SP metadata XML for IdP configuration."""
    metadata_xml = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{SAML_SP_ENTITY_ID}">
  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{SAML_SP_ACS_URL or 'https://sentinel.local/api/v1/auth/sso/saml/acs'}"
        index="0"
        isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""
    return metadata_xml, 200, {"Content-Type": "application/xml"}


@saml_bp.route("/status", methods=["GET"])
def saml_status():
    return jsonify({"enabled": SAML_IDP_METADATA_URL is not None}), 200


# ── MFA Blueprint (TOTP) ────────────────────────────────────────────

mfa_bp = Blueprint("mfa", __name__, url_prefix="/api/v1/auth/mfa")


def _get_current_user():
    """Get the current authenticated user from JWT."""
    user_id = get_jwt_identity()
    try:
        return _User.query.get(int(user_id))
    except (TypeError, ValueError):
        return _User.query.get(user_id)


@mfa_bp.route("/enroll", methods=["POST"])
@jwt_required()
def mfa_enroll():
    """Generate a TOTP secret, persist in DB, return provisioning URI."""
    user = _get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    # Persist secret in user record
    user.mfa_secret = secret
    _db.session.commit()

    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="SENTINEL")

    return jsonify(
        {
            "provisioning_uri": provisioning_uri,
            "message": "Scan the QR code with your authenticator app, then verify with /api/v1/auth/mfa/verify",
        }
    ), 200


@mfa_bp.route("/verify", methods=["POST"])
@jwt_required()
def mfa_verify():
    """Verify a TOTP code against the user's stored secret. Enables MFA on success."""
    user = _get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.mfa_secret:
        return jsonify({"error": "MFA not enrolled. Call /enroll first"}), 400

    data = request.get_json() or {}
    code = data.get("code")
    if not code:
        return jsonify({"error": "code required"}), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code, valid_window=1):
        user.mfa_enabled = True
        _db.session.commit()
        return jsonify(
            {
                "valid": True,
                "message": "MFA verification successful, MFA is now enabled",
            }
        ), 200
    return jsonify({"valid": False, "error": "Invalid or expired TOTP code"}), 401


@mfa_bp.route("/disable", methods=["POST"])
@jwt_required()
def mfa_disable():
    """Disable MFA. Requires current TOTP code for confirmation."""
    user = _get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.mfa_enabled:
        return jsonify({"error": "MFA is not enabled"}), 400

    data = request.get_json() or {}
    code = data.get("code")
    if not code:
        return jsonify({"error": "Current TOTP code required to disable MFA"}), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid TOTP code"}), 401

    user.mfa_secret = None
    user.mfa_enabled = False
    user.mfa_backup_codes = None
    _db.session.commit()
    return jsonify({"message": "MFA disabled successfully"}), 200


@mfa_bp.route("/backup-codes", methods=["POST"])
@jwt_required()
def mfa_backup_codes():
    """Generate 10 backup codes. Returns plaintext once; hashes stored in DB."""
    user = _get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.mfa_enabled:
        return jsonify({"error": "MFA must be enabled first"}), 400

    codes = [secrets.token_hex(4).upper() for _ in range(10)]
    hashed = [hashlib.sha256(c.encode()).hexdigest() for c in codes]
    user.mfa_backup_codes = json.dumps(hashed)
    _db.session.commit()

    return jsonify(
        {
            "backup_codes": codes,
            "message": "Store these codes safely. They will not be shown again.",
        }
    ), 200


@mfa_bp.route("/status", methods=["GET"])
@jwt_required()
def mfa_status():
    user = _get_current_user()
    if not user:
        return jsonify({"enabled": False, "method": "totp"}), 200
    return jsonify(
        {
            "enabled": bool(user.mfa_enabled),
            "enrolled": bool(user.mfa_secret),
            "method": "totp",
            "has_backup_codes": bool(user.mfa_backup_codes),
        }
    ), 200


# ── SCIM 2.0 Blueprint ──────────────────────────────────────────────

scim_bp = Blueprint("scim", __name__, url_prefix="/api/v1/auth/scim/v2")


def _scim_auth_required(f):
    """Validate SCIM bearer token from Authorization header."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not SCIM_BEARER_TOKEN:
            return jsonify(
                {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "detail": "SCIM not configured (SCIM_BEARER_TOKEN not set)",
                    "status": "501",
                }
            ), 501

        auth_header = request.headers.get("Authorization", "")
        if (
            not auth_header.startswith("Bearer ")
            or auth_header[7:] != SCIM_BEARER_TOKEN
        ):
            return jsonify(
                {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "detail": "Invalid or missing SCIM bearer token",
                    "status": "401",
                }
            ), 401

        return f(*args, **kwargs)

    return decorated


def _user_to_scim(user) -> dict:
    """Convert a User model instance to SCIM 2.0 resource format."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(user.id),
        "userName": user.username,
        "displayName": user.username,
        "emails": [{"value": user.email, "primary": True}] if user.email else [],
        "active": user.status.value == "active",
        "meta": {
            "resourceType": "User",
            "created": user.created_at.isoformat() if user.created_at else None,
        },
    }


@scim_bp.route("/Users", methods=["GET"])
@_scim_auth_required
def scim_list_users():
    """SCIM 2.0 ListUsers endpoint."""
    start_index = request.args.get("startIndex", 1, type=int)
    count = request.args.get("count", 100, type=int)

    users = (
        _User.query.filter(_User.status == _UserStatus.ACTIVE)
        .offset(start_index - 1)
        .limit(count)
        .all()
    )

    total = _User.query.filter(_User.status == _UserStatus.ACTIVE).count()

    return jsonify(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "startIndex": start_index,
            "itemsPerPage": count,
            "Resources": [_user_to_scim(u) for u in users],
        }
    ), 200


@scim_bp.route("/Users", methods=["POST"])
@_scim_auth_required
def scim_create_user():
    """SCIM 2.0 CreateUser endpoint — provisions user in Sentinel DB."""
    data = request.get_json() or {}
    schemas = data.get("schemas", [])

    if "urn:ietf:params:scim:schemas:core:2.0:User" not in schemas:
        return jsonify(
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "Invalid schema",
                "status": "400",
            }
        ), 400

    username = data.get("userName")
    if not username:
        return jsonify(
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "userName required",
                "status": "400",
            }
        ), 400

    email = None
    emails = data.get("emails", [])
    if emails:
        email = emails[0].get("value")

    # Check for existing user
    existing = _User.query.filter(
        (_User.username == username) | (_User.email == email)
    ).first()
    if existing:
        return jsonify(
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "User already exists",
                "status": "409",
            }
        ), 409

    user = _User(
        username=username,
        email=email or f"{username}@scim.provisioned",
        role=_UserRole.VIEWER,
        status=_UserStatus.ACTIVE,
        password_hash=bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt()).decode(
            "utf-8"
        ),
    )
    _db.session.add(user)
    _db.session.commit()
    logger.info("SCIM provisioned user: %s", username)

    return jsonify(_user_to_scim(user)), 201


@scim_bp.route("/Users/<user_id>", methods=["GET"])
@_scim_auth_required
def scim_get_user(user_id: str):
    """SCIM 2.0 GetUser endpoint."""
    try:
        user = _User.query.get(int(user_id))
    except (TypeError, ValueError):
        user = None

    if not user:
        return jsonify(
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "User not found",
                "status": "404",
            }
        ), 404

    return jsonify(_user_to_scim(user)), 200


@scim_bp.route("/Users/<user_id>", methods=["PUT"])
@_scim_auth_required
def scim_update_user(user_id: str):
    """SCIM 2.0 ReplaceUser endpoint."""
    try:
        user = _User.query.get(int(user_id))
    except (TypeError, ValueError):
        user = None

    if not user:
        return jsonify(
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": "User not found",
                "status": "404",
            }
        ), 404

    data = request.get_json() or {}

    if "userName" in data:
        user.username = data["userName"]
    emails = data.get("emails", [])
    if emails:
        user.email = emails[0].get("value", user.email)
    if "active" in data:
        user.status = _UserStatus.ACTIVE if data["active"] else _UserStatus.INACTIVE

    _db.session.commit()
    return jsonify(_user_to_scim(user)), 200


@scim_bp.route("/Users/<user_id>", methods=["DELETE"])
@_scim_auth_required
def scim_delete_user(user_id: str):
    """SCIM 2.0 DeleteUser (deactivate) endpoint."""
    try:
        user = _User.query.get(int(user_id))
    except (TypeError, ValueError):
        user = None

    if not user:
        return "", 404

    user.status = _UserStatus.INACTIVE
    _db.session.commit()
    logger.info("SCIM deactivated user: %s", user.username)
    return "", 204


@scim_bp.route("/ServiceProviderConfig", methods=["GET"])
def scim_service_provider_config():
    """SCIM 2.0 ServiceProviderConfig discovery."""
    return jsonify(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": False},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": True},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Authentication via OAuth 2.0 Bearer Token",
                }
            ],
        }
    ), 200


# ── Registration helper ──────────────────────────────────────────────


def register_enterprise_auth(app):
    """Register all enterprise auth blueprints on the Flask app.

    Accepts the Flask app to late-bind DB/model references from app.py,
    avoiding circular imports.
    """
    global _db, _User, _UserRole, _UserStatus

    # Import from the app module that called us
    from app import db, User, UserRole, UserStatus

    _db = db
    _User = User
    _UserRole = UserRole
    _UserStatus = UserStatus

    app.register_blueprint(oidc_bp)
    app.register_blueprint(saml_bp)
    app.register_blueprint(mfa_bp)
    app.register_blueprint(scim_bp)
    logger.info(
        "Enterprise auth registered: OIDC=%s SAML=%s MFA=enabled SCIM=%s",
        "enabled" if OIDC_ISSUER else "disabled",
        "enabled" if SAML_IDP_METADATA_URL else "disabled",
        "enabled" if SCIM_BEARER_TOKEN else "disabled",
    )
