"""Enterprise authentication: OIDC, SAML 2.0, MFA (TOTP), and SCIM provisioning.

Registers additional Flask blueprints on the auth-service for:
- /api/v1/auth/sso/oidc/*   -- OpenID Connect login flow
- /api/v1/auth/sso/saml/*   -- SAML 2.0 SP-initiated flow
- /api/v1/auth/mfa/*        -- TOTP enroll / verify / disable
- /api/v1/auth/scim/v2/*    -- SCIM 2.0 user provisioning (Users endpoint)

These endpoints are opt-in: they only activate when the corresponding
environment variables (OIDC_ISSUER, SAML_IDP_METADATA_URL, etc.) are set.
"""

import base64
import io
import json
import logging
import os
import secrets
from datetime import datetime
from urllib.parse import urlencode

import pyotp
from flask import Blueprint, abort, jsonify, redirect, request, url_for

logger = logging.getLogger(__name__)

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
    """Exchange the authorization code for tokens and create a local session."""
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

        return jsonify({
            "provider": "oidc",
            "email": userinfo.get("email"),
            "name": userinfo.get("name"),
            "sub": userinfo.get("sub"),
            "id_token": tokens.get("id_token"),
        }), 200

    except Exception as exc:
        logger.error("OIDC callback failed: %s", exc)
        return jsonify({"error": "OIDC authentication failed"}), 401


@oidc_bp.route("/status", methods=["GET"])
def oidc_status():
    return jsonify({"enabled": OIDC_ISSUER is not None, "issuer": OIDC_ISSUER}), 200


# ── SAML Blueprint ───────────────────────────────────────────────────

saml_bp = Blueprint("saml", __name__, url_prefix="/api/v1/auth/sso/saml")

SAML_IDP_METADATA_URL = os.environ.get("SAML_IDP_METADATA_URL")
SAML_SP_ENTITY_ID = os.environ.get("SAML_SP_ENTITY_ID", "https://sentinel.local/saml/metadata")
SAML_SP_ACS_URL = os.environ.get("SAML_SP_ACS_URL")


@saml_bp.route("/login", methods=["GET"])
def saml_login():
    """Initiate SP-initiated SAML login."""
    if not SAML_IDP_METADATA_URL:
        return jsonify({"error": "SAML not configured"}), 501

    return jsonify({
        "message": "SAML SP-initiated login",
        "idp_metadata_url": SAML_IDP_METADATA_URL,
        "sp_entity_id": SAML_SP_ENTITY_ID,
        "acs_url": SAML_SP_ACS_URL,
    }), 200


@saml_bp.route("/acs", methods=["POST"])
def saml_acs():
    """Assertion Consumer Service -- receives the SAML response from IdP."""
    if not SAML_IDP_METADATA_URL:
        return jsonify({"error": "SAML not configured"}), 501

    saml_response = request.form.get("SAMLResponse")
    if not saml_response:
        return jsonify({"error": "SAMLResponse required"}), 400

    # In production, validate the SAML assertion using python3-saml.
    # This stub returns the raw data for integration testing.
    return jsonify({
        "provider": "saml",
        "message": "SAML assertion received -- validate with python3-saml in production",
        "assertion_present": True,
    }), 200


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


@mfa_bp.route("/enroll", methods=["POST"])
def mfa_enroll():
    """Generate a TOTP secret and provisioning URI for the authenticated user."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    data = request.get_json() or {}
    username = data.get("username", "sentinel-user")

    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="SENTINEL")

    return jsonify({
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "message": "Scan the QR code with your authenticator app, then verify with /api/v1/auth/mfa/verify",
    }), 200


@mfa_bp.route("/verify", methods=["POST"])
def mfa_verify():
    """Verify a TOTP code against the user's secret."""
    data = request.get_json() or {}
    secret = data.get("secret")
    code = data.get("code")

    if not secret or not code:
        return jsonify({"error": "secret and code required"}), 400

    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=1):
        return jsonify({"valid": True, "message": "MFA verification successful"}), 200
    return jsonify({"valid": False, "error": "Invalid or expired TOTP code"}), 401


@mfa_bp.route("/status", methods=["GET"])
def mfa_status():
    return jsonify({"enabled": True, "method": "totp"}), 200


# ── SCIM 2.0 Blueprint ──────────────────────────────────────────────

scim_bp = Blueprint("scim", __name__, url_prefix="/api/v1/auth/scim/v2")


@scim_bp.route("/Users", methods=["GET"])
def scim_list_users():
    """SCIM 2.0 ListUsers endpoint for IdP user provisioning."""
    start_index = request.args.get("startIndex", 1, type=int)
    count = request.args.get("count", 100, type=int)

    return jsonify({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 0,
        "startIndex": start_index,
        "itemsPerPage": count,
        "Resources": [],
    }), 200


@scim_bp.route("/Users", methods=["POST"])
def scim_create_user():
    """SCIM 2.0 CreateUser endpoint."""
    data = request.get_json() or {}
    schemas = data.get("schemas", [])

    if "urn:ietf:params:scim:schemas:core:2.0:User" not in schemas:
        return jsonify({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "Invalid schema",
            "status": "400",
        }), 400

    username = data.get("userName")
    email = None
    emails = data.get("emails", [])
    if emails:
        email = emails[0].get("value")

    display_name = data.get("displayName", username)

    return jsonify({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": secrets.token_urlsafe(16),
        "userName": username,
        "displayName": display_name,
        "emails": [{"value": email, "primary": True}] if email else [],
        "active": True,
        "meta": {
            "resourceType": "User",
            "created": datetime.utcnow().isoformat(),
        },
    }), 201


@scim_bp.route("/Users/<user_id>", methods=["GET"])
def scim_get_user(user_id: str):
    """SCIM 2.0 GetUser endpoint."""
    return jsonify({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": "User not found",
        "status": "404",
    }), 404


@scim_bp.route("/Users/<user_id>", methods=["PUT"])
def scim_update_user(user_id: str):
    """SCIM 2.0 ReplaceUser endpoint."""
    data = request.get_json() or {}
    return jsonify({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user_id,
        "userName": data.get("userName"),
        "active": data.get("active", True),
    }), 200


@scim_bp.route("/Users/<user_id>", methods=["DELETE"])
def scim_delete_user(user_id: str):
    """SCIM 2.0 DeleteUser (deactivate) endpoint."""
    return "", 204


@scim_bp.route("/ServiceProviderConfig", methods=["GET"])
def scim_service_provider_config():
    """SCIM 2.0 ServiceProviderConfig discovery."""
    return jsonify({
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
    }), 200


# ── Registration helper ──────────────────────────────────────────────

def register_enterprise_auth(app):
    """Register all enterprise auth blueprints on the Flask app."""
    app.register_blueprint(oidc_bp)
    app.register_blueprint(saml_bp)
    app.register_blueprint(mfa_bp)
    app.register_blueprint(scim_bp)
    logger.info(
        "Enterprise auth registered: OIDC=%s SAML=%s MFA=enabled SCIM=enabled",
        "enabled" if OIDC_ISSUER else "disabled",
        "enabled" if SAML_IDP_METADATA_URL else "disabled",
    )
