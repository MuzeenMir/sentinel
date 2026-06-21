"""Unit tests for auth-service request-body validation schemas (SEC-06 / C1).

These exercise the pure-pydantic schema module in isolation (no Flask/DB
import), so they run without the full auth-service dependency tree.
"""

import os
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "auth-service"))

from schemas import (  # noqa: E402
    SCIM_USER_SCHEMA_URN,
    ScimUserCreateSchema,
    ScimUserReplaceSchema,
    UserUpdateSchema,
)


# --- UserUpdateSchema (app.py update_user) ---------------------------------


def test_user_update_normalizes_role_case():
    assert UserUpdateSchema.model_validate({"role": "ADMIN"}).role == "admin"


def test_user_update_normalizes_status_case():
    assert UserUpdateSchema.model_validate({"status": "Active"}).status == "active"


def test_user_update_rejects_unknown_role():
    with pytest.raises(ValidationError):
        UserUpdateSchema.model_validate({"role": "superadmin"})


def test_user_update_rejects_unknown_status():
    with pytest.raises(ValidationError):
        UserUpdateSchema.model_validate({"status": "deleted"})


def test_user_update_rejects_non_string_role():
    with pytest.raises(ValidationError):
        UserUpdateSchema.model_validate({"role": 1})


def test_user_update_allows_partial_body():
    payload = UserUpdateSchema.model_validate({"status": "suspended"})
    assert payload.role is None
    assert payload.status == "suspended"


# --- ScimUserCreateSchema (scim_create_user) -------------------------------


def _valid_scim_create():
    return {
        "schemas": [SCIM_USER_SCHEMA_URN],
        "userName": "alice",
        "emails": [{"value": "alice@example.com", "primary": True}],
        "active": True,
    }


def test_scim_create_valid_extracts_primary_email():
    payload = ScimUserCreateSchema.model_validate(_valid_scim_create())
    assert payload.userName == "alice"
    assert payload.primary_email() == "alice@example.com"


def test_scim_create_requires_core_user_schema_urn():
    body = _valid_scim_create()
    body["schemas"] = ["urn:something:else"]
    with pytest.raises(ValidationError):
        ScimUserCreateSchema.model_validate(body)


def test_scim_create_requires_username():
    body = _valid_scim_create()
    del body["userName"]
    with pytest.raises(ValidationError):
        ScimUserCreateSchema.model_validate(body)


def test_scim_create_rejects_blank_username():
    body = _valid_scim_create()
    body["userName"] = "   "
    with pytest.raises(ValidationError):
        ScimUserCreateSchema.model_validate(body)


def test_scim_create_rejects_malformed_emails():
    # emails as a list of bare strings (not {value: ...}) must not crash with
    # AttributeError at runtime — the schema rejects it as a 400.
    body = _valid_scim_create()
    body["emails"] = ["alice@example.com"]
    with pytest.raises(ValidationError):
        ScimUserCreateSchema.model_validate(body)


def test_scim_create_emails_optional():
    body = _valid_scim_create()
    del body["emails"]
    payload = ScimUserCreateSchema.model_validate(body)
    assert payload.primary_email() is None


# --- ScimUserReplaceSchema (scim_update_user) ------------------------------


def test_scim_replace_allows_active_only():
    payload = ScimUserReplaceSchema.model_validate({"active": False})
    assert payload.active is False
    assert payload.userName is None


def test_scim_replace_rejects_blank_username():
    with pytest.raises(ValidationError):
        ScimUserReplaceSchema.model_validate({"userName": ""})


def test_scim_replace_rejects_malformed_emails():
    with pytest.raises(ValidationError):
        ScimUserReplaceSchema.model_validate({"emails": [42]})
