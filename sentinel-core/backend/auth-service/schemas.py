"""Request-body validation schemas for auth-service mutating routes (SEC-06).

Pure pydantic models — no Flask or DB imports — so they can be unit-tested in
isolation and reused across handlers without dragging in the full service.

The role/status allow-lists mirror ``app.UserRole`` / ``app.UserStatus`` (those
enums remain the source of truth for the persisted DB values; these frozensets
are kept in sync deliberately so this module stays import-light).
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator

VALID_ROLES = frozenset({"admin", "security_analyst", "auditor", "operator", "viewer"})
VALID_STATUSES = frozenset({"active", "inactive", "suspended"})

SCIM_USER_SCHEMA_URN = "urn:ietf:params:scim:schemas:core:2.0:User"


class UserUpdateSchema(BaseModel):
    """Body for ``PUT /api/v1/auth/users/<id>`` — partial role/status update."""

    model_config = ConfigDict(extra="ignore")

    role: Optional[str] = None
    status: Optional[str] = None

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if v.lower() not in VALID_ROLES:
            raise ValueError(f"invalid role; allowed: {sorted(VALID_ROLES)}")
        return v.lower()

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if v.lower() not in VALID_STATUSES:
            raise ValueError(f"invalid status; allowed: {sorted(VALID_STATUSES)}")
        return v.lower()


class ScimEmail(BaseModel):
    model_config = ConfigDict(extra="ignore")

    value: str
    primary: Optional[bool] = None
    type: Optional[str] = None


def _require_non_blank(v: Optional[str]) -> Optional[str]:
    if v is not None and not v.strip():
        raise ValueError("userName must be non-empty")
    return v


class ScimUserCreateSchema(BaseModel):
    """SCIM 2.0 CreateUser body."""

    model_config = ConfigDict(extra="ignore")

    schemas: list[str]
    userName: str
    emails: list[ScimEmail] = []
    active: Optional[bool] = None

    @field_validator("schemas")
    @classmethod
    def _require_core_user_schema(cls, v: list[str]) -> list[str]:
        if SCIM_USER_SCHEMA_URN not in v:
            raise ValueError("missing core User schema urn")
        return v

    @field_validator("userName")
    @classmethod
    def _non_blank_username(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("userName must be non-empty")
        return v

    def primary_email(self) -> Optional[str]:
        return self.emails[0].value if self.emails else None


class ScimUserReplaceSchema(BaseModel):
    """SCIM 2.0 ReplaceUser body — every field optional."""

    model_config = ConfigDict(extra="ignore")

    userName: Optional[str] = None
    emails: list[ScimEmail] = []
    active: Optional[bool] = None

    _validate_username = field_validator("userName")(_require_non_blank)

    def primary_email(self) -> Optional[str]:
        return self.emails[0].value if self.emails else None
