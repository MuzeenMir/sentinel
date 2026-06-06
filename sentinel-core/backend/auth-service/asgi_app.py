"""FastAPI application for the auth-service migration."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import app as flask_auth


asgi = FastAPI(title="SENTINEL Auth Service")
logger = logging.getLogger(__name__)


@asgi.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@asgi.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready"}


@asgi.post("/api/v1/auth/register")
async def register(request: Request) -> JSONResponse:
    try:
        data: dict[str, Any] | None = await request.json()
    except ValueError:
        data = None

    with flask_auth.app.app_context():
        try:
            if not data:
                return JSONResponse({"error": "Missing required field: username"}, 400)

            required_fields = ["username", "email", "password", "role"]
            for field in required_fields:
                if field not in data:
                    return JSONResponse(
                        {"error": f"Missing required field: {field}"}, 400
                    )

            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, data["email"]):
                return JSONResponse({"error": "Invalid email format"}, 400)

            if not re.match(r"^[a-zA-Z0-9_]{3,50}$", data["username"]):
                return JSONResponse(
                    {
                        "error": "Username must be 3-50 characters, alphanumeric and underscores only"
                    },
                    400,
                )

            existing_user = flask_auth.User.query.filter(
                (flask_auth.User.username == data["username"])
                | (flask_auth.User.email == data["email"])
            ).first()
            if existing_user:
                return JSONResponse({"error": "Username or email already exists"}, 409)

            user = flask_auth.User(
                username=data["username"],
                email=data["email"],
                role=getattr(
                    flask_auth.UserRole,
                    data["role"].upper(),
                    flask_auth.UserRole.SECURITY_ANALYST,
                ),
                status=flask_auth.UserStatus.ACTIVE,
                tenant_id=flask_auth._default_tenant_id(),
            )

            try:
                user.set_password(data["password"])
            except ValueError:
                return JSONResponse(
                    {
                        "error": "Password does not meet security requirements",
                        "requirements": [
                            "Minimum 8 characters",
                            "At least one uppercase letter",
                            "At least one lowercase letter",
                            "At least one number",
                            'At least one special character (!@#$%^&*(),.?":{}|<>)',
                        ],
                    },
                    400,
                )

            flask_auth.db.session.add(user)
            flask_auth.db.session.flush()
            try:
                flask_auth.audit_log(
                    flask_auth.AuditCategory.AUTH,
                    "user_registered",
                    actor=f"user:{user.id}",
                    tenant_id=flask_auth._audit_tenant_id(user.tenant_id),
                    detail={"username": user.username, "role": user.role.value},
                )
            except flask_auth.AuditLogError:
                flask_auth.db.session.rollback()
                logger.exception("Audit failure blocked user registration")
                return JSONResponse({"error": "Audit log unavailable"}, 500)

            flask_auth.db.session.commit()
            logger.info("New user registered: %s", user.username)
            return JSONResponse(
                {"message": "User registered successfully", "user": user.to_dict()},
                201,
            )
        except Exception as exc:
            flask_auth.db.session.rollback()
            logger.error("Registration error: %s", exc)
            return JSONResponse({"error": "Internal server error"}, 500)
