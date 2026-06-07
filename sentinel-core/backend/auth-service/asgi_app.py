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


@asgi.post("/api/v1/auth/login")
async def login(request: Request) -> JSONResponse:
    try:
        try:
            data: dict[str, Any] | None = await request.json()
        except ValueError:
            data = None

        with flask_auth.app.app_context():
            if not data or "username" not in data or "password" not in data:
                return JSONResponse({"error": "Username and password required"}, 400)

            username = data["username"]
            password = data["password"]
            if not isinstance(username, str) or not isinstance(password, str):
                return JSONResponse(
                    {"error": "Username and password must be strings"}, 400
                )

            ip_addr = request.client.host if request.client else "unknown"
            rate_limit_key = f"login_attempt:{ip_addr}"
            if not flask_auth.rate_limit(rate_limit_key, limit=5, window=300):
                logger.warning("Rate limit exceeded for IP: %s", ip_addr)
                return JSONResponse(
                    {"error": "Too many login attempts. Please try again later."}, 429
                )

            user = flask_auth.User.query.filter_by(username=username).first()

            if user:
                if user.status != flask_auth.UserStatus.ACTIVE:
                    flask_auth.redis_client.incr(f"failed_login_ip:{ip_addr}")
                    flask_auth.redis_client.expire(f"failed_login_ip:{ip_addr}", 3600)
                    flask_auth._audit_fail_soft(
                        flask_auth.AuditCategory.AUTH,
                        "login_blocked_inactive",
                        actor=f"user:{username}",
                        detail={"ip": ip_addr, "status": user.status.value},
                    )
                    return JSONResponse(
                        {"error": "Account is inactive or suspended"}, 403
                    )

                if flask_auth.login_attempts_exceeded(user):
                    flask_auth.redis_client.incr(f"failed_login_ip:{ip_addr}")
                    flask_auth.redis_client.expire(f"failed_login_ip:{ip_addr}", 3600)
                    flask_auth._audit_fail_soft(
                        flask_auth.AuditCategory.AUTH,
                        "login_blocked_locked",
                        actor=f"user:{username}",
                        detail={"ip": ip_addr},
                    )
                    remaining_time = (
                        int((user.locked_until - datetime.utcnow()).total_seconds())
                        if user.locked_until
                        else 0
                    )
                    return JSONResponse(
                        {
                            "error": "Account temporarily locked due to too many failed attempts",
                            "retry_after": max(0, remaining_time),
                        },
                        403,
                    )
            else:
                flask_auth.bcrypt.checkpw(
                    password.encode("utf-8"), flask_auth.DUMMY_PASSWORD_HASH
                )

            if not user or not user.check_password(password):
                if user:
                    flask_auth.increment_failed_login(user)
                flask_auth.redis_client.incr(f"failed_login_ip:{ip_addr}")
                flask_auth.redis_client.expire(f"failed_login_ip:{ip_addr}", 3600)
                flask_auth._audit_fail_soft(
                    flask_auth.AuditCategory.AUTH,
                    "login_failed",
                    actor=f"user:{username}",
                    detail={"ip": ip_addr},
                )
                return JSONResponse({"error": "Invalid credentials"}, 401)

            try:
                flask_auth.audit_log(
                    flask_auth.AuditCategory.AUTH,
                    "login_success",
                    actor=f"user:{user.id}",
                    tenant_id=user.tenant_id,
                    detail={"username": user.username, "ip": ip_addr},
                )
            except flask_auth.AuditLogError:
                flask_auth.db.session.rollback()
                logger.exception("Audit failure blocked login")
                return JSONResponse({"error": "Audit log unavailable"}, 500)

            flask_auth.reset_login_attempts(user)

            if getattr(user, "mfa_enabled", False) and user.mfa_secret:
                import secrets as _secrets

                mfa_token = _secrets.token_urlsafe(32)
                flask_auth.redis_client.setex(
                    f"mfa_challenge:{mfa_token}", 300, str(user.id)
                )
                return JSONResponse(
                    {
                        "mfa_required": True,
                        "mfa_token": mfa_token,
                        "message": "MFA verification required",
                    },
                    200,
                )

            additional_claims = {
                "tenant_id": user.tenant_id,
                "role": user.role.value,
            }
            access_token = flask_auth.create_access_token(
                identity=str(user.id), additional_claims=additional_claims
            )
            refresh_token = flask_auth.create_refresh_token(
                identity=str(user.id), additional_claims=additional_claims
            )

            logger.info(
                "Successful login for user: %s from IP: %s", user.username, ip_addr
            )
            return JSONResponse(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": user.to_dict(),
                    "token_type": "Bearer",
                    "expires_in": int(
                        flask_auth.app.config[
                            "JWT_ACCESS_TOKEN_EXPIRES"
                        ].total_seconds()
                    ),
                },
                200,
            )
    except Exception as exc:
        logger.error("Login error: %s", exc)
        return JSONResponse({"error": "Internal server error"}, 500)
