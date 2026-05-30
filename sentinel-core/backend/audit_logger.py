"""Centralized SOC2 audit logger for SENTINEL services (T-031: PG-only).

Provides an immutable, append-only audit trail for security-relevant events:
- Authentication (login, logout, failed attempts, MFA, SSO)
- Authorization (role changes, permission denials)
- Data access (API calls to sensitive endpoints)
- Configuration changes (policy updates, integration changes, tenant ops)
- System events (service start/stop, model retraining, hardening actions)

Events are stored in the PostgreSQL ``audit_log`` table, protected at the
role level by the ``sentinel_app`` REVOKE matrix (``INSERT, SELECT`` only;
``UPDATE, DELETE, TRUNCATE`` revoked). This is the only audit storage
surface; Redis is no longer used for the shared audit logger.

Failure-mode note: audit rows are committed in their own psycopg2 transaction,
separate from any caller's SQLAlchemy session. An audit row may exist for an
action whose subsequent durable commit failed. This is intentional: the
append-only audit ledger records intent. Callers MUST audit BEFORE committing
the act (audit-then-act ordering) so any persisted state change is preceded by
an audit row; the inverse is acceptable.

Usage::

    from audit_logger import audit_log, AuditCategory, AuditLogError

    audit_log(
        category=AuditCategory.AUTH,
        action="login_success",
        actor="user:42",
        tenant_id=7,
        resource="auth-service",
        detail={"ip": "10.0.0.1", "method": "password"},
    )
"""

import hashlib
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from flask import g

logger = logging.getLogger(__name__)

_AUDIT_TTL_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "365"))
_SERVICE_NAME = os.environ.get("SENTINEL_SERVICE_NAME", "unknown")

_SENSITIVE_KEYS = re.compile(
    r"(password|token|secret|authorization|cookie|mfa|code)",
    re.I,
)


class AuditCategory(str, Enum):
    AUTH = "auth"
    AUTHZ = "authorization"
    DATA_ACCESS = "data_access"
    CONFIG_CHANGE = "config_change"
    SYSTEM = "system"
    COMPLIANCE = "compliance"
    POLICY = "policy"
    ALERT = "alert"


class AuditLogError(RuntimeError):
    """Raised when the append-only PG audit sink cannot persist an event."""


def _connect_pg():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise AuditLogError("DATABASE_URL is required for PG audit logging")
    return psycopg2.connect(url)


def _sanitize_for_failure_log(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if _SENSITIVE_KEYS.search(str(key))
            else _sanitize_for_failure_log(val)
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_for_failure_log(item) for item in value]
    return value


def _actor_user_id(actor: Optional[str]) -> Optional[int]:
    if not actor or not actor.startswith("user:"):
        return None
    raw = actor.split(":", 1)[1]
    return int(raw) if raw.isdigit() else None


def _default_tenant_id() -> Optional[int]:
    raw = os.environ.get("DEFAULT_TENANT_ID")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _compute_integrity_hash(record: dict) -> str:
    """Compute SHA-256 hash over the audit record for tamper detection."""
    canonical = json.dumps(record, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def audit_log(
    category: AuditCategory,
    action: str,
    actor: Optional[str] = None,
    resource: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    tenant_id: Optional[int] = None,
    redis_client=None,  # accepted + ignored for migration-window callers; remove in v2.0.0
) -> str:
    """Record an immutable audit event in PostgreSQL.

    Returns a legacy ``audit_<hex>`` record id for API compatibility.

    Raises ``AuditLogError`` if the PG sink cannot persist the event. Callers
    that need fail-soft semantics (login-deny, logout) must wrap this call.
    """
    record_id = f"audit_{uuid.uuid4().hex[:16]}"
    ts = time.time()

    if actor is None:
        user = getattr(g, "current_user", None) if _in_request_context() else None
        if user:
            actor = f"user:{user.get('id', 'unknown')}"
        else:
            actor = "system"

    if tenant_id is None and _in_request_context():
        tenant_id = getattr(g, "tenant_id", None)
    if tenant_id is None:
        tenant_id = _default_tenant_id()

    category_value = category.value if isinstance(category, AuditCategory) else category

    record = {
        "id": record_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "epoch": ts,
        "category": category_value,
        "action": action,
        "actor": actor,
        "resource": resource or _SERVICE_NAME,
        "service": _SERVICE_NAME,
        "tenant_id": tenant_id,
        "detail": detail or {},
    }
    record["integrity_hash"] = _compute_integrity_hash(record)

    details_payload: Dict[str, Any] = {
        "actor": actor,
        "service": _SERVICE_NAME,
        "detail": detail or {},
        "epoch": ts,
        "record_id": record_id,
    }

    conn = _connect_pg()
    try:
        cur = conn.cursor()
        try:
            if tenant_id is not None:
                cur.execute(
                    "SELECT set_config('app.tenant_id', %(tenant_id)s, true)",
                    {"tenant_id": str(tenant_id)},
                )
            cur.execute(
                """
                INSERT INTO audit_log (
                    tenant_id, user_id, action, category,
                    resource_type, resource_id,
                    details, timestamp, event_hash, prev_event_hash
                )
                VALUES (
                    %(tenant_id)s, %(user_id)s, %(action)s, %(category)s,
                    %(resource_type)s, %(resource_id)s,
                    %(details)s::jsonb,
                    %(timestamp)s, %(event_hash)s, NULL
                )
                """,
                {
                    "tenant_id": tenant_id,
                    "user_id": _actor_user_id(actor),
                    "action": action,
                    "category": category_value,
                    "resource_type": (
                        detail.get("resource_type")
                        if isinstance(detail, dict)
                        else None
                    ),
                    "resource_id": resource or _SERVICE_NAME,
                    "details": json.dumps(details_payload, default=str),
                    "timestamp": record["timestamp"],
                    "event_hash": record["integrity_hash"],
                },
            )
            conn.commit()
        except Exception as exc:
            conn.rollback()
            logger.error(
                "audit_log_insert_failed",
                exc_info=True,
                extra={
                    "audit_failure": True,
                    "audit_event": _sanitize_for_failure_log(record),
                },
            )
            raise AuditLogError("failed to persist audit event") from exc
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return record_id


def query_audit_log(
    category: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    actor: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    tenant_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Query audit records from PostgreSQL with filtering."""
    clamped_limit = max(1, min(limit, 1000))
    where = []
    params: Dict[str, Any] = {
        "limit": clamped_limit,
        "offset": max(0, offset),
    }

    if tenant_id is not None:
        where.append("tenant_id = %(tenant_id)s")
        params["tenant_id"] = tenant_id
    if category is not None:
        where.append("category = %(category)s")
        params["category"] = category
    if start_time is not None:
        where.append("EXTRACT(EPOCH FROM timestamp) >= %(start_time)s")
        params["start_time"] = start_time
    if end_time is not None:
        where.append("EXTRACT(EPOCH FROM timestamp) <= %(end_time)s")
        params["end_time"] = end_time
    if actor is not None:
        # Actor-only SOC lookups are intentionally not indexed in T-031. Add
        # (tenant_id, actor, timestamp DESC) or an expression index on
        # details->>'actor' only if SOC reports slow actor queries.
        where.append("details->>'actor' = %(actor)s")
        params["actor"] = actor

    where_clause = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
        SELECT id, event_id, timestamp, category, action,
               resource_type, resource_id, tenant_id, user_id,
               details, event_hash
        FROM audit_log
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT %(limit)s OFFSET %(offset)s
    """

    conn = _connect_pg()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            if tenant_id is not None:
                cur.execute(
                    "SELECT set_config('app.tenant_id', %(tenant_id)s, true)",
                    {"tenant_id": str(tenant_id)},
                )
            cur.execute(sql, params)
            rows = cur.fetchall()
        except Exception as exc:
            logger.error("audit_query_failed", exc_info=True)
            raise AuditLogError("failed to read audit_log") from exc
    finally:
        try:
            conn.close()
        except Exception:
            pass

    results: List[Dict[str, Any]] = []
    for row in rows:
        row_dict = dict(row)
        details = row_dict.get("details") or {}
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except (ValueError, TypeError):
                details = {}
        results.append(
            {
                "id": f"audit_{row_dict['event_id']}",
                "event_id": str(row_dict.get("event_id")),
                "timestamp": (
                    row_dict["timestamp"].isoformat() + "Z"
                    if hasattr(row_dict.get("timestamp"), "isoformat")
                    else row_dict.get("timestamp")
                ),
                "category": row_dict.get("category"),
                "action": row_dict.get("action"),
                "resource": row_dict.get("resource_id"),
                "tenant_id": row_dict.get("tenant_id"),
                "actor": details.get("actor"),
                "service": details.get("service"),
                "detail": details.get("detail", {}),
                "integrity_hash": row_dict.get("event_hash"),
            }
        )
    return results


def get_audit_stats(tenant_id: Optional[int] = None) -> Dict[str, Any]:
    """Get audit log statistics from PostgreSQL."""
    where = ""
    params: Dict[str, Any] = {}
    if tenant_id is not None:
        where = "WHERE tenant_id = %(tenant_id)s"
        params["tenant_id"] = tenant_id

    sql = f"""
        SELECT category, COUNT(*) AS count
        FROM audit_log
        {where}
        GROUP BY category
    """

    conn = _connect_pg()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            if tenant_id is not None:
                cur.execute(
                    "SELECT set_config('app.tenant_id', %(tenant_id)s, true)",
                    {"tenant_id": str(tenant_id)},
                )
            cur.execute(sql, params)
            rows = cur.fetchall()
        except Exception:
            logger.error("audit_stats_failed", exc_info=True)
            return {
                "total_events": 0,
                "by_category": {},
                "retention_days": _AUDIT_TTL_DAYS,
                "timestamp": datetime.utcnow().isoformat(),
            }
    finally:
        try:
            conn.close()
        except Exception:
            pass

    by_category: Dict[str, int] = {}
    total = 0
    for row in rows:
        row_dict = dict(row)
        cat = row_dict.get("category")
        cnt = int(row_dict.get("count", 0))
        if cat:
            by_category[cat] = cnt
            total += cnt

    return {
        "total_events": total,
        "by_category": by_category,
        "retention_days": _AUDIT_TTL_DAYS,
        "timestamp": datetime.utcnow().isoformat(),
    }


def verify_integrity(record: Dict[str, Any]) -> bool:
    """Verify a record's integrity hash to detect tampering."""
    stored_hash = record.pop("integrity_hash", None)
    if not stored_hash:
        return False
    computed = _compute_integrity_hash(record)
    record["integrity_hash"] = stored_hash
    return computed == stored_hash


def _in_request_context() -> bool:
    try:
        from flask import has_request_context

        return has_request_context()
    except Exception:
        return False
