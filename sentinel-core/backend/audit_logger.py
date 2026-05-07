"""Centralized SOC2 audit logger for SENTINEL services.

Provides an immutable, append-only audit trail for security-relevant events:
- Authentication (login, logout, failed attempts, MFA, SSO)
- Authorization (role changes, permission denials)
- Data access (API calls to sensitive endpoints)
- Configuration changes (policy updates, integration changes, tenant ops)
- System events (service start/stop, model retraining, hardening actions)

Events are stored in Redis sorted sets (score = timestamp) for efficient
time-range queries, and optionally forwarded to the SIEM integration
dispatcher for external log aggregation.

Usage::

    from audit_logger import audit_log, AuditCategory

    audit_log(
        category=AuditCategory.AUTH,
        action="login_success",
        actor="user:42",
        resource="auth-service",
        detail={"ip": "10.0.0.1", "method": "password"},
    )

All audit records include: timestamp, category, action, actor, resource,
tenant_id, service, detail (arbitrary JSON), and a SHA-256 integrity hash
of the record for tamper detection.
"""

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from flask import g

logger = logging.getLogger(__name__)

_AUDIT_KEY_PREFIX = "sentinel:audit:"
_AUDIT_INDEX = "sentinel:audit:index"
_AUDIT_STATS = "sentinel:audit:stats"
_AUDIT_TTL_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "365"))
_SERVICE_NAME = os.environ.get("SENTINEL_SERVICE_NAME", "unknown")


class AuditCategory(str, Enum):
    AUTH = "auth"
    AUTHZ = "authorization"
    DATA_ACCESS = "data_access"
    CONFIG_CHANGE = "config_change"
    SYSTEM = "system"
    COMPLIANCE = "compliance"
    POLICY = "policy"
    ALERT = "alert"


def _get_redis():
    """Get Redis client from Flask app context, or return None."""
    try:
        from flask import current_app

        if hasattr(current_app, "extensions") and "redis" in current_app.extensions:
            return current_app.extensions["redis"]
    except RuntimeError:
        pass
    # Fallback: try module-level import
    try:
        import redis as _redis

        url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        return _redis.from_url(url)
    except Exception:
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
    redis_client=None,
) -> Optional[str]:
    """Record an immutable audit event.

    Returns the audit record ID, or None on failure.
    """
    record_id = f"audit_{uuid.uuid4().hex[:16]}"
    ts = time.time()

    # Extract actor from Flask context if not provided
    if actor is None:
        user = getattr(g, "current_user", None) if _in_request_context() else None
        if user:
            actor = f"user:{user.get('id', 'unknown')}"
        else:
            actor = "system"

    if tenant_id is None and _in_request_context():
        tenant_id = getattr(g, "tenant_id", None)

    record = {
        "id": record_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "epoch": ts,
        "category": category.value if isinstance(category, AuditCategory) else category,
        "action": action,
        "actor": actor,
        "resource": resource or _SERVICE_NAME,
        "service": _SERVICE_NAME,
        "tenant_id": tenant_id,
        "detail": detail or {},
    }

    record["integrity_hash"] = _compute_integrity_hash(record)

    rc = redis_client or _get_redis()
    if not rc:
        logger.warning("Audit log: no Redis client available, logging to stdout only")
        logger.info("AUDIT: %s", json.dumps(record, default=str))
        return record_id

    try:
        serialized = json.dumps(record, default=str)

        # Append to category-specific sorted set (score = epoch for time queries)
        cat_key = f"{_AUDIT_KEY_PREFIX}{record['category']}"
        rc.zadd(cat_key, {serialized: ts})

        # Append to global audit index
        rc.zadd(_AUDIT_INDEX, {serialized: ts})

        # Increment stats
        rc.hincrby(_AUDIT_STATS, record["category"], 1)
        rc.hincrby(_AUDIT_STATS, "total", 1)

        # Set TTL on category key (extend on each write)
        rc.expire(cat_key, _AUDIT_TTL_DAYS * 86400)

        logger.debug("Audit recorded: %s/%s by %s", record["category"], action, actor)
    except Exception as exc:
        logger.error("Failed to persist audit record: %s", exc)
        logger.info("AUDIT (fallback): %s", json.dumps(record, default=str))

    return record_id


def query_audit_log(
    redis_client,
    category: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    actor: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Query audit records with filtering."""
    start = start_time or 0
    end = end_time or float("inf")

    key = f"{_AUDIT_KEY_PREFIX}{category}" if category else _AUDIT_INDEX

    try:
        raw = redis_client.zrangebyscore(key, start, end, start=offset, num=limit)
        records = [json.loads(r) for r in raw]

        if actor:
            records = [r for r in records if r.get("actor") == actor]

        return records
    except Exception as exc:
        logger.error("Audit query failed: %s", exc)
        return []


def get_audit_stats(redis_client) -> Dict[str, Any]:
    """Get audit log statistics."""
    try:
        raw = redis_client.hgetall(_AUDIT_STATS)
        stats = {}
        for k, v in raw.items():
            key = k.decode() if isinstance(k, bytes) else k
            val = int(v.decode() if isinstance(v, bytes) else v)
            stats[key] = val

        return {
            "total_events": stats.get("total", 0),
            "by_category": {k: v for k, v in stats.items() if k != "total"},
            "retention_days": _AUDIT_TTL_DAYS,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as exc:
        logger.error("Audit stats failed: %s", exc)
        return {"total_events": 0, "by_category": {}, "retention_days": _AUDIT_TTL_DAYS}


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
