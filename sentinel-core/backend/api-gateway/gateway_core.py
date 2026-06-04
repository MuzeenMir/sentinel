"""Framework-agnostic helpers for the API gateway."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from collections.abc import Iterator
from typing import Any

import redis
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from audit_logger import (  # noqa: E402
    AuditCategory as AuditCategory,
    get_audit_stats as get_audit_stats,
    query_audit_log as query_audit_log,
    verify_integrity as verify_integrity,
)


CONFIG = {
    "AUTH_SERVICE_URL": os.environ.get("AUTH_SERVICE_URL", "http://auth-service:5000"),
    "DATA_COLLECTOR_URL": os.environ.get(
        "DATA_COLLECTOR_URL", "http://data-collector:5001"
    ),
    "ALERT_SERVICE_URL": os.environ.get(
        "ALERT_SERVICE_URL", "http://alert-service:5002"
    ),
    "POLICY_SERVICE_URL": os.environ.get(
        "POLICY_SERVICE_URL", "http://policy-orchestrator:5004"
    ),
    "COMPLIANCE_ENGINE_URL": os.environ.get(
        "COMPLIANCE_ENGINE_URL", "http://compliance-engine:5007"
    ),
    "XAI_SERVICE_URL": os.environ.get("XAI_SERVICE_URL", "http://xai-service:5006"),
    "AI_ENGINE_URL": os.environ.get("AI_ENGINE_URL", "http://ai-engine:5003"),
    "DRL_ENGINE_URL": os.environ.get("DRL_ENGINE_URL", "http://drl-engine:5005"),
    "HARDENING_SERVICE_URL": os.environ.get(
        "HARDENING_SERVICE_URL", "http://hardening-service:5011"
    ),
    "HIDS_AGENT_URL": os.environ.get("HIDS_AGENT_URL", "http://hids-agent:5010"),
    "REDIS_URL": os.environ.get("REDIS_URL", "redis://localhost:6379"),
}

SSE_CHANNEL_THREATS = "sentinel:sse:threats"
SSE_CHANNEL_ALERTS = "sentinel:sse:alerts"
STATS_CACHE_KEY = "sentinel:gateway:stats_cache"
STATS_CACHE_TTL = 10
CONFIG_CACHE_KEY = "sentinel:config"

_AUTH_PATH_RE = re.compile(r"[A-Za-z0-9_\-/]+")
_PROXY_SUFFIX_RE = re.compile(r"[A-Za-z0-9_\-/]+")

logger = logging.getLogger(__name__)
redis_client = redis.from_url(CONFIG["REDIS_URL"], decode_responses=True)


def get_service_url(name: str) -> str:
    """Return a configured backend service URL."""
    return CONFIG[name]


def _load_cors_origins() -> list[str]:
    """Return the explicit CORS allowlist; fail fast in production if unset."""
    origins = os.environ.get("CORS_ORIGINS", "").strip()
    if not origins:
        if os.environ.get("SENTINEL_ENV") == "production":
            raise RuntimeError("CORS_ORIGINS is required in production")
        return ["http://localhost:3000"]
    return [origin.strip() for origin in origins.split(",") if origin.strip()]


def record_request(endpoint: str, method: str) -> None:
    """Track an API request for the rolling request statistics."""
    timestamp = int(time.time())
    key = f"api_requests:{endpoint}:{method}:{timestamp}"
    redis_client.incr(key)
    redis_client.expire(key, 3600)


def get_request_stats() -> dict[str, int]:
    """Get API request statistics from the last five minutes."""
    current_time = int(time.time())
    stats: dict[str, int] = {}
    for offset in range(300):
        timestamp = current_time - offset
        for key in redis_client.scan_iter(f"api_requests:*:*:{timestamp}", count=100):
            count = redis_client.get(key)
            if count:
                parts = key.split(":")
                endpoint = f"{parts[1]}:{parts[2]}"
                stats[endpoint] = stats.get(endpoint, 0) + int(count)
    return stats


def _internal_service_headers() -> dict[str, str]:
    """Build headers for internal downstream service calls."""
    internal_service_token = os.environ.get("INTERNAL_SERVICE_TOKEN", "").strip()
    if not internal_service_token:
        raise RuntimeError(
            "INTERNAL_SERVICE_TOKEN is unset; gateway refuses to make "
            "unauthenticated downstream calls"
        )
    return {"Authorization": f"Bearer {internal_service_token}"}


def _fetch_downstream_stats() -> dict[str, Any]:
    """Aggregate real statistics from downstream services, cached briefly."""
    cached = redis_client.get(STATS_CACHE_KEY)
    if cached:
        return json.loads(cached)

    result: dict[str, Any] = {
        "threats_detected": 0,
        "alerts_total": 0,
        "alerts_by_severity": {},
        "alerts_by_status": {},
        "policies_total": 0,
        "policies_by_action": {},
    }
    headers = _internal_service_headers()

    try:
        response = requests.get(
            f"{CONFIG['ALERT_SERVICE_URL']}/api/v1/alerts/statistics",
            headers=headers,
            timeout=3,
        )
        if response.status_code == 200:
            data = response.json()
            result["alerts_total"] = data.get("total_alerts", 0)
            result["alerts_by_severity"] = data.get("by_severity", {})
            result["alerts_by_status"] = data.get("by_status", {})
    except requests.exceptions.RequestException:
        logger.debug("Alert service stats unavailable")

    try:
        response = requests.get(
            f"{CONFIG['DATA_COLLECTOR_URL']}/api/v1/threats",
            headers=headers,
            params={"limit": 1},
            timeout=3,
        )
        if response.status_code == 200:
            result["threats_detected"] = response.json().get("total", 0)
    except requests.exceptions.RequestException:
        logger.debug("Data collector stats unavailable")

    try:
        response = requests.get(
            f"{CONFIG['POLICY_SERVICE_URL']}/api/v1/statistics",
            headers=headers,
            timeout=3,
        )
        if response.status_code == 200:
            data = response.json()
            result["policies_total"] = data.get("total_policies", 0)
            result["policies_by_action"] = data.get("policies_by_action", {})
    except requests.exceptions.RequestException:
        logger.debug("Policy orchestrator stats unavailable")

    redis_client.set(STATS_CACHE_KEY, json.dumps(result), ex=STATS_CACHE_TTL)
    return result


def _default_config() -> dict[str, Any]:
    return {
        "ai_engine": {
            "model_path": "/models/current_model.pkl",
            "confidence_threshold": 0.85,
            "batch_size": 1000,
        },
        "firewall": {"max_rules": 10000, "sync_interval": 30},
        "monitoring": {"alert_threshold": 0.95, "retention_days": 90},
    }


def _load_config() -> dict[str, Any]:
    """Load config from Redis if available, else return defaults."""
    try:
        raw = redis_client.get(CONFIG_CACHE_KEY)
        if raw:
            return json.loads(raw)
    except Exception as exc:
        logger.warning("Config cache read failed: %s", exc)
    return _default_config()


def _save_config(new_config: dict[str, Any]) -> None:
    """Persist config in Redis."""
    redis_client.set(CONFIG_CACHE_KEY, json.dumps(new_config))


def _sse_pubsub_stream(channel: str, heartbeat_type: str) -> Iterator[str]:
    """Subscribe to a Redis pub/sub channel and yield SSE frames."""
    pubsub_client = redis.from_url(CONFIG["REDIS_URL"], decode_responses=True)
    pubsub = pubsub_client.pubsub()
    pubsub.subscribe(channel)
    try:
        while True:
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=15)
            if message and message["type"] == "message":
                yield f"data: {message['data']}\n\n"
            else:
                heartbeat = json.dumps(
                    {"type": heartbeat_type, "timestamp": time.time()}
                )
                yield f"data: {heartbeat}\n\n"
    finally:
        pubsub.unsubscribe(channel)
        pubsub.close()
        pubsub_client.close()
