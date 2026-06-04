"""FastAPI application for the API gateway."""

from __future__ import annotations

import time

import requests
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

import gateway_core as core


asgi = FastAPI(title="SENTINEL API Gateway")
asgi.add_middleware(
    CORSMiddleware,
    allow_origins=core._load_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri=core.CONFIG["REDIS_URL"],
)
asgi.state.limiter = limiter
asgi.add_middleware(SlowAPIMiddleware)


@asgi.middleware("http")
async def request_metrics(request: Request, call_next):
    """Record request counts and response duration for the ASGI runtime."""
    started_at = time.time()
    core.record_request(request.url.path, request.method)
    response = await call_next(request)
    duration = time.time() - started_at
    response.headers["X-Response-Time"] = f"{duration:.3f}s"
    core.logger.info(
        "%s %s - %s - %.3fs",
        request.method,
        request.url.path,
        response.status_code,
        duration,
    )
    return response


@asgi.exception_handler(RateLimitExceeded)
async def rate_limit_handler(
    _request: Request, _exc: RateLimitExceeded
) -> JSONResponse:
    return JSONResponse(
        {
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later.",
        },
        status_code=429,
    )


@asgi.exception_handler(404)
async def not_found(request: Request, _exc: object) -> JSONResponse:
    return JSONResponse(
        {
            "error": "Endpoint not found",
            "message": f"The requested endpoint {request.url.path} does not exist",
        },
        status_code=404,
    )


def require_current_user(request: Request) -> dict[str, object] | JSONResponse:
    """Resolve the authenticated user using gateway token semantics."""
    auth_header = request.headers.get("authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    elif request.query_params.get("token"):
        token = request.query_params.get("token")
    if not token:
        return JSONResponse({"error": "Authorization token required"}, status_code=401)

    try:
        response = requests.post(
            f"{core.CONFIG['AUTH_SERVICE_URL']}/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if response.status_code != 200:
            return JSONResponse({"error": "Invalid token"}, status_code=401)
        user_info = response.json()
        request.state.verified_token = token
        return dict(user_info["user"])
    except requests.exceptions.RequestException:
        return JSONResponse(
            {"error": "Authentication service unavailable"}, status_code=503
        )


def require_role(
    request: Request, required_role: str
) -> dict[str, object] | JSONResponse:
    """Resolve an authenticated user and require a specific role."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    if current_user.get("role") != required_role:
        return JSONResponse({"error": "Insufficient permissions"}, status_code=403)
    return current_user


def _asgi_sse_stream(channel: str, heartbeat_type: str):
    """Wrap the SSE generator so ASGI treats disconnects as clean exits."""
    try:
        yield from core._sse_pubsub_stream(channel, heartbeat_type)
    except GeneratorExit:
        return


def _forward_auth_headers(request: Request) -> dict[str, str]:
    """Return the verified bearer token for downstream requests."""
    auth_header = request.headers.get("Authorization")
    if auth_header:
        return {"Authorization": auth_header}
    verified_token = getattr(request.state, "verified_token", None)
    if verified_token:
        return {"Authorization": f"Bearer {verified_token}"}
    return {}


async def _proxy_to(
    base_url: str,
    path_suffix: str,
    request: Request,
    current_user: dict[str, object] | None = None,
) -> Response:
    """Forward an ASGI request using the gateway proxy semantics."""
    suffix = path_suffix.strip("/")
    if not core._PROXY_SUFFIX_RE.fullmatch(suffix):
        return JSONResponse({"error": "Invalid proxy path"}, status_code=400)

    clean_suffix = "/".join(token for token in suffix.split("/") if token)
    url = base_url.rstrip("/") + "/" + clean_suffix
    headers = _forward_auth_headers(request)
    if current_user and current_user.get("tenant_id"):
        headers["X-Tenant-ID"] = str(current_user["tenant_id"])

    params = dict(request.query_params)
    params.pop("token", None)
    try:
        if request.method == "GET":
            response = requests.get(url, headers=headers, params=params, timeout=30)
        elif request.method == "POST":
            response = requests.post(
                url,
                headers=headers,
                json=await _json_body(request),
                params=params,
                timeout=30,
            )
        elif request.method == "PUT":
            response = requests.put(
                url,
                headers=headers,
                json=await _json_body(request),
                timeout=30,
            )
        elif request.method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=30)
        else:
            return JSONResponse({"error": "Method not allowed"}, status_code=405)
        if not response.content:
            return Response(status_code=response.status_code)
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Backend service unavailable"}, status_code=503)


async def _json_body(request: Request) -> object | None:
    try:
        return await request.json()
    except Exception:
        return None


async def _validate_json_request(
    request: Request,
    required_fields: list[str] | None = None,
) -> JSONResponse | dict[str, object]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0]
    if content_type != "application/json":
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=400
        )

    data = await _json_body(request)
    if not isinstance(data, dict):
        return JSONResponse(
            {"error": "Content-Type must be application/json"}, status_code=400
        )

    if required_fields:
        missing = [field for field in required_fields if field not in data]
        if missing:
            return JSONResponse(
                {"error": f"Missing required fields: {', '.join(missing)}"},
                status_code=400,
            )
    return data


@asgi.get("/health")
def health_check() -> dict[str, object]:
    """Health check endpoint for the gateway."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "request_stats": core.get_request_stats(),
    }


@asgi.get("/readyz")
def readyz() -> dict[str, str]:
    """Readiness probe for the ASGI runtime."""
    return {"status": "ready"}


@asgi.post("/api/v1/auth/verify")
def auth_verify(request: Request) -> JSONResponse:
    """Verify authentication token through the auth service."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        response = requests.post(
            f"{core.CONFIG['AUTH_SERVICE_URL']}/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Auth service unavailable"}, status_code=503)


@asgi.api_route(
    "/api/v1/auth/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE"],
)
async def auth_proxy(path: str, request: Request) -> JSONResponse:
    """Proxy authentication requests to auth service."""
    if path.startswith("/") or not core._AUTH_PATH_RE.fullmatch(path):
        return JSONResponse({"error": "Invalid path"}, status_code=400)

    auth_url = f"{core.CONFIG['AUTH_SERVICE_URL']}/api/v1/auth/{path}"
    headers = {}
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header

    try:
        if request.method == "GET":
            params = dict(request.query_params)
            params.pop("token", None)
            response = requests.get(auth_url, params=params, headers=headers)
        elif request.method == "POST":
            response = requests.post(
                auth_url, json=await request.json(), headers=headers
            )
        elif request.method == "PUT":
            response = requests.put(
                auth_url, json=await request.json(), headers=headers
            )
        else:
            response = requests.delete(auth_url, headers=headers)
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Auth service unavailable"}, status_code=503)


@asgi.get("/api/v1/threats")
def get_threats(request: Request) -> JSONResponse:
    """Get detected threats."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user

    params = dict(request.query_params)
    params.pop("token", None)
    try:
        response = requests.get(
            f"{core.CONFIG['DATA_COLLECTOR_URL']}/api/v1/threats",
            headers=_forward_auth_headers(request),
            params=params,
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse(
            {"error": "Data collector service unavailable"}, status_code=503
        )


@asgi.post("/api/v1/threats")
async def create_threat(request: Request) -> JSONResponse:
    """Create a new threat (manual entry)."""
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        response = requests.post(
            f"{core.CONFIG['DATA_COLLECTOR_URL']}/api/v1/threats",
            headers=_forward_auth_headers(request),
            json=await request.json(),
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse(
            {"error": "Data collector service unavailable"}, status_code=503
        )


@asgi.get("/api/v1/threats/{threat_id}")
async def get_threat(threat_id: int, request: Request) -> Response:
    """Get specific threat details."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(
        core.CONFIG["DATA_COLLECTOR_URL"],
        f"/api/v1/threats/{threat_id}",
        request,
        current_user,
    )


@asgi.get("/api/v1/alerts")
def get_alerts(request: Request) -> JSONResponse:
    """Get system alerts."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user

    params = dict(request.query_params)
    params.pop("token", None)
    try:
        response = requests.get(
            f"{core.CONFIG['ALERT_SERVICE_URL']}/api/v1/alerts",
            headers=_forward_auth_headers(request),
            params=params,
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Alert service unavailable"}, status_code=503)


@asgi.post("/api/v1/alerts")
async def create_alert(request: Request) -> JSONResponse:
    """Create a new alert."""
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        response = requests.post(
            f"{core.CONFIG['ALERT_SERVICE_URL']}/api/v1/alerts",
            headers=_forward_auth_headers(request),
            json=await request.json(),
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Alert service unavailable"}, status_code=503)


@asgi.get("/api/v1/alerts/stats")
def get_alert_stats(request: Request) -> JSONResponse:
    """Proxy alert stats."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        response = requests.get(
            f"{core.CONFIG['ALERT_SERVICE_URL']}/api/v1/alerts/statistics",
            headers=_forward_auth_headers(request),
            params=dict(request.query_params),
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Alert service unavailable"}, status_code=503)


@asgi.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: int, request: Request) -> JSONResponse:
    """Get specific alert details."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        response = requests.get(
            f"{core.CONFIG['ALERT_SERVICE_URL']}/api/v1/alerts/{alert_id}",
            headers=_forward_auth_headers(request),
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Alert service unavailable"}, status_code=503)


@asgi.post("/api/v1/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, request: Request) -> JSONResponse:
    """Acknowledge an alert."""
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        response = requests.post(
            f"{core.CONFIG['ALERT_SERVICE_URL']}/api/v1/alerts/{alert_id}/acknowledge",
            headers=_forward_auth_headers(request),
            json=await request.json(),
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Alert service unavailable"}, status_code=503)


@asgi.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, request: Request) -> JSONResponse:
    """Resolve an alert."""
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        response = requests.post(
            f"{core.CONFIG['ALERT_SERVICE_URL']}/api/v1/alerts/{alert_id}/resolve",
            headers=_forward_auth_headers(request),
            json=await request.json(),
            params=dict(request.query_params),
            timeout=30,
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Backend service unavailable"}, status_code=503)


@asgi.put("/api/v1/alerts/{alert_id}")
async def update_alert(alert_id: int, request: Request) -> JSONResponse:
    """Update alert status."""
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        response = requests.put(
            f"{core.CONFIG['ALERT_SERVICE_URL']}/api/v1/alerts/{alert_id}",
            headers=_forward_auth_headers(request),
            json=await request.json(),
            timeout=30,
        )
        return JSONResponse(response.json(), status_code=response.status_code)
    except requests.exceptions.RequestException:
        return JSONResponse({"error": "Backend service unavailable"}, status_code=503)


@asgi.get("/api/v1/config")
def get_config(request: Request) -> JSONResponse:
    """Get system configuration."""
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        return JSONResponse(core._load_config(), status_code=200)
    except Exception:
        return JSONResponse(
            {"error": "Configuration retrieval failed"}, status_code=500
        )


@asgi.put("/api/v1/config")
async def update_config(request: Request) -> JSONResponse:
    """Update system configuration."""
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        new_config = await request.json()
        required_keys = ["ai_engine", "firewall", "monitoring"]
        for key in required_keys:
            if key not in new_config:
                return JSONResponse(
                    {"error": f"Missing configuration section: {key}"},
                    status_code=400,
                )
        core._save_config(new_config)
        return JSONResponse(
            {"message": "Configuration updated successfully"}, status_code=200
        )
    except Exception:
        return JSONResponse({"error": "Configuration update failed"}, status_code=500)


@asgi.get("/api/v1/stats")
@asgi.get("/api/v1/statistics")
def get_statistics(request: Request) -> JSONResponse:
    """Aggregate real-time statistics from downstream services."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user

    try:
        downstream = core._fetch_downstream_stats()
        stats = {
            "requests": core.get_request_stats(),
            "threats_detected": downstream.get("threats_detected", 0),
            "alerts_total": downstream.get("alerts_total", 0),
            "alerts_by_severity": downstream.get("alerts_by_severity", {}),
            "alerts_by_status": downstream.get("alerts_by_status", {}),
            "policies_total": downstream.get("policies_total", 0),
            "policies_by_action": downstream.get("policies_by_action", {}),
            "system_health": "healthy",
            "timestamp": time.time(),
        }
        return JSONResponse(stats, status_code=200)
    except RuntimeError:
        return JSONResponse(
            {"error": "Statistics service misconfigured"}, status_code=503
        )
    except Exception:
        return JSONResponse({"error": "Statistics retrieval failed"}, status_code=500)


@asgi.get("/api/v1/stream/threats", response_model=None)
def stream_threats(request: Request) -> JSONResponse | StreamingResponse:
    """Stream real-time threat events via Redis pub/sub."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    return StreamingResponse(
        _asgi_sse_stream(core.SSE_CHANNEL_THREATS, "threat_heartbeat"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@asgi.get("/api/v1/stream/alerts", response_model=None)
def stream_alerts(request: Request) -> JSONResponse | StreamingResponse:
    """Stream real-time alert events via Redis pub/sub."""
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    return StreamingResponse(
        _asgi_sse_stream(core.SSE_CHANNEL_ALERTS, "alert_heartbeat"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@asgi.get("/api/v1/policies")
async def get_policies(request: Request) -> Response:
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(
        core.CONFIG["POLICY_SERVICE_URL"],
        "/api/v1/policies",
        request,
        current_user,
    )


@asgi.get("/api/v1/policies/{policy_id}")
async def get_policy(policy_id: str, request: Request) -> Response:
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(
        core.CONFIG["POLICY_SERVICE_URL"],
        f"/api/v1/policies/{policy_id}",
        request,
        current_user,
    )


@asgi.post("/api/v1/policies")
async def create_policy(request: Request) -> Response:
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user
    validation = await _validate_json_request(
        request, ["name", "action", "source", "destination"]
    )
    if isinstance(validation, JSONResponse):
        return validation
    return await _proxy_to(
        core.CONFIG["POLICY_SERVICE_URL"],
        "/api/v1/policies",
        request,
        current_user,
    )


@asgi.put("/api/v1/policies/{policy_id}")
async def update_policy(policy_id: str, request: Request) -> Response:
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(
        core.CONFIG["POLICY_SERVICE_URL"],
        f"/api/v1/policies/{policy_id}",
        request,
        current_user,
    )


@asgi.delete("/api/v1/policies/{policy_id}")
async def delete_policy(policy_id: str, request: Request) -> Response:
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(
        core.CONFIG["POLICY_SERVICE_URL"],
        f"/api/v1/policies/{policy_id}",
        request,
        current_user,
    )


@asgi.get("/api/v1/frameworks")
async def get_frameworks(request: Request) -> Response:
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(
        core.CONFIG["COMPLIANCE_ENGINE_URL"],
        "/api/v1/frameworks",
        request,
        current_user,
    )


@asgi.get("/api/v1/frameworks/{framework_id}")
async def get_framework(framework_id: str, request: Request) -> Response:
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(
        core.CONFIG["COMPLIANCE_ENGINE_URL"],
        f"/api/v1/frameworks/{framework_id}",
        request,
        current_user,
    )


@asgi.post("/api/v1/assess")
async def compliance_assess(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["COMPLIANCE_ENGINE_URL"], "/api/v1/assess"
    )


@asgi.post("/api/v1/gap-analysis")
async def compliance_gap_analysis(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["COMPLIANCE_ENGINE_URL"],
        "/api/v1/gap-analysis",
    )


@asgi.post("/api/v1/reports")
async def compliance_reports(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["COMPLIANCE_ENGINE_URL"], "/api/v1/reports"
    )


@asgi.get("/api/v1/reports/history")
async def compliance_reports_history(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["COMPLIANCE_ENGINE_URL"],
        "/api/v1/reports/history",
    )


@asgi.post("/api/v1/map-policy")
async def compliance_map_policy(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["COMPLIANCE_ENGINE_URL"],
        "/api/v1/map-policy",
    )


@asgi.post("/api/v1/explain/detection")
async def xai_explain_detection(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["XAI_SERVICE_URL"],
        "/api/v1/explain/detection",
    )


@asgi.post("/api/v1/explain/policy")
async def xai_explain_policy(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["XAI_SERVICE_URL"],
        "/api/v1/explain/policy",
    )


@asgi.get("/api/v1/audit-trail")
async def xai_audit_trail(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["XAI_SERVICE_URL"], "/api/v1/audit-trail"
    )


@asgi.post("/api/v1/report/compliance")
async def xai_report_compliance(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["XAI_SERVICE_URL"],
        "/api/v1/report/compliance",
    )


@asgi.get("/api/v1/xai/statistics")
async def xai_statistics(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["XAI_SERVICE_URL"], "/api/v1/statistics"
    )


@asgi.post("/api/v1/detect")
async def ai_detect(request: Request) -> Response:
    return await _auth_proxy(request, core.CONFIG["AI_ENGINE_URL"], "/api/v1/detect")


@asgi.post("/api/v1/detect/batch")
async def ai_detect_batch(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["AI_ENGINE_URL"], "/api/v1/detect/batch"
    )


@asgi.post("/api/v1/decide")
async def drl_decide(request: Request) -> Response:
    return await _auth_proxy(request, core.CONFIG["DRL_ENGINE_URL"], "/api/v1/decide")


@asgi.post("/api/v1/decide/batch")
async def drl_decide_batch(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["DRL_ENGINE_URL"], "/api/v1/decide/batch"
    )


@asgi.get("/api/v1/action-space")
async def drl_action_space(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["DRL_ENGINE_URL"], "/api/v1/action-space"
    )


@asgi.get("/api/v1/state-space")
async def drl_state_space(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["DRL_ENGINE_URL"], "/api/v1/state-space"
    )


@asgi.api_route("/api/v1/hardening/scan", methods=["GET", "POST"])
async def hardening_scan(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["HARDENING_SERVICE_URL"],
        "/api/v1/hardening/scan",
    )


@asgi.get("/api/v1/hardening/posture")
async def hardening_posture(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["HARDENING_SERVICE_URL"],
        "/api/v1/hardening/posture",
    )


@asgi.get("/api/v1/hardening/remediations")
async def hardening_remediations(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["HARDENING_SERVICE_URL"],
        "/api/v1/hardening/remediations",
    )


@asgi.post("/api/v1/hardening/remediate/{check_id}")
async def hardening_remediate(check_id: str, request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["HARDENING_SERVICE_URL"],
        f"/api/v1/hardening/remediate/{check_id}",
    )


@asgi.get("/api/v1/hids/events")
async def hids_events(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["HIDS_AGENT_URL"], "/api/v1/hids/events"
    )


@asgi.get("/api/v1/hids/alerts")
async def hids_alerts(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["HIDS_AGENT_URL"], "/api/v1/hids/alerts"
    )


@asgi.get("/api/v1/hids/status")
async def hids_status(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["HIDS_AGENT_URL"], "/api/v1/hids/status"
    )


@asgi.get("/api/v1/admin/users")
async def admin_get_users(request: Request) -> Response:
    return await _role_proxy(
        request, core.CONFIG["AUTH_SERVICE_URL"], "/api/v1/auth/users"
    )


@asgi.put("/api/v1/admin/users/{user_id}")
async def admin_update_user(user_id: int, request: Request) -> Response:
    return await _role_proxy(
        request,
        core.CONFIG["AUTH_SERVICE_URL"],
        f"/api/v1/auth/users/{user_id}",
    )


@asgi.get("/api/v1/traffic")
async def get_traffic(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["DATA_COLLECTOR_URL"], "/api/v1/traffic"
    )


@asgi.get("/api/v1/tenants")
async def tenants_list(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["AUTH_SERVICE_URL"], "/api/v1/tenants"
    )


@asgi.post("/api/v1/tenants")
async def tenants_create(request: Request) -> Response:
    return await _role_proxy(
        request, core.CONFIG["AUTH_SERVICE_URL"], "/api/v1/tenants"
    )


@asgi.get("/api/v1/tenants/{tenant_pk}")
async def tenant_get(tenant_pk: int, request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["AUTH_SERVICE_URL"],
        f"/api/v1/tenants/{tenant_pk}",
    )


@asgi.put("/api/v1/tenants/{tenant_pk}")
async def tenant_update(tenant_pk: int, request: Request) -> Response:
    return await _role_proxy(
        request,
        core.CONFIG["AUTH_SERVICE_URL"],
        f"/api/v1/tenants/{tenant_pk}",
    )


@asgi.delete("/api/v1/tenants/{tenant_pk}")
async def tenant_delete(tenant_pk: int, request: Request) -> Response:
    return await _role_proxy(
        request,
        core.CONFIG["AUTH_SERVICE_URL"],
        f"/api/v1/tenants/{tenant_pk}",
    )


@asgi.api_route("/api/v1/integrations", methods=["GET", "POST"])
async def integrations(request: Request) -> Response:
    return await _auth_proxy(
        request, core.CONFIG["ALERT_SERVICE_URL"], "/api/v1/integrations"
    )


@asgi.post("/api/v1/integrations/test")
async def integrations_test(request: Request) -> Response:
    return await _auth_proxy(
        request,
        core.CONFIG["ALERT_SERVICE_URL"],
        "/api/v1/integrations/test",
    )


@asgi.get("/api/v1/audit/events")
def get_audit_events(request: Request) -> JSONResponse:
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user

    records = core.query_audit_log(
        category=request.query_params.get("category"),
        start_time=_query_float(request, "start_time"),
        end_time=_query_float(request, "end_time"),
        actor=request.query_params.get("actor"),
        limit=min(_query_int(request, "limit", 100), 1000),
        offset=_query_int(request, "offset", 0),
        tenant_id=current_user.get("tenant_id"),
    )
    return JSONResponse({"events": records, "count": len(records)}, status_code=200)


@asgi.get("/api/v1/audit/stats")
def audit_statistics(request: Request) -> JSONResponse:
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user
    return JSONResponse(
        core.get_audit_stats(tenant_id=current_user.get("tenant_id")),
        status_code=200,
    )


@asgi.post("/api/v1/audit/verify")
async def audit_verify_integrity(request: Request) -> JSONResponse:
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user
    data = await _json_body(request)
    records = data.get("records", []) if isinstance(data, dict) else []
    results = [
        {"id": record.get("id"), "valid": core.verify_integrity(record)}
        for record in records
        if isinstance(record, dict)
    ]
    return JSONResponse({"results": results, "total": len(results)}, status_code=200)


@asgi.get("/api/v1/audit/categories")
def audit_categories(request: Request) -> JSONResponse:
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user
    return JSONResponse(
        {"categories": [category.value for category in core.AuditCategory]},
        status_code=200,
    )


@asgi.get("/api/v1/test-rate-limit")
@limiter.limit("5 per minute")
def test_rate_limit(request: Request) -> dict[str, object]:
    """Test rate limiting functionality."""
    return {"message": "Rate limit test successful", "timestamp": time.time()}


async def _auth_proxy(request: Request, base_url: str, path_suffix: str) -> Response:
    current_user = require_current_user(request)
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(base_url, path_suffix, request, current_user)


async def _role_proxy(request: Request, base_url: str, path_suffix: str) -> Response:
    current_user = require_role(request, "admin")
    if isinstance(current_user, JSONResponse):
        return current_user
    return await _proxy_to(base_url, path_suffix, request, current_user)


def _query_int(request: Request, name: str, default: int) -> int:
    try:
        return int(request.query_params.get(name, default))
    except (TypeError, ValueError):
        return default


def _query_float(request: Request, name: str) -> float | None:
    value = request.query_params.get(name)
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None
