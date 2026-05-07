"""SENTINEL Python SDK client.

Provides a high-level interface to the SENTINEL API gateway.  Handles
authentication, automatic JWT refresh, retries with exponential backoff,
and maps API responses to typed dataclass models.

Usage::

    from sentinel_sdk import SentinelClient

    with SentinelClient("https://sentinel.example.com", username="admin", password="s3cret") as client:
        client.authenticate()
        result = client.detect({"src_ip": "10.0.0.5", "dst_ip": "1.2.3.4", ...})
        threats = client.get_threats(severity="high", limit=10)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter, Retry

from sdk.exceptions import (
    APIError,
    AuthenticationError,
    RateLimitError,
    SentinelError,
    ValidationError,
)
from sdk.models import (
    Alert,
    Assessment,
    DetectionResult,
    Explanation,
    Policy,
    Threat,
)

logger = logging.getLogger("sentinel-sdk")

_DEFAULT_TIMEOUT = 30
_TOKEN_REFRESH_MARGIN_SEC = 120
_MAX_RETRIES = 3
_BACKOFF_FACTOR = 0.5


class SentinelClient:
    """Thread-safe client for the SENTINEL REST API."""

    def __init__(
        self,
        api_url: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = _DEFAULT_TIMEOUT,
        verify_ssl: bool = True,
    ):
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._username = username
        self._password = password
        self._timeout = timeout
        self._verify_ssl = verify_ssl

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: float = 0.0

        self._session = self._build_session()

    # ── context manager ───────────────────────────────────────────────

    def __enter__(self) -> SentinelClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._session.close()

    # ── authentication ────────────────────────────────────────────────

    def authenticate(self) -> bool:
        if self._api_key:
            self._access_token = self._api_key
            self._token_expires_at = float("inf")
            return True

        if not self._username or not self._password:
            raise AuthenticationError("Either api_key or username/password is required")

        data = self._post("/api/v1/auth/login", json={
            "username": self._username,
            "password": self._password,
        }, auth_required=False)

        self._access_token = data.get("access_token") or data.get("token")
        self._refresh_token = data.get("refresh_token")
        expires_in = data.get("expires_in", 3600)
        self._token_expires_at = time.time() + expires_in

        if not self._access_token:
            raise AuthenticationError("No token returned by auth service")
        return True

    def _ensure_auth(self) -> None:
        if self._access_token is None:
            raise AuthenticationError("Not authenticated; call authenticate() first")
        if time.time() >= self._token_expires_at - _TOKEN_REFRESH_MARGIN_SEC:
            self._refresh_auth()

    def _refresh_auth(self) -> None:
        if self._refresh_token:
            try:
                data = self._post("/api/v1/auth/refresh", json={
                    "refresh_token": self._refresh_token,
                }, auth_required=False)
                self._access_token = data.get("access_token") or data.get("token")
                self._refresh_token = data.get("refresh_token", self._refresh_token)
                expires_in = data.get("expires_in", 3600)
                self._token_expires_at = time.time() + expires_in
                return
            except (APIError, AuthenticationError):
                logger.debug("Token refresh failed; re-authenticating")

        if self._username and self._password:
            self.authenticate()
        else:
            raise AuthenticationError("Token expired and no credentials available for refresh")

    # ── detection ─────────────────────────────────────────────────────

    def detect(self, traffic_data: Dict[str, Any]) -> DetectionResult:
        if not traffic_data:
            raise ValidationError("traffic_data must be non-empty")
        data = self._post("/api/v1/detect", json=traffic_data)
        return DetectionResult.from_dict(data)

    def detect_batch(self, traffic_batch: List[Dict[str, Any]]) -> List[DetectionResult]:
        if not traffic_batch:
            raise ValidationError("traffic_batch must be non-empty")
        data = self._post("/api/v1/detect/batch", json={"batch": traffic_batch})
        results = data.get("results", [])
        return [DetectionResult.from_dict(r) for r in results]

    # ── threats ───────────────────────────────────────────────────────

    def get_threats(self, severity: Optional[str] = None, limit: int = 100) -> List[Threat]:
        params: Dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity
        data = self._get("/api/v1/threats", params=params)
        items = data.get("threats", data.get("items", []))
        if isinstance(data, list):
            items = data
        return [Threat.from_dict(t) for t in items]

    # ── alerts ────────────────────────────────────────────────────────

    def get_alerts(self, status: Optional[str] = None, limit: int = 100) -> List[Alert]:
        params: Dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        data = self._get("/api/v1/alerts", params=params)
        items = data.get("alerts", data.get("items", []))
        if isinstance(data, list):
            items = data
        return [Alert.from_dict(a) for a in items]

    # ── policies ──────────────────────────────────────────────────────

    def create_policy(
        self,
        name: str,
        action: str,
        source: str,
        destination: str,
        protocol: str = "tcp",
        **kwargs: Any,
    ) -> Policy:
        for field_name, value in [("name", name), ("action", action),
                                   ("source", source), ("destination", destination)]:
            if not value:
                raise ValidationError(f"{field_name} is required")
        payload: Dict[str, Any] = {
            "name": name,
            "action": action,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            **kwargs,
        }
        data = self._post("/api/v1/policies", json=payload)
        return Policy.from_dict(data)

    def get_policies(self) -> List[Policy]:
        data = self._get("/api/v1/policies")
        items = data.get("policies", data.get("items", []))
        if isinstance(data, list):
            items = data
        return [Policy.from_dict(p) for p in items]

    # ── compliance ────────────────────────────────────────────────────

    def get_compliance_assessment(self, framework: str) -> Assessment:
        if not framework:
            raise ValidationError("framework is required")
        data = self._post("/api/v1/assess", json={"framework": framework})
        return Assessment.from_dict(data)

    # ── explainability ────────────────────────────────────────────────

    def explain_detection(
        self,
        detection_id: str,
        features: Dict[str, Any],
        prediction: float,
    ) -> Explanation:
        data = self._post("/api/v1/explain/detection", json={
            "detection_id": detection_id,
            "features": features,
            "prediction": prediction,
        })
        return Explanation.from_dict(data)

    # ── statistics ────────────────────────────────────────────────────

    def get_statistics(self) -> Dict[str, Any]:
        return self._get("/api/v1/statistics")

    # ── HTTP plumbing ─────────────────────────────────────────────────

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=_MAX_RETRIES,
            backoff_factor=_BACKOFF_FACTOR,
            status_forcelist=[502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _headers(self, auth_required: bool = True) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if auth_required and self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        return headers

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._ensure_auth()
        url = f"{self._api_url}{path}"
        resp = self._session.get(
            url, headers=self._headers(), params=params,
            timeout=self._timeout, verify=self._verify_ssl,
        )
        return self._handle_response(resp)

    def _post(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        auth_required: bool = True,
    ) -> Dict[str, Any]:
        if auth_required:
            self._ensure_auth()
        url = f"{self._api_url}{path}"
        resp = self._session.post(
            url, headers=self._headers(auth_required), json=json,
            timeout=self._timeout, verify=self._verify_ssl,
        )
        return self._handle_response(resp)

    @staticmethod
    def _handle_response(resp: requests.Response) -> Dict[str, Any]:
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            raise RateLimitError(
                retry_after=float(retry_after) if retry_after else None,
                response_body=resp.json() if resp.content else {},
            )
        if resp.status_code == 401:
            raise AuthenticationError("Invalid or expired token")
        if resp.status_code == 403:
            raise APIError("Insufficient permissions", status_code=403)
        if resp.status_code >= 400:
            body = {}
            try:
                body = resp.json()
            except ValueError:
                pass
            raise APIError(
                body.get("error", f"HTTP {resp.status_code}"),
                status_code=resp.status_code,
                response_body=body,
            )
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {}
