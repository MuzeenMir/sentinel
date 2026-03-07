#!/usr/bin/env python3
"""
SENTINEL MCP Server — exposes SENTINEL API as MCP tools for Cursor/LLMs.

Environment:
  SENTINEL_API_URL  Base URL for API gateway (default http://localhost:8080)
  SENTINEL_API_TOKEN Optional JWT for authenticated calls
"""

import os
import json
import logging
from typing import Any, Optional

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    from mcp.server import Server
    FastMCP = None

BASE_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:8080").rstrip("/")
TOKEN = os.environ.get("SENTINEL_API_TOKEN", "")


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    return h


def _get(path: str, params: Optional[dict] = None) -> dict:
    r = requests.get(f"{BASE_URL}{path}", headers=_headers(), params=params or {}, timeout=15)
    r.raise_for_status()
    return r.json() if r.content else {}


def _post(path: str, data: Optional[dict] = None) -> dict:
    r = requests.post(f"{BASE_URL}{path}", headers=_headers(), json=data or {}, timeout=15)
    r.raise_for_status()
    return r.json() if r.content else {}


def _put(path: str, data: Optional[dict] = None) -> dict:
    r = requests.put(f"{BASE_URL}{path}", headers=_headers(), json=data or {}, timeout=15)
    r.raise_for_status()
    return r.json() if r.content else {}


if FastMCP is not None:
    mcp = FastMCP(
        "SENTINEL",
        description="SENTINEL security platform: threats, alerts, policies, compliance, hardening.",
    )

    @mcp.tool()
    def get_dashboard_stats() -> str:
        """Return dashboard statistics (threats, blocked, traffic)."""
        try:
            data = _get("/api/v1/statistics")
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_threats(limit: int = 50, severity: Optional[str] = None) -> str:
        """List recent threats. Optional severity filter: LOW, MEDIUM, HIGH, CRITICAL."""
        try:
            params = {"limit": limit}
            if severity:
                params["severity"] = severity
            data = _get("/api/v1/threats", params)
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_threat(threat_id: str) -> str:
        """Get a single threat by ID."""
        try:
            data = _get(f"/api/v1/threats/{threat_id}")
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_alerts(limit: int = 50, status: Optional[str] = None) -> str:
        """List alerts. Optional status: new, acknowledged, resolved, ignored."""
        try:
            params = {"limit": limit}
            if status:
                params["status"] = status
            data = _get("/api/v1/alerts", params)
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_policies() -> str:
        """List firewall/policy rules."""
        try:
            data = _get("/api/v1/policies")
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_compliance_frameworks() -> str:
        """List compliance frameworks (NIST, GDPR, HIPAA, PCI-DSS, etc.)."""
        try:
            data = _get("/api/v1/frameworks")
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def run_compliance_assessment(framework: str) -> str:
        """Run a compliance assessment for a framework (e.g. NIST, GDPR)."""
        try:
            data = _post("/api/v1/assess", {"framework": framework, "policies": []})
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_hardening_posture() -> str:
        """Get current hardening posture score and check summary."""
        try:
            data = _get("/api/v1/hardening/posture")
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_config() -> str:
        """Get current system configuration (platform settings)."""
        try:
            data = _get("/api/v1/config")
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def get_health() -> str:
        """Check API gateway health and status."""
        try:
            data = _get("/health")
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def main() -> None:
        mcp.run()

else:
    # Fallback if mcp.server.fastmcp not available
    def main() -> None:
        logger.error("Install mcp with: pip install mcp[cli]")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
