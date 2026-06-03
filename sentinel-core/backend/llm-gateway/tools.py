"""Grounded tool registry for the analyst copilot.

The copilot may only call these tools. Three are **read-only** and fetch facts
from existing services over HTTP; each returns the record ids that ground the
facts (used by the grounding enforcer). The fourth, ``propose_reversible_action``,
returns a *draft* action for a human to review and makes **no** network call —
the copilot can never execute enforcement (advisory-only invariant).

All upstream URLs and paths are configurable so this service does not hard-depend
on any sibling's routing. Tests inject a fake session; nothing here touches the
network at import time.
"""

from __future__ import annotations

import os
import re
import uuid
from typing import Any, Optional

SERVICE_TOKEN_HEADER = "X-Internal-Service-Token"
HTTP_TIMEOUT = 5.0

# entity_id is attacker/LLM-controlled and is interpolated into upstream URL
# path segments / query params. Restrict to a strict allowlist so it can never
# inject path traversal (``../``), a new path segment (``/``), a scheme/host
# (``:``, ``@``), or query/whitespace — anti-SSRF / path-injection.
_ENTITY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class UnknownToolError(ValueError):
    """Raised when an unregistered tool is invoked."""


class InvalidEntityIdError(ValueError):
    """Raised when an entity_id fails the allowlist (anti-SSRF guard)."""


def validate_entity_id(entity_id: Any) -> str:
    if not isinstance(entity_id, str) or not _ENTITY_ID_RE.fullmatch(entity_id):
        raise InvalidEntityIdError(f"invalid entity_id: {entity_id!r}")
    return entity_id


def config_from_env() -> dict:
    return {
        "ai_engine_url": os.environ.get("AI_ENGINE_URL", "http://ai-engine:5003"),
        "api_gateway_url": os.environ.get("API_GATEWAY_URL", "http://api-gateway:8080"),
        "policy_url": os.environ.get(
            "POLICY_SERVICE_URL", "http://policy-orchestrator:5004"
        ),
    }


def _definitions() -> list[dict]:
    return [
        {
            "name": "get_threat_score",
            "description": (
                "Fetch the current threat score and contributing factors for an "
                "entity (host/user). Returns grounded record ids."
            ),
            "input_schema": {
                "type": "object",
                "properties": {"entity_id": {"type": "string"}},
                "required": ["entity_id"],
            },
        },
        {
            "name": "get_audit_events",
            "description": (
                "Fetch recent audit-trail events for an entity within a time "
                "window (e.g. '24h'). Returns event record ids for citation."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "entity_id": {"type": "string"},
                    "window": {"type": "string", "default": "24h"},
                },
                "required": ["entity_id"],
            },
        },
        {
            "name": "get_enforcement_state",
            "description": (
                "Fetch the current enforcement state for an entity (blocked, "
                "quarantined, none) including any active reversible action TTL."
            ),
            "input_schema": {
                "type": "object",
                "properties": {"entity_id": {"type": "string"}},
                "required": ["entity_id"],
            },
        },
        {
            "name": "propose_reversible_action",
            "description": (
                "Draft a reversible enforcement action for a HUMAN to review and "
                "confirm. Does NOT execute anything. Always carries a TTL."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "entity_id": {"type": "string"},
                    "action_type": {
                        "type": "string",
                        "enum": ["block", "quarantine", "rate_limit"],
                    },
                    "ttl_seconds": {"type": "integer", "default": 900},
                    "rationale": {"type": "string"},
                },
                "required": ["entity_id", "action_type", "rationale"],
            },
        },
    ]


class ToolRegistry:
    def __init__(
        self,
        config: Optional[dict] = None,
        session: Any = None,
        service_token: Optional[str] = None,
    ):
        self.config = config or config_from_env()
        if session is None:
            import requests  # lazy: not needed when a session is injected

            session = requests.Session()
        self.session = session
        self.service_token = (
            service_token
            if service_token is not None
            else os.environ.get("INTERNAL_SERVICE_TOKEN", "")
        )

    def definitions(self) -> list[dict]:
        return _definitions()

    def _headers(self) -> dict:
        return {SERVICE_TOKEN_HEADER: self.service_token}

    def _get(self, url: str, params: Optional[dict] = None) -> dict:
        resp = self.session.get(
            url, headers=self._headers(), params=params or {}, timeout=HTTP_TIMEOUT
        )
        resp.raise_for_status()
        return resp.json()

    def execute(self, name: str, tool_input: dict) -> dict:
        handler = {
            "get_threat_score": self._threat_score,
            "get_audit_events": self._audit_events,
            "get_enforcement_state": self._enforcement_state,
            "propose_reversible_action": self._propose,
        }.get(name)
        if handler is None:
            raise UnknownToolError(name)
        if name == "propose_reversible_action":
            return handler(tool_input)
        try:
            return handler(tool_input)
        except Exception as exc:  # noqa: BLE001 - fail-soft to the model
            return {"tool": name, "ok": False, "error": str(exc), "record_ids": []}

    # --- read tools -------------------------------------------------------

    def _threat_score(self, args: dict) -> dict:
        entity = validate_entity_id(args["entity_id"])
        data = self._get(f"{self.config['ai_engine_url']}/score/{entity}")
        rid = data.get("id") or entity
        return {
            "tool": "get_threat_score",
            "ok": True,
            "result": data,
            "record_ids": [f"score:{rid}"],
        }

    def _audit_events(self, args: dict) -> dict:
        entity = validate_entity_id(args["entity_id"])
        window = args.get("window", "24h")
        data = self._get(
            f"{self.config['api_gateway_url']}/internal/audit",
            params={"entity_id": entity, "window": window},
        )
        events = data.get("events", [])
        return {
            "tool": "get_audit_events",
            "ok": True,
            "result": data,
            "record_ids": [f"audit:{e['id']}" for e in events if e.get("id")],
        }

    def _enforcement_state(self, args: dict) -> dict:
        entity = validate_entity_id(args["entity_id"])
        data = self._get(f"{self.config['policy_url']}/enforcement/{entity}")
        return {
            "tool": "get_enforcement_state",
            "ok": True,
            "result": data,
            "record_ids": [f"enforce:{entity}"],
        }

    # --- propose tool (no network, never executed) ------------------------

    def _propose(self, args: dict) -> dict:
        entity = validate_entity_id(args["entity_id"])
        proposal_id = f"proposal:{uuid.uuid4().hex[:12]}"
        ttl = int(args.get("ttl_seconds", 900))
        draft = {
            "proposal_id": proposal_id,
            "executed": False,
            "reversible": True,
            "ttl_seconds": ttl,
            "entity_id": entity,
            "action_type": args["action_type"],
            "rationale": args["rationale"],
            "confirm_via": (
                f"{self.config['policy_url']}/enforcement (human confirmation required)"
            ),
        }
        return {
            "tool": "propose_reversible_action",
            "ok": True,
            "result": draft,
            "record_ids": [proposal_id],
        }
