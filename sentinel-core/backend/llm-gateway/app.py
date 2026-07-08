"""SENTINEL LLM Gateway.

Phase 2 — Wedge #2: the grounded LLM analyst copilot.

This service replaces the Phase-1 410 shell with a real, grounded, tool-using
analyst copilot. It is **advisory only**: it summarizes incidents from real
backend data, answers follow-ups with citations to source records, and
*proposes* (never executes) reversible enforcement actions. A human confirms
any action through the existing policy-orchestrator API.

Inference is provided by the Anthropic API and is optional: when no API key is
configured the gateway still serves /health and reports inference disabled.
"""

import hmac
import logging
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import redis
from flask import Flask, jsonify, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from observability import configure_logging  # noqa: E402
from metrics import init_metrics  # noqa: E402

from provider import ProviderRouter  # noqa: E402
from audit import CopilotAuditor  # noqa: E402
from copilot import Copilot  # noqa: E402
from cost import resolve_token_budget  # noqa: E402
from persistence import SessionStore  # noqa: E402
from prompts import render  # noqa: E402
from proposals import ProposalError, ProposalSigner  # noqa: E402
from residency import resolve_residency  # noqa: E402
from safety import RateLimiter, check_request  # noqa: E402
from triage_store import list_pending_proposals  # noqa: E402
from tools import (  # noqa: E402
    SERVICE_TOKEN_HEADER,
    InvalidEntityIdError,
    ToolRegistry,
    config_from_env,
)

SERVICE_NAME = "llm-gateway"

app = Flask(__name__)
configure_logging(service_name=SERVICE_NAME)
init_metrics(app, service_name=SERVICE_NAME)

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

# Overridable audit sink (tests set a no-op; default resolves the shared logger).
audit_sink = None


def inference_enabled() -> bool:
    """True when the configured provider has the credentials/endpoint it needs.

    Anthropic (default) requires ANTHROPIC_API_KEY; the local provider
    (INFERENCE_PROVIDER=local) requires a self-hosted endpoint URL instead —
    the hosted key is never consulted for local inference.
    """
    if ProviderRouter.from_env().name == "local":
        base_url = (
            os.environ.get("LOCAL_LLM_BASE_URL")
            or os.environ.get("INFERENCE_BASE_URL")
            or ""
        )
        return bool(base_url.strip())
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


# --- dependency factories (overridable in tests) -------------------------


def make_registry() -> ToolRegistry:
    return ToolRegistry(
        config=config_from_env(),
        service_token=os.environ.get("INTERNAL_SERVICE_TOKEN", ""),
    )


def make_inference_client():
    """Build the inference client for the configured provider (C1).

    ``INFERENCE_PROVIDER=local`` selects the self-hostable llama.cpp / Gemma
    adapter (inference sovereignty); the default is the hosted Anthropic client.
    Both expose the same ``complete(...) -> LLMResponse`` contract, so the
    copilot is provider-agnostic and on-prem is a config swap, not a code change.
    Credentials are resolved per provider inside ``build()`` (ANTHROPIC_API_KEY
    vs LOCAL_LLM_API_KEY) so the hosted key is never sent to a local endpoint.
    """
    return ProviderRouter.from_env().build()


def make_copilot_context(actor: str, tenant_id=None) -> SimpleNamespace:
    """Build the per-request copilot stack. Overridden in tests to avoid network."""
    registry = make_registry()
    auditor = CopilotAuditor(actor=actor, tenant_id=tenant_id, sink=audit_sink)
    client = make_inference_client()
    copilot = Copilot(
        client=client,
        registry=registry,
        audit_hook=auditor.hook(),
        max_total_tokens=resolve_token_budget(),
    )
    return SimpleNamespace(copilot=copilot, registry=registry, auditor=auditor)


def _triage_db():
    """Connection for the read-only approval queue. Overridden in tests."""
    from _lib.db import connect

    return connect()


def _session_store(tenant_id=None) -> SessionStore:
    """Session store bound to the authenticated tenant so all copilot state is
    namespaced per tenant (C3 interim isolation). ``tenant_id`` is derived only
    from the verified gateway context, never from the client."""
    return SessionStore(redis_client, tenant_id=tenant_id)


def _rate_limiter() -> RateLimiter:
    return RateLimiter(
        redis_client, limit=int(os.environ.get("COPILOT_RATE_LIMIT", "20"))
    )


def _gateway_authenticated() -> bool:
    """True when the caller presents the valid internal service token, i.e. the
    request arrived via the authenticated api-gateway path (which mints the
    X-Actor / X-Tenant-Id headers). Without it, forwarded identity headers are
    untrusted and must not be honored."""
    expected = os.environ.get("INTERNAL_SERVICE_TOKEN", "")
    if not expected:
        return False
    return hmac.compare_digest(request.headers.get(SERVICE_TOKEN_HEADER, ""), expected)


def _actor() -> str:
    """Server-derived rate-limit identity. Never trusts client-supplied body
    fields. The gateway-forwarded ``X-Actor`` header is honored ONLY when the
    caller is authenticated with the internal service token; otherwise we key on
    the source address so a client cannot rotate the key to bypass the limit."""
    if _gateway_authenticated():
        actor = (request.headers.get("X-Actor") or "").strip()
        if actor:
            return f"user:{actor}"
    return f"ip:{request.remote_addr or 'unknown'}"


def _tenant():
    """Tenant context, honored only from the authenticated gateway. A client
    cannot self-assert a tenant via the request body/headers (RLS scoping is
    hardened further under Phase-3 C3)."""
    if _gateway_authenticated():
        return request.headers.get("X-Tenant-Id")
    return None


# --- health --------------------------------------------------------------


@app.get("/health")
def health():
    return (
        jsonify(
            {
                "status": "healthy",
                "service": SERVICE_NAME,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ),
        200,
    )


@app.get("/readyz")
def readyz():
    residency = resolve_residency()
    return (
        jsonify(
            {
                "status": "ready",
                "service": SERVICE_NAME,
                "inference_enabled": inference_enabled(),
                # Honest visibility of WHERE inference routes (a config seam, not
                # a residency guarantee — see ADR-021).
                "inference_provider": residency.provider,
                "inference_region": residency.region,
                "inference_default_endpoint": residency.is_default,
            }
        ),
        200,
    )


# --- copilot endpoints ---------------------------------------------------


@app.post("/copilot/summarize")
def copilot_summarize():
    data = request.get_json(force=True, silent=True) or {}
    entity_id = data.get("entity_id")
    if not entity_id:
        return jsonify({"error": "entity_id is required"}), 400
    if not inference_enabled():
        return jsonify({"error": "inference disabled (no provider configured)"}), 503

    actor = _actor()
    if not _rate_limiter().allow(actor):
        return jsonify({"error": "rate limit exceeded"}), 429

    ctx = make_copilot_context(actor, _tenant())
    # Pre-fetch grounded facts so the summary is deterministic and cited.
    prefetched = [
        ctx.registry.execute("get_threat_score", {"entity_id": entity_id}),
        ctx.registry.execute(
            "get_audit_events", {"entity_id": entity_id, "window": "24h"}
        ),
        ctx.registry.execute("get_enforcement_state", {"entity_id": entity_id}),
        # The node product's primary signal — seed it deterministically; small
        # local models don't reliably decide to fetch it themselves.
        ctx.registry.execute("get_node_alerts", {"limit": 10}),
    ]
    result = ctx.copilot.run(
        system=render("system"),
        user_message=f"Summarize the security incident for entity {entity_id}.",
        prefetched=prefetched,
    )

    store = _session_store(_tenant())
    session_id = store.create_session(entity_id)
    store.append_message(session_id, "user", f"summarize {entity_id}")
    store.append_message(session_id, "assistant", result.text)
    for proposal in result.proposals:
        store.save_proposal(session_id, proposal)

    return jsonify(
        {
            "session_id": session_id,
            "entity_id": entity_id,
            "summary": result.text,
            "grounded": result.grounded,
            "citations": result.record_ids,
            "citation_provenance": result.citation_provenance,
            "proposals": result.proposals,
        }
    ), 200


@app.post("/copilot/ask")
def copilot_ask():
    data = request.get_json(force=True, silent=True) or {}
    session_id = data.get("session_id")
    question = data.get("question", "")
    if not session_id or not question:
        return jsonify({"error": "session_id and question are required"}), 400
    if not inference_enabled():
        return jsonify({"error": "inference disabled (no provider configured)"}), 503

    allowed, reason = check_request(question)
    if not allowed:
        return jsonify({"error": reason}), 400

    store = _session_store(_tenant())
    session = store.get_session(session_id)
    if session is None:
        return jsonify({"error": "unknown session"}), 404

    actor = _actor()
    if not _rate_limiter().allow(actor):
        return jsonify({"error": "rate limit exceeded"}), 429

    entity_id = session["entity_id"]
    ctx = make_copilot_context(actor, _tenant())
    result = ctx.copilot.run(
        system=render("system"),
        user_message=render("followup", entity_id=entity_id, question=question),
    )

    store.append_message(session_id, "user", question)
    store.append_message(session_id, "assistant", result.text)
    for proposal in result.proposals:
        store.save_proposal(session_id, proposal)

    return jsonify(
        {
            "session_id": session_id,
            "answer": result.text,
            "grounded": result.grounded,
            "citations": result.record_ids,
            "citation_provenance": result.citation_provenance,
            "proposals": result.proposals,
        }
    ), 200


@app.post("/copilot/propose")
def copilot_propose():
    """Draft a reversible action for human confirmation. Never executes."""
    data = request.get_json(force=True, silent=True) or {}
    required = ("entity_id", "action_type", "rationale")
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"missing: {', '.join(missing)}"}), 400

    actor = _actor()
    registry = make_registry()
    try:
        draft = registry.execute(
            "propose_reversible_action",
            {
                "entity_id": data["entity_id"],
                "action_type": data["action_type"],
                "ttl_seconds": int(data.get("ttl_seconds", 900)),
                "rationale": data["rationale"],
            },
        )
    except InvalidEntityIdError:
        return jsonify({"error": "invalid entity_id"}), 400
    proposal = draft["result"]

    auditor = CopilotAuditor(actor=actor, tenant_id=_tenant(), sink=audit_sink)
    auditor.log_proposal(proposal)

    # Defensive: the draft must never be marked executed.
    if proposal["executed"] is not False:
        return jsonify({"error": "invalid proposal"}), 502
    return jsonify({"proposal": proposal}), 200


@app.get("/copilot/proposals")
def copilot_proposals():
    """Approval queue: the reversible proposals the auto-triage worker drafted
    and stored, awaiting human confirmation. Read-only — listing a proposal
    executes nothing; a human still confirms each via /copilot/confirm and the
    policy-orchestrator enforcement boundary."""
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    try:
        conn = _triage_db()
    except Exception as exc:  # noqa: BLE001 - DB briefly unavailable is not fatal
        logger.warning("Approval queue unavailable: %r", exc)
        return jsonify({"proposals": [], "error": "queue unavailable"}), 503
    try:
        proposals = list_pending_proposals(conn, limit=limit)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001 - best-effort release
            pass
    return jsonify({"proposals": proposals}), 200


@app.post("/copilot/confirm")
def copilot_confirm():
    """Validate a human-confirmed proposal: signature and TTL.

    This endpoint NEVER executes enforcement and does NOT consume the proposal's
    single-use nonce. Single-use is owned by the enforcement boundary
    (policy-orchestrator ``POST /enforcement``) -- the only place a proposal is
    actually applied. Consuming the nonce here too would double-spend it, so the
    subsequent forward to ``/enforcement`` would always fail as a replay. On
    success the frontend forwards the validated proposal to ``forward_to``.
    """
    data = request.get_json(force=True, silent=True) or {}
    proposal = data.get("proposal") or data
    try:
        ProposalSigner().verify(proposal)
    except ProposalError:
        return jsonify({"error": "invalid proposal"}), 400

    auditor = CopilotAuditor(actor=_actor(), tenant_id=_tenant(), sink=audit_sink)
    auditor.log_proposal({**proposal, "confirmed": True})

    return jsonify(
        {
            "confirmed": True,
            "proposal": proposal,
            "forward_to": proposal.get("confirm_via"),
        }
    ), 200


if __name__ == "__main__":
    from _lib.net import bind_host

    port = int(os.environ.get("PORT", "5012"))
    app.run(host=bind_host(), port=port)
