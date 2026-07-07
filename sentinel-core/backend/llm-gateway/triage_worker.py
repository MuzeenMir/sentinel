"""Auto-triage worker — the spine link between detection and the analyst.

Polls ``node_alerts`` for rows the copilot has not yet triaged, runs the
grounded analyst on each (deterministically prefetching THE alert so citations
are anchored), stores the cited triage in ``node_alert_triage``, and for
high/critical alerts drafts a signed reversible enforcement proposal.

Advisory-only invariant holds end to end: the worker NEVER executes
enforcement. Proposals are drafts a human confirms through the existing
policy-orchestrator ``POST /enforcement`` boundary, which alone verifies the
signature and consumes the single-use nonce.

Runs as its own compose service (llm-gateway image, command override —
reaper-style) so slow local inference can never stall the detector. Liveness
is a heartbeat file probed by the compose healthcheck, like the reaper.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from prompts import render  # noqa: E402
from proposals import ProposalError  # noqa: E402

logger = logging.getLogger(__name__)

ALERT_COLS = (
    "id",
    "alert_id",
    "event_type",
    "severity",
    "score",
    "pid",
    "uid",
    "comm",
    "exe",
    "hostname",
    "source_event_id",
    "summary",
    "status",
    "created_at",
)

_SELECT_SQL = (
    "SELECT "
    + ", ".join(f"a.{c}" for c in ALERT_COLS)
    + " FROM node_alerts a"
    + " LEFT JOIN node_alert_triage t ON t.alert_id = a.id"
    + " WHERE t.id IS NULL OR (t.status = 'failed' AND t.attempts < %s)"
    + " ORDER BY a.id LIMIT %s"
)

UPSERT_COLS = (
    "alert_id",
    "status",
    "grounded",
    "triage_text",
    "citations",
    "citation_provenance",
    "proposal",
    "provider",
    "model",
    "error",
)

_UPSERT_SQL = """
    INSERT INTO node_alert_triage
        (alert_id, status, grounded, triage_text, citations,
         citation_provenance, proposal, provider, model, error)
    VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s, %s)
    ON CONFLICT (alert_id) DO UPDATE SET
        status = EXCLUDED.status,
        grounded = EXCLUDED.grounded,
        triage_text = EXCLUDED.triage_text,
        citations = EXCLUDED.citations,
        citation_provenance = EXCLUDED.citation_provenance,
        proposal = EXCLUDED.proposal,
        provider = EXCLUDED.provider,
        model = EXCLUDED.model,
        error = EXCLUDED.error,
        attempts = node_alert_triage.attempts + 1,
        updated_at = CURRENT_TIMESTAMP
"""

# Proposal entity ids must satisfy tools.validate_entity_id's allowlist.
_ENTITY_STRIP_RE = re.compile(r"[^A-Za-z0-9._-]")
_RATIONALE_MAX = 500


def _inference_enabled() -> bool:
    """Mirror app.inference_enabled without importing the Flask app."""
    from provider import ProviderRouter

    if ProviderRouter.from_env().name == "local":
        base_url = (
            os.environ.get("LOCAL_LLM_BASE_URL")
            or os.environ.get("INFERENCE_BASE_URL")
            or ""
        )
        return bool(base_url.strip())
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


def _default_db_connect():
    from _lib.db import connect

    return connect()


def _default_context() -> SimpleNamespace:
    """Build the copilot stack the same way app.make_copilot_context does."""
    from audit import CopilotAuditor
    from copilot import Copilot
    from cost import resolve_token_budget
    from provider import ProviderRouter
    from tools import ToolRegistry, config_from_env

    registry = ToolRegistry(
        config=config_from_env(),
        service_token=os.environ.get("INTERNAL_SERVICE_TOKEN", ""),
    )
    auditor = CopilotAuditor(
        actor="triage-worker", tenant_id=os.environ.get("DEFAULT_TENANT_ID")
    )
    copilot = Copilot(
        client=ProviderRouter.from_env().build(),
        registry=registry,
        audit_hook=auditor.hook(),
        max_total_tokens=resolve_token_budget(),
    )
    return SimpleNamespace(copilot=copilot, registry=registry, auditor=auditor)


def _entity_from_hostname(hostname) -> str:
    cleaned = _ENTITY_STRIP_RE.sub("", hostname or "")[:128]
    return cleaned or "node"


class TriageWorker:
    def __init__(
        self,
        db_connect=None,
        context_factory=None,
        batch_size: int | None = None,
        max_attempts: int | None = None,
        proposal_severities=("critical", "high"),
        proposal_action: str | None = None,
        proposal_ttl: int | None = None,
        inference_gate=None,
        heartbeat_path: str | None = None,
    ):
        self.db_connect = db_connect or _default_db_connect
        self.context_factory = context_factory or _default_context
        self.batch_size = batch_size or int(os.environ.get("TRIAGE_BATCH_SIZE", "5"))
        self.max_attempts = max_attempts or int(
            os.environ.get("TRIAGE_MAX_ATTEMPTS", "3")
        )
        self.proposal_severities = frozenset(proposal_severities)
        self.proposal_action = proposal_action or os.environ.get(
            "TRIAGE_PROPOSAL_ACTION", "quarantine"
        )
        self.proposal_ttl = proposal_ttl or int(
            os.environ.get("TRIAGE_PROPOSAL_TTL_SECONDS", "900")
        )
        self.inference_gate = inference_gate or _inference_enabled
        self.heartbeat_path = heartbeat_path or os.environ.get(
            "TRIAGE_HEARTBEAT_PATH", "/tmp/triage-heartbeat"
        )
        self.provider = os.environ.get("INFERENCE_PROVIDER", "anthropic")
        self.model = (
            os.environ.get("LOCAL_LLM_MODEL", "")
            if self.provider == "local"
            else os.environ.get("ANTHROPIC_MODEL", "")
        )
        self.upsert_cols = UPSERT_COLS

    # --- fetch -------------------------------------------------------------

    def fetch_untriaged(self, conn) -> list[dict]:
        with conn.cursor() as cur:
            cur.execute(_SELECT_SQL, (self.max_attempts, self.batch_size))
            rows = cur.fetchall()
        return [dict(zip(ALERT_COLS, row)) for row in rows]

    # --- triage ------------------------------------------------------------

    @staticmethod
    def _alert_json(alert: dict) -> dict:
        """JSON-native view of the alert (Decimal/UUID/datetime coerced) so the
        prefetched block renders and hashes cleanly."""
        out = dict(alert)
        if out.get("score") is not None:
            out["score"] = float(out["score"])
        for key in ("alert_id", "created_at"):
            val = out.get(key)
            if val is not None and not isinstance(val, (str, int, float, bool)):
                out[key] = val.isoformat() if hasattr(val, "isoformat") else str(val)
        return out

    def triage_alert(self, ctx, alert: dict) -> dict:
        record_id = f"node_alert:{alert['id']}"
        prefetched = [
            {
                "tool": "get_node_alerts",
                "ok": True,
                "result": {"alerts": [self._alert_json(alert)]},
                "record_ids": [record_id],
            }
        ]
        result = ctx.copilot.run(
            system=render("system"),
            user_message=render(
                "triage",
                record_id=record_id,
                severity=alert.get("severity") or "unknown",
                comm=alert.get("comm") or "unknown",
                exe=alert.get("exe") or "unknown",
                hostname=alert.get("hostname") or "unknown",
                summary=alert.get("summary") or "n/a",
            ),
            prefetched=prefetched,
        )
        if not result.grounded:
            return {
                "status": "failed",
                "grounded": False,
                "text": result.text,
                "citations": result.record_ids,
                "provenance": {},
                "proposal": None,
                "error": f"ungrounded triage: {result.reason}",
            }

        proposal, error = None, None
        if alert.get("severity") in self.proposal_severities:
            proposal, error = self._draft_proposal(ctx, alert, result.text)

        return {
            "status": "triaged",
            "grounded": True,
            "text": result.text,
            "citations": result.record_ids,
            "provenance": result.citation_provenance,
            "proposal": proposal,
            "error": error,
        }

    def _draft_proposal(self, ctx, alert: dict, triage_text: str):
        """Draft (never execute) a signed reversible action for human review."""
        rationale = f"auto-triage: {triage_text}"[:_RATIONALE_MAX]
        try:
            draft = ctx.registry.execute(
                "propose_reversible_action",
                {
                    "entity_id": _entity_from_hostname(alert.get("hostname")),
                    "action_type": self.proposal_action,
                    "ttl_seconds": self.proposal_ttl,
                    "rationale": rationale,
                },
            )
        except ProposalError as exc:
            logger.warning("Proposal signing unavailable: %s", exc)
            return None, str(exc)
        proposal = draft["result"]
        auditor = getattr(ctx, "auditor", None)
        if auditor is not None:
            auditor.log_proposal(proposal)
        return proposal, None

    # --- persist -----------------------------------------------------------

    def record(self, conn, alert: dict, outcome: dict) -> None:
        with conn.cursor() as cur:
            cur.execute(
                _UPSERT_SQL,
                (
                    alert["id"],
                    outcome["status"],
                    outcome["grounded"],
                    outcome["text"],
                    json.dumps(outcome["citations"]),
                    json.dumps(outcome["provenance"]),
                    json.dumps(outcome["proposal"]),
                    self.provider,
                    self.model,
                    outcome["error"],
                ),
            )
        conn.commit()

    # --- loop --------------------------------------------------------------

    def poll_once(self, conn) -> int:
        alerts = self.fetch_untriaged(conn)
        if not alerts:
            return 0
        ctx = self.context_factory()
        triaged = 0
        for alert in alerts:
            try:
                outcome = self.triage_alert(ctx, alert)
            except Exception as exc:  # noqa: BLE001 - one bad alert must not stall the batch
                logger.warning("Triage failed for alert %s: %r", alert.get("id"), exc)
                outcome = {
                    "status": "failed",
                    "grounded": False,
                    "text": None,
                    "citations": [],
                    "provenance": {},
                    "proposal": None,
                    "error": str(exc),
                }
            self.record(conn, alert, outcome)
            # Beat inside the batch: one slow local-inference call must not
            # push the heartbeat past the healthcheck's stale threshold.
            self._heartbeat()
            if outcome["status"] == "triaged":
                triaged += 1
        return triaged

    def _heartbeat(self) -> None:
        Path(self.heartbeat_path).touch()

    def cycle(self) -> int:
        """One poll cycle. Always heartbeats — a config-idle or DB-down worker
        is alive, not unhealthy; the alert backlog metric covers the rest."""
        count = 0
        if not self.inference_gate():
            logger.info("Inference disabled (no provider configured); idling")
        else:
            conn = None
            try:
                conn = self.db_connect()
                count = self.poll_once(conn)
            except Exception as exc:  # noqa: BLE001 - transient DB/LLM outage
                logger.warning("Triage cycle failed: %r", exc)
            finally:
                if conn is not None:
                    conn.close()
        self._heartbeat()
        return count

    def run(self, interval_seconds: int | None = None) -> None:
        interval = interval_seconds or int(os.environ.get("TRIAGE_POLL_SECONDS", "10"))
        logger.info(
            "Triage worker starting: provider=%s batch=%s interval=%ss",
            self.provider,
            self.batch_size,
            interval,
        )
        while True:
            self.cycle()
            time.sleep(interval)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    TriageWorker().run()
