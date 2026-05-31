"""Copilot audit integration.

Puts the copilot *inside* the cryptographic audit ledger: every prompt,
completion, tool call, proposal, and final answer is written to the shared
append-only audit trail via ``audit_logger.audit_log`` (imported, never edited).

The sink is injectable for tests; the default sink is resolved lazily so this
module imports without psycopg2 present.
"""

from __future__ import annotations

from typing import Any, Callable, Optional


def _default_sink(**kwargs: Any) -> None:  # pragma: no cover - needs PG
    """Lazily import the shared logger so tests don't require psycopg2."""
    import audit_logger

    category_name = kwargs.pop("category_name", "INCIDENT")
    category = getattr(audit_logger.AuditCategory, category_name, None)
    audit_logger.audit_log(category=category, **kwargs)


class CopilotAuditor:
    def __init__(
        self,
        actor: str,
        tenant_id: Optional[str] = None,
        sink: Optional[Callable[..., None]] = None,
        category_name: str = "INCIDENT",
    ):
        self.actor = actor
        self.tenant_id = tenant_id
        self.category_name = category_name
        self._sink = sink

    def _emit(
        self,
        event_type: str,
        metadata: dict,
        target: Optional[str] = None,
        status: str = "success",
    ) -> None:
        sink = self._sink or _default_sink
        sink(
            event_type=event_type,
            actor=self.actor,
            target=target,
            metadata=metadata or {},
            status=status,
            tenant_id=self.tenant_id,
            category_name=self.category_name,
        )

    # Convenience helpers ------------------------------------------------
    def log_prompt(self, metadata: dict) -> None:
        self._emit("copilot_prompt", metadata)

    def log_completion(self, metadata: dict) -> None:
        self._emit("copilot_completion", metadata)

    def log_tool_call(self, metadata: dict) -> None:
        self._emit("copilot_tool_call", metadata)

    def log_proposal(self, proposal: dict) -> None:
        self._emit(
            "copilot_proposal",
            proposal,
            target=proposal.get("entity_id"),
        )

    def log_answer(self, metadata: dict) -> None:
        status = "success" if metadata.get("grounded", True) else "failure"
        self._emit("copilot_answer", metadata, status=status)

    def hook(self) -> Callable[[str, dict], None]:
        """Return a callable matching Copilot's audit_hook(event_type, payload)."""

        def _hook(event_type: str, payload: dict) -> None:
            self._emit(f"copilot_{event_type}", payload or {})

        return _hook
