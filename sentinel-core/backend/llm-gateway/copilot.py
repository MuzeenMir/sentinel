"""Copilot orchestration loop.

Drives a grounded, tool-using conversation: call the model, execute any tool
calls, feed results back, and enforce grounding on the final answer (with a
bounded repair round). Hard guards on iterations and token budget prevent
runaway loops/cost. Deterministic given an injected client + registry, so it is
fully unit-testable without the network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from anthropic_client import DEFAULT_SYNTHESIS_MODEL
from cost import cache_hit_ratio, estimate_cost_usd
from grounding import GroundingResult, repair_instruction, validate_grounding
from provenance import (
    DEFAULT_FRESHNESS_SECONDS,
    citation_hashes,
    provenance_from_results,
    verify_citations,
)
from telemetry import span

SAFE_FALLBACK = "I could not produce a grounded answer from the available data."


def _render_prefetched(results: list[dict]) -> str:
    """Render pre-fetched tool results into a citation-friendly context block."""
    lines: list[str] = []
    for r in results:
        if not r.get("ok"):
            continue
        ids = ", ".join(r.get("record_ids", []) or [])
        lines.append(f"- {r.get('tool')}: {json.dumps(r.get('result'))} [ids: {ids}]")
    return "\n".join(lines)


@dataclass
class CopilotResult:
    text: str
    grounded: bool
    record_ids: list[str] = field(default_factory=list)
    proposals: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    citation_provenance: dict = field(default_factory=dict)
    usage: dict = field(default_factory=dict)
    cost_usd: float = 0.0
    cache_hit_ratio: float = 0.0
    iterations: int = 0
    repairs: int = 0
    stop_reason: Optional[str] = None
    reason: Optional[str] = None


class Copilot:
    def __init__(
        self,
        client: Any,
        registry: Any,
        system: Optional[str] = None,
        max_iters: int = 6,
        max_repairs: int = 1,
        max_total_tokens: int = 100_000,
        audit_hook: Any = None,
        citation_freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    ):
        self.client = client
        self.registry = registry
        self.default_system = system
        self.max_iters = max_iters
        self.max_repairs = max_repairs
        self.max_total_tokens = max_total_tokens
        self.citation_freshness_seconds = citation_freshness_seconds
        # audit_hook(event_type: str, payload: dict) -> None; no-op by default.
        self.audit_hook = audit_hook or (lambda event_type, payload: None)

    @staticmethod
    def _assistant_content(resp: Any) -> list[dict]:
        content: list[dict] = []
        if resp.text:
            content.append({"type": "text", "text": resp.text})
        for call in resp.tool_calls:
            content.append(
                {
                    "type": "tool_use",
                    "id": call["id"],
                    "name": call["name"],
                    "input": call["input"],
                }
            )
        return content

    def run(
        self,
        system: str,
        user_message: str,
        prefetched: Optional[list[dict]] = None,
    ) -> CopilotResult:
        valid_ids: set[str] = set()
        proposals: list[dict] = []
        tool_results: list[dict] = []
        usage_total = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
        }
        repairs = 0

        user_content = user_message
        if prefetched:
            for r in prefetched:
                valid_ids.update(r.get("record_ids", []) or [])
                tool_results.append(r)
                if r.get("tool") == "propose_reversible_action" and r.get("ok"):
                    proposals.append(r["result"])
            user_content = (
                user_message
                + "\n\nGrounded data (cite these record ids):\n"
                + _render_prefetched(prefetched)
            )
        messages: list[dict] = [{"role": "user", "content": user_content}]
        # Audit the prompt occurrence (metadata only — no raw content, no PII) so
        # the copilot is fully inside the ledger from the first turn.
        self.audit_hook(
            "prompt", {"chars": len(user_content), "prefetched": bool(prefetched)}
        )

        for iteration in range(1, self.max_iters + 1):
            with span("copilot.model_call", iteration=iteration):
                resp = self.client.complete(
                    system=system,
                    messages=messages,
                    tools=self.registry.definitions(),
                )
            for key in usage_total:
                usage_total[key] += resp.usage.get(key, 0)
            self.audit_hook(
                "llm_completion", {"usage": resp.usage, "stop": resp.stop_reason}
            )

            spent = usage_total["input_tokens"] + usage_total["output_tokens"]
            if spent > self.max_total_tokens:
                return CopilotResult(
                    text=SAFE_FALLBACK,
                    grounded=False,
                    record_ids=sorted(valid_ids),
                    proposals=proposals,
                    tool_results=tool_results,
                    usage=usage_total,
                    iterations=iteration,
                    repairs=repairs,
                    stop_reason="token_budget",
                    reason="token budget exceeded",
                )

            if resp.stop_reason == "tool_use" and resp.tool_calls:
                messages.append(
                    {"role": "assistant", "content": self._assistant_content(resp)}
                )
                result_blocks = []
                for call in resp.tool_calls:
                    with span("copilot.tool_call", tool=call["name"]):
                        out = self.registry.execute(call["name"], call["input"])
                    self.audit_hook(
                        "tool_call", {"name": call["name"], "input": call["input"]}
                    )
                    valid_ids.update(out.get("record_ids", []))
                    tool_results.append(out)
                    if call["name"] == "propose_reversible_action" and out.get("ok"):
                        proposals.append(out["result"])
                    result_blocks.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": call["id"],
                            "content": json.dumps(out.get("result", out)),
                        }
                    )
                messages.append({"role": "user", "content": result_blocks})
                continue

            # Final natural-language answer: enforce grounding + citation
            # provenance (cited ids must map to a real, fresh source record).
            gr = validate_grounding(resp.text, valid_ids)
            provenance = provenance_from_results(tool_results)
            if gr.ok:
                pv = verify_citations(
                    gr.cited_ids,
                    provenance,
                    freshness_seconds=self.citation_freshness_seconds,
                )
                if not pv.ok:
                    gr = GroundingResult(
                        ok=False, cited_ids=gr.cited_ids, reason=pv.reason
                    )
            if gr.ok:
                cited_provenance = citation_hashes(gr.cited_ids, provenance)
                cost_usd = estimate_cost_usd(usage_total, DEFAULT_SYNTHESIS_MODEL)
                cache_ratio = cache_hit_ratio(usage_total)
                self.audit_hook(
                    "answer",
                    {
                        "grounded": True,
                        "record_ids": sorted(valid_ids),
                        "citation_provenance": cited_provenance,
                        "cost_usd": cost_usd,
                        "cache_hit_ratio": cache_ratio,
                    },
                )
                return CopilotResult(
                    text=resp.text,
                    grounded=True,
                    record_ids=sorted(valid_ids),
                    proposals=proposals,
                    tool_results=tool_results,
                    citation_provenance=cited_provenance,
                    usage=usage_total,
                    cost_usd=cost_usd,
                    cache_hit_ratio=cache_ratio,
                    iterations=iteration,
                    repairs=repairs,
                    stop_reason=resp.stop_reason,
                )
            if repairs < self.max_repairs:
                repairs += 1
                messages.append({"role": "assistant", "content": resp.text})
                messages.append({"role": "user", "content": repair_instruction(gr)})
                continue

            self.audit_hook("answer", {"grounded": False, "reason": gr.reason})
            return CopilotResult(
                text=SAFE_FALLBACK,
                grounded=False,
                record_ids=sorted(valid_ids),
                proposals=proposals,
                tool_results=tool_results,
                usage=usage_total,
                iterations=iteration,
                repairs=repairs,
                stop_reason="ungrounded",
                reason=gr.reason,
            )

        return CopilotResult(
            text=SAFE_FALLBACK,
            grounded=False,
            record_ids=sorted(valid_ids),
            proposals=proposals,
            tool_results=tool_results,
            usage=usage_total,
            iterations=self.max_iters,
            repairs=repairs,
            stop_reason="max_iters",
            reason="max tool iterations reached",
        )
