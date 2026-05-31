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

from grounding import repair_instruction, validate_grounding

SAFE_FALLBACK = "I could not produce a grounded answer from the available data."


@dataclass
class CopilotResult:
    text: str
    grounded: bool
    record_ids: list[str] = field(default_factory=list)
    proposals: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    usage: dict = field(default_factory=dict)
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
    ):
        self.client = client
        self.registry = registry
        self.default_system = system
        self.max_iters = max_iters
        self.max_repairs = max_repairs
        self.max_total_tokens = max_total_tokens
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

    def run(self, system: str, user_message: str) -> CopilotResult:
        messages: list[dict] = [{"role": "user", "content": user_message}]
        valid_ids: set[str] = set()
        proposals: list[dict] = []
        tool_results: list[dict] = []
        usage_total = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}
        repairs = 0

        for iteration in range(1, self.max_iters + 1):
            resp = self.client.complete(
                system=system, messages=messages, tools=self.registry.definitions()
            )
            for key in usage_total:
                usage_total[key] += resp.usage.get(key, 0)
            self.audit_hook("llm_completion", {"usage": resp.usage, "stop": resp.stop_reason})

            spent = usage_total["input_tokens"] + usage_total["output_tokens"]
            if spent > self.max_total_tokens:
                return CopilotResult(
                    text=SAFE_FALLBACK, grounded=False, record_ids=sorted(valid_ids),
                    proposals=proposals, tool_results=tool_results, usage=usage_total,
                    iterations=iteration, repairs=repairs, stop_reason="token_budget",
                    reason="token budget exceeded",
                )

            if resp.stop_reason == "tool_use" and resp.tool_calls:
                messages.append({"role": "assistant", "content": self._assistant_content(resp)})
                result_blocks = []
                for call in resp.tool_calls:
                    out = self.registry.execute(call["name"], call["input"])
                    self.audit_hook("tool_call", {"name": call["name"], "input": call["input"]})
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

            # Final natural-language answer: enforce grounding.
            gr = validate_grounding(resp.text, valid_ids)
            if gr.ok:
                self.audit_hook("answer", {"grounded": True, "record_ids": sorted(valid_ids)})
                return CopilotResult(
                    text=resp.text, grounded=True, record_ids=sorted(valid_ids),
                    proposals=proposals, tool_results=tool_results, usage=usage_total,
                    iterations=iteration, repairs=repairs, stop_reason=resp.stop_reason,
                )
            if repairs < self.max_repairs:
                repairs += 1
                messages.append({"role": "assistant", "content": resp.text})
                messages.append({"role": "user", "content": repair_instruction(gr)})
                continue

            self.audit_hook("answer", {"grounded": False, "reason": gr.reason})
            return CopilotResult(
                text=SAFE_FALLBACK, grounded=False, record_ids=sorted(valid_ids),
                proposals=proposals, tool_results=tool_results, usage=usage_total,
                iterations=iteration, repairs=repairs, stop_reason="ungrounded",
                reason=gr.reason,
            )

        return CopilotResult(
            text=SAFE_FALLBACK, grounded=False, record_ids=sorted(valid_ids),
            proposals=proposals, tool_results=tool_results, usage=usage_total,
            iterations=self.max_iters, repairs=repairs, stop_reason="max_iters",
            reason="max tool iterations reached",
        )
