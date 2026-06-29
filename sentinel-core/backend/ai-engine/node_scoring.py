"""Deterministic host-event scorer for the node path.

This is the Month-1 spine scorer: explicit rules, fully deterministic, easy to
test. It implements the HostEventScorer seam so the Month-2 trained ML detector
can be dropped in without touching the consumer.
"""

from __future__ import annotations

from typing import Protocol

THREAT_COMMS = {"nc", "ncat", "socat", "msfconsole", "mimikatz"}
SHELL_COMMS = {"sh", "bash", "zsh", "dash", "ksh"}
WORLD_WRITABLE_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")
THRESHOLD = 0.5


def score_event(event: dict) -> dict:
    comm = (event.get("comm") or "").lower()
    exe = (event.get("exe") or "").lower()
    args = " ".join(event.get("args") or []).lower()
    score = 0.0
    reasons: list[str] = []

    if "/dev/tcp/" in args or "/dev/udp/" in args:
        score = max(score, 0.95)
        reasons.append("shell redirect to /dev/tcp (reverse shell)")
    if comm in THREAT_COMMS:
        score = max(score, 0.9)
        reasons.append(f"offensive tool '{comm}'")
    if exe.startswith(WORLD_WRITABLE_PREFIXES):
        score = max(score, 0.7)
        reasons.append(f"exec from world-writable path '{exe}'")
    if comm in SHELL_COMMS and (" -i" in f" {args}" or args.endswith(" -i")):
        score = max(score, 0.6)
        reasons.append("interactive shell")

    is_threat = score >= THRESHOLD
    if score >= 0.9:
        severity = "critical"
    elif score >= 0.7:
        severity = "high"
    elif score >= THRESHOLD:
        severity = "medium"
    else:
        severity = "info"

    return {
        "is_threat": is_threat,
        "score": round(score, 4),
        "severity": severity,
        "summary": "; ".join(reasons) or "no suspicious indicators",
    }


class HostEventScorer(Protocol):
    def score(self, event: dict) -> dict: ...


class RuleScorer:
    """Default Month-1 scorer. Swap for the ML detector in Month-2."""

    def score(self, event: dict) -> dict:
        return score_event(event)
