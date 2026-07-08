"""Deterministic host-event scorer for the node path.

This is the Month-1 spine scorer: explicit rules, fully deterministic, easy to
test. It implements the HostEventScorer seam so the Month-2 trained ML detector
can be dropped in without touching the consumer.
"""

from __future__ import annotations

import re
from typing import Protocol

THREAT_COMMS = {"nc", "ncat", "socat", "msfconsole", "mimikatz"}
SHELL_COMMS = {"sh", "bash", "zsh", "dash", "ksh"}
WORLD_WRITABLE_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")
# Binaries whose mere execution is a strong privilege-escalation signal on a
# self-protecting single host (GTFOBins-style setuid/polkit vectors).
PRIVESC_COMMS = {"pkexec", "setcap", "getcap"}
# Groups that grant root-equivalent or container-escape power.
PRIVILEGED_GROUPS = {"sudo", "admin", "wheel", "root", "docker", "lxd", "adm"}
# Reading these is credential theft (hashes) regardless of the process.
CREDENTIAL_FILES = ("/etc/shadow", "/etc/gshadow")
DOWNLOADERS = ("curl", "wget", "fetch")
THRESHOLD = 0.5

# A numeric chmod mode that sets the setuid/setgid bit (leading 4/2/6 in a
# 4-digit octal mode, e.g. 4755). Symbolic form (u+s / g+s) is matched textually.
_SETUID_NUMERIC_RE = re.compile(r"\b[642]\d{3}\b")
_PIPE_TO_SHELL_RE = re.compile(r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python\d?)\b")


def _pipes_to_shell(args: str) -> bool:
    return bool(_PIPE_TO_SHELL_RE.search(args))


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

    # --- privilege escalation -------------------------------------------
    if "/etc/sudoers" in args and _writes(args):
        score = max(score, 0.95)
        reasons.append("write to /etc/sudoers (privilege escalation)")
    if comm == "chmod" and ("u+s" in args or "g+s" in args or _setuid_numeric(args)):
        score = max(score, 0.75)
        reasons.append("setuid/setgid bit added (privilege escalation)")
    if comm == "setcap" and "cap_" in args:
        score = max(score, 0.75)
        reasons.append("privilege-escalation: file capabilities granted (setcap)")
    elif comm in PRIVESC_COMMS:
        score = max(score, 0.75)
        reasons.append(f"privilege-escalation binary '{comm}'")
    if comm in ("usermod", "gpasswd", "adduser") and _adds_privileged_group(args):
        score = max(score, 0.75)
        reasons.append("user added to privileged group (privilege escalation)")
    if any(f in args for f in CREDENTIAL_FILES) and comm != "chmod":
        score = max(score, 0.7)
        reasons.append("credential store access (/etc/shadow)")

    # --- suspicious execution -------------------------------------------
    if any(d in args for d in DOWNLOADERS) and _pipes_to_shell(args):
        score = max(score, 0.9)
        reasons.append("remote download piped to a shell")
    if (
        "base64" in args
        and ("-d" in args or "--decode" in args)
        and _pipes_to_shell(args)
    ):
        score = max(score, 0.85)
        reasons.append("base64-decoded payload piped to a shell")
    if (
        comm == "chmod"
        and ("+x" in args or _exec_numeric(args))
        and _targets_world_writable(args)
    ):
        score = max(score, 0.65)
        reasons.append("made a world-writable file executable")

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


def _writes(args: str) -> bool:
    """True when the command line redirects/appends into a file (>, >>, tee)."""
    return ">>" in args or ">" in args or "tee " in args


def _setuid_numeric(args: str) -> bool:
    return bool(_SETUID_NUMERIC_RE.search(args))


def _exec_numeric(args: str) -> bool:
    """A numeric chmod mode granting execute to anyone (odd/7/5 low digits)."""
    for token in args.split():
        if re.fullmatch(r"[0-7]{3,4}", token) and int(token[-3:]) & 0o111:
            return True
    return False


def _targets_world_writable(args: str) -> bool:
    return any(prefix.rstrip("/") in args for prefix in WORLD_WRITABLE_PREFIXES)


def _adds_privileged_group(args: str) -> bool:
    tokens = args.split()
    return any(g in tokens for g in PRIVILEGED_GROUPS)


class HostEventScorer(Protocol):
    def score(self, event: dict) -> dict: ...


class RuleScorer:
    """Default Month-1 scorer. Swap for the ML detector in Month-2."""

    def score(self, event: dict) -> dict:
        return score_event(event)
