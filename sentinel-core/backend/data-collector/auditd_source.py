"""Pure auditd-record parsing for the offline node path. No I/O."""
from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

_KV_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')
_MSG_TS_RE = re.compile(r"audit\((\d+)\.(\d+):(\d+)\)")
# x86_64 execve=59, execveat=322; auditd may also render the name when interpreted.
_EXECVE_SYSCALLS = {"59", "322", "execve", "execveat"}


def _parse_kv(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _KV_RE.finditer(line):
        key = m.group(1)
        out[key] = m.group(3) if m.group(3) is not None else m.group(2)
    return out


def _parse_msg_ts(msg: str) -> str:
    m = _MSG_TS_RE.search(msg)
    if not m:
        return datetime.now(timezone.utc).isoformat()
    epoch = int(m.group(1)) + int(m.group(2)) / 1000.0
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _decode_args(execve_kv: dict[str, str]) -> list[str]:
    args: list[str] = []
    i = 0
    while f"a{i}" in execve_kv:
        args.append(execve_kv[f"a{i}"])
        i += 1
    return args


def parse_event(lines: list[str]) -> dict | None:
    syscall_kv: dict[str, str] = {}
    execve_kv: dict[str, str] = {}
    for line in lines:
        if line.startswith("type=SYSCALL"):
            syscall_kv = _parse_kv(line)
        elif line.startswith("type=EXECVE"):
            execve_kv = _parse_kv(line)
    if syscall_kv.get("syscall") not in _EXECVE_SYSCALLS:
        return None
    msg = next((l for l in lines if "msg=audit(" in l), "")
    return {
        "event_type": "execve",
        "timestamp": _parse_msg_ts(msg),
        "pid": int(syscall_kv.get("pid", 0) or 0),
        "uid": int(syscall_kv.get("uid", 0) or 0),
        "comm": syscall_kv.get("comm", ""),
        "exe": syscall_kv.get("exe", ""),
        "args": _decode_args(execve_kv),
        "hostname": socket.gethostname(),
        "raw": "\n".join(lines),
    }
