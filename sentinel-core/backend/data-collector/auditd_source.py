"""Pure auditd-record parsing for the offline node path. No I/O."""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

_KV_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')
_MSG_TS_RE = re.compile(r"audit\((\d+)\.(\d+):(\d+)\)")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
# x86_64 execve=59, execveat=322; auditd may also render the name when interpreted.
_EXECVE_SYSCALLS = {"59", "322", "execve", "execveat"}
_HOSTNAME = socket.gethostname()


def _parse_kv_with_quote_info(line: str) -> dict[str, tuple[str, bool]]:
    """Return {key: (value, was_quoted)} for each kv pair in line."""
    out: dict[str, tuple[str, bool]] = {}
    for m in _KV_RE.finditer(line):
        key = m.group(1)
        was_quoted = m.group(3) is not None
        val = m.group(3) if was_quoted else m.group(2)
        out[key] = (val, was_quoted)
    return out


def _parse_kv(line: str) -> dict[str, str]:
    return {k: v for k, (v, _) in _parse_kv_with_quote_info(line).items()}


def _maybe_hex_decode(v: str, was_quoted: bool) -> str:
    """Decode bare even-length hex runs to UTF-8; quoted values are always literal."""
    if was_quoted or not _HEX_RE.match(v):
        return v
    try:
        return bytes.fromhex(v).decode("utf-8", errors="replace")
    except ValueError:
        return v


def _parse_msg_ts(msg: str) -> str:
    m = _MSG_TS_RE.search(msg)
    if not m:
        return ""
    epoch = int(m.group(1)) + int(m.group(2)) / 1000.0
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _to_int(v: object, default: int = 0) -> int:
    try:
        return int(v)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return default


def _decode_args(execve_line: str) -> list[str]:
    kv_info = _parse_kv_with_quote_info(execve_line)
    args: list[str] = []
    i = 0
    while f"a{i}" in kv_info:
        val, was_quoted = kv_info[f"a{i}"]
        args.append(_maybe_hex_decode(val, was_quoted))
        i += 1
    return args


def parse_event(lines: list[str]) -> dict | None:
    syscall_kv_info: dict[str, tuple[str, bool]] = {}
    execve_line = ""
    for line in lines:
        if line.startswith("type=SYSCALL"):
            syscall_kv_info = _parse_kv_with_quote_info(line)
        elif line.startswith("type=EXECVE"):
            execve_line = line
    if syscall_kv_info.get("syscall", ("", False))[0] not in _EXECVE_SYSCALLS:
        return None
    msg = next((ln for ln in lines if "msg=audit(" in ln), "")
    comm_val, comm_quoted = syscall_kv_info.get("comm", ("", True))
    exe_val, exe_quoted = syscall_kv_info.get("exe", ("", True))
    pid_val, _ = syscall_kv_info.get("pid", ("0", False))
    uid_val, _ = syscall_kv_info.get("uid", ("0", False))
    return {
        "event_type": "execve",
        "timestamp": _parse_msg_ts(msg),
        "pid": _to_int(pid_val),
        "uid": _to_int(uid_val),
        "comm": _maybe_hex_decode(comm_val, comm_quoted),
        "exe": _maybe_hex_decode(exe_val, exe_quoted),
        "args": _decode_args(execve_line),
        "hostname": _HOSTNAME,
        "raw": "\n".join(lines),
    }
