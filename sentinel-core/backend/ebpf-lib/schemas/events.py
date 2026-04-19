"""eBPF event schemas for SENTINEL kernel instrumentation.

Defines the canonical event types emitted by eBPF programs running in
XDP, tracepoint, kprobe, and LSM attach points.  Each event maps 1:1
to a packed C struct produced by the kernel-side eBPF program and read
from a BPF ring-buffer or perf-event array.

Binary layout constants (offsets, sizes) match the structs defined in
``ebpf-lib/src/*.bpf.c``.
"""

from __future__ import annotations

import json
import logging
import socket
import struct
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Type, Union

logger = logging.getLogger("sentinel.ebpf.events")


# ── Enumerations ──────────────────────────────────────────────────────


class EventType(IntEnum):
    NETWORK_FLOW = 1
    PROCESS_EXEC = 2
    FILE_ACCESS = 3
    NETWORK_CONNECT = 4
    PRIVILEGE_ESCALATION = 5
    MODULE_LOAD = 6
    FIM_ALERT = 7
    POLICY_VIOLATION = 8


class PolicyAction(IntEnum):
    ALLOW = 0
    DENY = 1
    LOG = 2
    RATE_LIMIT = 3
    QUARANTINE = 4


# ── Event dataclasses ─────────────────────────────────────────────────


@dataclass(slots=True)
class NetworkFlowEvent:
    """XDP flow summary exported from the per-flow hash map."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    bytes_sent: int
    bytes_recv: int
    packets: int
    duration: float
    flags: int
    event_type: EventType = EventType.NETWORK_FLOW


@dataclass(slots=True)
class ProcessExecEvent:
    """sched_process_exec tracepoint — new process execution."""

    timestamp: float
    pid: int
    ppid: int
    uid: int
    comm: str
    filename: str
    args: List[str] = field(default_factory=list)
    event_type: EventType = EventType.PROCESS_EXEC


@dataclass(slots=True)
class FileAccessEvent:
    """sys_enter_openat tracepoint — sensitive file access."""

    timestamp: float
    pid: int
    uid: int
    path: str
    flags: int
    mode: str
    event_type: EventType = EventType.FILE_ACCESS


@dataclass(slots=True)
class NetworkConnectEvent:
    """tcp_v4_connect kprobe — outbound connection per process."""

    timestamp: float
    pid: int
    uid: int
    comm: str
    dst_ip: str
    dst_port: int
    protocol: int
    event_type: EventType = EventType.NETWORK_CONNECT


NetConnectEvent = NetworkConnectEvent


@dataclass(slots=True)
class PrivEscalationEvent:
    """sys_enter_setuid tracepoint — privilege escalation attempt."""

    timestamp: float
    pid: int
    uid: int
    target_uid: int
    comm: str
    event_type: EventType = EventType.PRIVILEGE_ESCALATION


@dataclass(slots=True)
class ModuleLoadEvent:
    """module_load tracepoint — kernel module insertion."""

    timestamp: float
    name: str
    pid: int
    uid: int
    event_type: EventType = EventType.MODULE_LOAD


@dataclass(slots=True)
class HIDSEvent:
    """Generic HIDS event for aggregated / synthetic alerts."""

    timestamp: float
    event_type: EventType
    severity: str
    data: Dict[str, Any] = field(default_factory=dict)


# ── Type registry ────────────────────────────────────────────────────

_EVENT_CLASSES: Dict[EventType, Type] = {
    EventType.NETWORK_FLOW: NetworkFlowEvent,
    EventType.PROCESS_EXEC: ProcessExecEvent,
    EventType.FILE_ACCESS: FileAccessEvent,
    EventType.NETWORK_CONNECT: NetworkConnectEvent,
    EventType.PRIVILEGE_ESCALATION: PrivEscalationEvent,
    EventType.MODULE_LOAD: ModuleLoadEvent,
    EventType.FIM_ALERT: HIDSEvent,
    EventType.POLICY_VIOLATION: HIDSEvent,
}

# ── Binary layout constants ──────────────────────────────────────────
#
# These match the packed C structs in ebpf-lib/src/*.bpf.c.
# All multi-byte fields are little-endian (host byte order on x86_64).
# IP addresses are stored as __u32 in network byte order.

_NETWORK_FLOW_FMT = "<Q II HH B 3x QQ I I I"
_NETWORK_FLOW_SIZE = struct.calcsize(_NETWORK_FLOW_FMT)

_PROCESS_EXEC_FMT = "<Q I I I 16s 256s"
_PROCESS_EXEC_SIZE = struct.calcsize(_PROCESS_EXEC_FMT)

_FILE_ACCESS_FMT = "<Q I I 256s I 8s"
_FILE_ACCESS_SIZE = struct.calcsize(_FILE_ACCESS_FMT)

_NET_CONNECT_FMT = "<Q I I 16s I H 2x B 3x"
_NET_CONNECT_SIZE = struct.calcsize(_NET_CONNECT_FMT)

_PRIV_ESCALATION_FMT = "<Q I I I 16s"
_PRIV_ESCALATION_SIZE = struct.calcsize(_PRIV_ESCALATION_FMT)

_MODULE_LOAD_FMT = "<Q 64s I I"
_MODULE_LOAD_SIZE = struct.calcsize(_MODULE_LOAD_FMT)


def _ip_u32_to_str(addr: int) -> str:
    """Convert a __u32 in network byte order to dotted-quad string."""
    return socket.inet_ntoa(struct.pack("!I", addr))


def _cstr(raw: bytes) -> str:
    """Extract a C string (null-terminated) from a fixed-size byte buffer."""
    idx = raw.find(b"\x00")
    if idx >= 0:
        raw = raw[:idx]
    return raw.decode("utf-8", errors="replace")


# ── Decoders ─────────────────────────────────────────────────────────


def _decode_network_flow(data: bytes) -> NetworkFlowEvent:
    (
        ts_ns,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        bytes_sent,
        bytes_recv,
        packets,
        duration_ms,
        flags,
    ) = struct.unpack_from(_NETWORK_FLOW_FMT, data)
    return NetworkFlowEvent(
        timestamp=ts_ns / 1e9,
        src_ip=_ip_u32_to_str(src_ip),
        dst_ip=_ip_u32_to_str(dst_ip),
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        packets=packets,
        duration=duration_ms / 1000.0,
        flags=flags,
    )


def _decode_process_exec(data: bytes) -> ProcessExecEvent:
    ts_ns, pid, ppid, uid, comm_raw, filename_raw = struct.unpack_from(
        _PROCESS_EXEC_FMT,
        data,
    )
    return ProcessExecEvent(
        timestamp=ts_ns / 1e9,
        pid=pid,
        ppid=ppid,
        uid=uid,
        comm=_cstr(comm_raw),
        filename=_cstr(filename_raw),
    )


def _decode_file_access(data: bytes) -> FileAccessEvent:
    ts_ns, pid, uid, path_raw, flags, mode_raw = struct.unpack_from(
        _FILE_ACCESS_FMT,
        data,
    )
    return FileAccessEvent(
        timestamp=ts_ns / 1e9,
        pid=pid,
        uid=uid,
        path=_cstr(path_raw),
        flags=flags,
        mode=_cstr(mode_raw),
    )


def _decode_net_connect(data: bytes) -> NetworkConnectEvent:
    ts_ns, pid, uid, comm_raw, dst_ip, dst_port, proto = struct.unpack_from(
        _NET_CONNECT_FMT,
        data,
    )
    return NetworkConnectEvent(
        timestamp=ts_ns / 1e9,
        pid=pid,
        uid=uid,
        comm=_cstr(comm_raw),
        dst_ip=_ip_u32_to_str(dst_ip),
        dst_port=dst_port,
        protocol=proto,
    )


def _decode_priv_escalation(data: bytes) -> PrivEscalationEvent:
    ts_ns, pid, uid, target_uid, comm_raw = struct.unpack_from(
        _PRIV_ESCALATION_FMT,
        data,
    )
    return PrivEscalationEvent(
        timestamp=ts_ns / 1e9,
        pid=pid,
        uid=uid,
        target_uid=target_uid,
        comm=_cstr(comm_raw),
    )


def _decode_module_load(data: bytes) -> ModuleLoadEvent:
    ts_ns, name_raw, pid, uid = struct.unpack_from(_MODULE_LOAD_FMT, data)
    return ModuleLoadEvent(
        timestamp=ts_ns / 1e9,
        name=_cstr(name_raw),
        pid=pid,
        uid=uid,
    )


_DECODERS = {
    EventType.NETWORK_FLOW: _decode_network_flow,
    EventType.PROCESS_EXEC: _decode_process_exec,
    EventType.FILE_ACCESS: _decode_file_access,
    EventType.NETWORK_CONNECT: _decode_net_connect,
    EventType.PRIVILEGE_ESCALATION: _decode_priv_escalation,
    EventType.MODULE_LOAD: _decode_module_load,
}

_MIN_SIZES = {
    EventType.NETWORK_FLOW: _NETWORK_FLOW_SIZE,
    EventType.PROCESS_EXEC: _PROCESS_EXEC_SIZE,
    EventType.FILE_ACCESS: _FILE_ACCESS_SIZE,
    EventType.NETWORK_CONNECT: _NET_CONNECT_SIZE,
    EventType.PRIVILEGE_ESCALATION: _PRIV_ESCALATION_SIZE,
    EventType.MODULE_LOAD: _MODULE_LOAD_SIZE,
}


# ── Public API ───────────────────────────────────────────────────────


def decode_event(
    raw_bytes: bytes,
    event_type: EventType,
) -> Optional[
    Union[
        NetworkFlowEvent,
        ProcessExecEvent,
        FileAccessEvent,
        NetworkConnectEvent,
        PrivEscalationEvent,
        ModuleLoadEvent,
    ]
]:
    """Parse a binary eBPF ring-buffer record into the appropriate dataclass.

    Returns ``None`` if the buffer is too short or the event type has no
    registered decoder.
    """
    decoder = _DECODERS.get(event_type)
    if decoder is None:
        logger.warning("No decoder for event type %s", event_type)
        return None

    min_size = _MIN_SIZES.get(event_type, 0)
    if len(raw_bytes) < min_size:
        logger.warning(
            "Buffer too short for %s: got %d, need %d",
            event_type.name,
            len(raw_bytes),
            min_size,
        )
        return None

    try:
        return decoder(raw_bytes)
    except struct.error as exc:
        logger.error("Failed to decode %s event: %s", event_type.name, exc)
        return None


class _EventEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, IntEnum):
            return o.name
        return super().default(o)


def event_to_json(event: Any) -> str:
    """Serialize any event dataclass to a JSON string.

    IntEnum fields are serialized by name for readability.
    """
    return json.dumps(asdict(event), cls=_EventEncoder, separators=(",", ":"))


PYTHON_EVENT_MAP = {
    EventType.NETWORK_FLOW: NetworkFlowEvent,
    EventType.PROCESS_EXEC: ProcessExecEvent,
    EventType.FILE_ACCESS: FileAccessEvent,
    EventType.NETWORK_CONNECT: NetworkConnectEvent,
    EventType.PRIVILEGE_ESCALATION: PrivEscalationEvent,
    EventType.MODULE_LOAD: ModuleLoadEvent,
}
