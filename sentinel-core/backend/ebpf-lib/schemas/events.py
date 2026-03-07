"""SENTINEL eBPF event schemas.

Mirror the C struct definitions from programs/common/types.h so that
user-space Python code can deserialize ring buffer events.
"""

from __future__ import annotations

import ctypes
import enum
import json
from dataclasses import asdict, dataclass, field
from typing import Any


class EventType(enum.IntEnum):
    NETWORK_FLOW = 1
    PROCESS_EXEC = 2
    FILE_ACCESS = 3
    NET_CONNECT = 4
    PRIV_ESCALATION = 5
    MODULE_LOAD = 6
    POLICY_DECISION = 7
    PTRACE_ATTACH = 8


class PolicyAction(enum.IntEnum):
    ALLOW = 0
    DENY = 1
    LOG = 2


# ── ctypes structs matching the C definitions ──────────────────────


class CFlowKey(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 3),
    ]


class CFlowValue(ctypes.LittleEndianStructure):
    _fields_ = [
        ("packets", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
        ("first_seen_ns", ctypes.c_uint64),
        ("last_seen_ns", ctypes.c_uint64),
        ("tcp_flags", ctypes.c_uint32),
        ("syn_count", ctypes.c_uint32),
        ("rst_count", ctypes.c_uint32),
        ("fin_count", ctypes.c_uint32),
    ]


class CNetworkFlowEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("key", CFlowKey),
        ("value", CFlowValue),
    ]


class CProcessExecEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]


class CFileAccessEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("path", ctypes.c_char * 256),
    ]


class CNetConnectEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8),
        ("comm", ctypes.c_char * 16),
    ]


class CPrivEscalationEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("target_uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]


class CModuleLoadEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("name", ctypes.c_char * 64),
    ]


class CPolicyDecisionEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("action", ctypes.c_uint32),
        ("rule_id", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("detail", ctypes.c_char * 128),
    ]


EVENT_STRUCT_MAP: dict[int, type[ctypes.Structure]] = {
    EventType.NETWORK_FLOW: CNetworkFlowEvent,
    EventType.PROCESS_EXEC: CProcessExecEvent,
    EventType.FILE_ACCESS: CFileAccessEvent,
    EventType.NET_CONNECT: CNetConnectEvent,
    EventType.PRIV_ESCALATION: CPrivEscalationEvent,
    EventType.MODULE_LOAD: CModuleLoadEvent,
    EventType.POLICY_DECISION: CPolicyDecisionEvent,
}


# ── Python dataclass representations (JSON-serializable) ───────────

def _ip_to_str(ip: int) -> str:
    """Convert a 32-bit IPv4 integer (network byte order) to dotted string."""
    b = ip.to_bytes(4, "little")
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


@dataclass
class NetworkFlowEvent:
    event_type: str = "network_flow"
    timestamp_ns: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    packets: int = 0
    bytes: int = 0
    duration_ns: int = 0
    tcp_flags: int = 0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0

    @classmethod
    def from_c(cls, c: CNetworkFlowEvent) -> NetworkFlowEvent:
        return cls(
            timestamp_ns=c.timestamp_ns,
            src_ip=_ip_to_str(c.key.src_ip),
            dst_ip=_ip_to_str(c.key.dst_ip),
            src_port=c.key.src_port,
            dst_port=c.key.dst_port,
            protocol=c.key.protocol,
            packets=c.value.packets,
            bytes=c.value.bytes,
            duration_ns=c.value.last_seen_ns - c.value.first_seen_ns,
            tcp_flags=c.value.tcp_flags,
            syn_count=c.value.syn_count,
            rst_count=c.value.rst_count,
            fin_count=c.value.fin_count,
        )


@dataclass
class ProcessExecEvent:
    event_type: str = "process_exec"
    timestamp_ns: int = 0
    pid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    comm: str = ""
    filename: str = ""

    @classmethod
    def from_c(cls, c: CProcessExecEvent) -> ProcessExecEvent:
        return cls(
            timestamp_ns=c.timestamp_ns,
            pid=c.pid, ppid=c.ppid,
            uid=c.uid, gid=c.gid,
            comm=c.comm.decode(errors="replace").rstrip("\x00"),
            filename=c.filename.decode(errors="replace").rstrip("\x00"),
        )


@dataclass
class FileAccessEvent:
    event_type: str = "file_access"
    timestamp_ns: int = 0
    pid: int = 0
    uid: int = 0
    flags: int = 0
    comm: str = ""
    path: str = ""

    @classmethod
    def from_c(cls, c: CFileAccessEvent) -> FileAccessEvent:
        return cls(
            timestamp_ns=c.timestamp_ns,
            pid=c.pid, uid=c.uid, flags=c.flags,
            comm=c.comm.decode(errors="replace").rstrip("\x00"),
            path=c.path.decode(errors="replace").rstrip("\x00"),
        )


@dataclass
class NetConnectEvent:
    event_type: str = "net_connect"
    timestamp_ns: int = 0
    pid: int = 0
    uid: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: int = 0
    comm: str = ""

    @classmethod
    def from_c(cls, c: CNetConnectEvent) -> NetConnectEvent:
        return cls(
            timestamp_ns=c.timestamp_ns,
            pid=c.pid, uid=c.uid,
            dst_ip=_ip_to_str(c.dst_ip),
            dst_port=c.dst_port,
            protocol=c.protocol,
            comm=c.comm.decode(errors="replace").rstrip("\x00"),
        )


@dataclass
class PrivEscalationEvent:
    event_type: str = "priv_escalation"
    timestamp_ns: int = 0
    pid: int = 0
    uid: int = 0
    target_uid: int = 0
    comm: str = ""

    @classmethod
    def from_c(cls, c: CPrivEscalationEvent) -> PrivEscalationEvent:
        return cls(
            timestamp_ns=c.timestamp_ns,
            pid=c.pid, uid=c.uid,
            target_uid=c.target_uid,
            comm=c.comm.decode(errors="replace").rstrip("\x00"),
        )


@dataclass
class ModuleLoadEvent:
    event_type: str = "module_load"
    timestamp_ns: int = 0
    pid: int = 0
    uid: int = 0
    name: str = ""

    @classmethod
    def from_c(cls, c: CModuleLoadEvent) -> ModuleLoadEvent:
        return cls(
            timestamp_ns=c.timestamp_ns,
            pid=c.pid, uid=c.uid,
            name=c.name.decode(errors="replace").rstrip("\x00"),
        )


@dataclass
class PolicyDecisionEvent:
    event_type: str = "policy_decision"
    timestamp_ns: int = 0
    pid: int = 0
    uid: int = 0
    action: str = ""
    rule_id: int = 0
    comm: str = ""
    detail: str = ""

    @classmethod
    def from_c(cls, c: CPolicyDecisionEvent) -> PolicyDecisionEvent:
        return cls(
            timestamp_ns=c.timestamp_ns,
            pid=c.pid, uid=c.uid,
            action=PolicyAction(c.action).name.lower(),
            rule_id=c.rule_id,
            comm=c.comm.decode(errors="replace").rstrip("\x00"),
            detail=c.detail.decode(errors="replace").rstrip("\x00"),
        )


PYTHON_EVENT_MAP: dict[int, type] = {
    EventType.NETWORK_FLOW: NetworkFlowEvent,
    EventType.PROCESS_EXEC: ProcessExecEvent,
    EventType.FILE_ACCESS: FileAccessEvent,
    EventType.NET_CONNECT: NetConnectEvent,
    EventType.PRIV_ESCALATION: PrivEscalationEvent,
    EventType.MODULE_LOAD: ModuleLoadEvent,
    EventType.POLICY_DECISION: PolicyDecisionEvent,
}


def decode_event(data: bytes) -> Any:
    """Decode raw ring buffer bytes into a Python dataclass."""
    if len(data) < 4:
        return None
    event_type = int.from_bytes(data[:4], "little")
    c_type = EVENT_STRUCT_MAP.get(event_type)
    py_type = PYTHON_EVENT_MAP.get(event_type)
    if not c_type or not py_type:
        return None
    if len(data) < ctypes.sizeof(c_type):
        return None
    c_event = c_type.from_buffer_copy(data)
    return py_type.from_c(c_event)


def event_to_json(event: Any) -> str:
    """Serialize an event dataclass to JSON."""
    return json.dumps(asdict(event))
