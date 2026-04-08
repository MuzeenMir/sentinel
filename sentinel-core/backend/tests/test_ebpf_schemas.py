"""Tests for the eBPF event schema deserialization layer."""

import ctypes
import json
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ebpf_lib.schemas.events import (
    EventType,
    PolicyAction,
    CNetworkFlowEvent,
    CProcessExecEvent,
    CFileAccessEvent,
    CNetConnectEvent,
    CPrivEscalationEvent,
    CModuleLoadEvent,
    CPolicyDecisionEvent,
    NetworkFlowEvent,
    ProcessExecEvent,
    FileAccessEvent,
    NetConnectEvent,
    PrivEscalationEvent,
    ModuleLoadEvent,
    PolicyDecisionEvent,
    decode_event,
    event_to_json,
)


class TestEventTypes:
    def test_event_type_values(self):
        assert EventType.NETWORK_FLOW == 1
        assert EventType.PROCESS_EXEC == 2
        assert EventType.FILE_ACCESS == 3
        assert EventType.NET_CONNECT == 4
        assert EventType.PRIV_ESCALATION == 5
        assert EventType.MODULE_LOAD == 6
        assert EventType.POLICY_DECISION == 7

    def test_policy_action_values(self):
        assert PolicyAction.ALLOW == 0
        assert PolicyAction.DENY == 1
        assert PolicyAction.LOG == 2


class TestNetworkFlowEvent:
    def _make_c_event(self) -> bytes:
        evt = CNetworkFlowEvent()
        evt.event_type = EventType.NETWORK_FLOW
        evt.timestamp_ns = 1000000
        evt.key.src_ip = 0x0100A8C0  # 192.168.0.1 in little-endian
        evt.key.dst_ip = 0x0101A8C0  # 192.168.1.1
        evt.key.src_port = 12345
        evt.key.dst_port = 80
        evt.key.protocol = 6  # TCP
        evt.value.packets = 100
        evt.value.bytes = 5000
        evt.value.first_seen_ns = 500000
        evt.value.last_seen_ns = 1000000
        evt.value.tcp_flags = 0x12  # SYN+ACK
        evt.value.syn_count = 1
        evt.value.rst_count = 0
        evt.value.fin_count = 0
        return bytes(evt)

    def test_decode_network_flow(self):
        data = self._make_c_event()
        event = decode_event(data)
        assert isinstance(event, NetworkFlowEvent)
        assert event.event_type == "network_flow"
        assert event.src_port == 12345
        assert event.dst_port == 80
        assert event.protocol == 6
        assert event.packets == 100
        assert event.bytes == 5000
        assert event.syn_count == 1

    def test_network_flow_to_json(self):
        data = self._make_c_event()
        event = decode_event(data)
        json_str = event_to_json(event)
        parsed = json.loads(json_str)
        assert parsed["event_type"] == "network_flow"
        assert parsed["packets"] == 100
        assert "src_ip" in parsed


class TestProcessExecEvent:
    def _make_c_event(self) -> bytes:
        evt = CProcessExecEvent()
        evt.event_type = EventType.PROCESS_EXEC
        evt.timestamp_ns = 2000000
        evt.pid = 1234
        evt.ppid = 1
        evt.uid = 0
        evt.gid = 0
        evt.comm = b"sshd"
        evt.filename = b"/usr/sbin/sshd"
        return bytes(evt)

    def test_decode_process_exec(self):
        data = self._make_c_event()
        event = decode_event(data)
        assert isinstance(event, ProcessExecEvent)
        assert event.pid == 1234
        assert event.ppid == 1
        assert event.uid == 0
        assert event.comm == "sshd"
        assert event.filename == "/usr/sbin/sshd"


class TestFileAccessEvent:
    def _make_c_event(self) -> bytes:
        evt = CFileAccessEvent()
        evt.event_type = EventType.FILE_ACCESS
        evt.timestamp_ns = 3000000
        evt.pid = 5678
        evt.uid = 1000
        evt.flags = 0
        evt.comm = b"cat"
        evt.path = b"/etc/passwd"
        return bytes(evt)

    def test_decode_file_access(self):
        data = self._make_c_event()
        event = decode_event(data)
        assert isinstance(event, FileAccessEvent)
        assert event.pid == 5678
        assert event.path == "/etc/passwd"
        assert event.comm == "cat"


class TestNetConnectEvent:
    def _make_c_event(self) -> bytes:
        evt = CNetConnectEvent()
        evt.event_type = EventType.NET_CONNECT
        evt.timestamp_ns = 4000000
        evt.pid = 9999
        evt.uid = 0
        evt.dst_ip = 0x08080808  # 8.8.8.8
        evt.dst_port = 443
        evt.protocol = 6
        evt.comm = b"curl"
        return bytes(evt)

    def test_decode_net_connect(self):
        data = self._make_c_event()
        event = decode_event(data)
        assert isinstance(event, NetConnectEvent)
        assert event.dst_port == 443
        assert event.protocol == 6
        assert event.comm == "curl"


class TestPrivEscalationEvent:
    def _make_c_event(self) -> bytes:
        evt = CPrivEscalationEvent()
        evt.event_type = EventType.PRIV_ESCALATION
        evt.timestamp_ns = 5000000
        evt.pid = 4444
        evt.uid = 1000
        evt.target_uid = 0
        evt.comm = b"sudo"
        return bytes(evt)

    def test_decode_priv_escalation(self):
        data = self._make_c_event()
        event = decode_event(data)
        assert isinstance(event, PrivEscalationEvent)
        assert event.uid == 1000
        assert event.target_uid == 0
        assert event.comm == "sudo"


class TestModuleLoadEvent:
    def _make_c_event(self) -> bytes:
        evt = CModuleLoadEvent()
        evt.event_type = EventType.MODULE_LOAD
        evt.timestamp_ns = 6000000
        evt.pid = 1
        evt.uid = 0
        evt.name = b"nf_conntrack"
        return bytes(evt)

    def test_decode_module_load(self):
        data = self._make_c_event()
        event = decode_event(data)
        assert isinstance(event, ModuleLoadEvent)
        assert event.name == "nf_conntrack"


class TestPolicyDecisionEvent:
    def _make_c_event(self) -> bytes:
        evt = CPolicyDecisionEvent()
        evt.event_type = EventType.POLICY_DECISION
        evt.timestamp_ns = 7000000
        evt.pid = 2222
        evt.uid = 0
        evt.action = PolicyAction.DENY
        evt.rule_id = 1
        evt.comm = b"nc"
        evt.detail = b"bind_port_denied"
        return bytes(evt)

    def test_decode_policy_decision(self):
        data = self._make_c_event()
        event = decode_event(data)
        assert isinstance(event, PolicyDecisionEvent)
        assert event.action == "deny"
        assert event.rule_id == 1
        assert event.detail == "bind_port_denied"


class TestDecodeEventEdgeCases:
    def test_empty_data(self):
        assert decode_event(b"") is None

    def test_short_data(self):
        assert decode_event(b"\x01\x00") is None

    def test_unknown_event_type(self):
        data = (99).to_bytes(4, "little") + b"\x00" * 100
        assert decode_event(data) is None

    def test_truncated_event(self):
        data = (1).to_bytes(4, "little") + b"\x00" * 4
        assert decode_event(data) is None
