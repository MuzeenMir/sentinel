"""Tail auditd and publish normalized host events onto a Redis stream."""

from __future__ import annotations

import json
import os
import re
import time
from typing import Iterable

from auditd_source import parse_event

_SERIAL_RE = re.compile(r"audit\(\d+\.\d+:(\d+)\)")
DEFAULT_STREAM = os.environ.get("NODE_EVENT_STREAM", "node:events")


def _group_by_serial(lines: Iterable[str]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}
    order: list[str] = []
    for line in lines:
        m = _SERIAL_RE.search(line)
        if not m:
            continue
        serial = m.group(1)
        if serial not in groups:
            groups[serial] = []
            order.append(serial)
        groups[serial].append(line)
    return [groups[s] for s in order]


class NodeCollector:
    def __init__(self, redis_client, stream: str = DEFAULT_STREAM):
        self.redis = redis_client
        self.stream = stream

    def emit(self, event: dict) -> str:
        return self.redis.xadd(self.stream, {"event": json.dumps(event)})

    def feed_lines(self, lines: Iterable[str]) -> int:
        count = 0
        for group in _group_by_serial(lines):
            event = parse_event(group)
            if event is not None:
                self.emit(event)
                count += 1
        return count

    def tail(self, path: str = "/var/log/audit/audit.log", poll: float = 0.5) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            fh.seek(0, os.SEEK_END)
            buf: list[str] = []
            while True:
                line = fh.readline()
                if not line:
                    if buf:
                        self.feed_lines(buf)
                        buf = []
                    time.sleep(poll)
                    continue
                buf.append(line.rstrip("\n"))
