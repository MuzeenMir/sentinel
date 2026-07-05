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
        """Follow ``path``, returning when it rotates so the caller reopens it.

        auditd renames the live log away on rotation; holding the old fd
        would read nothing forever, silently blinding the node.
        """
        with open(path, "r", encoding="utf-8") as fh:
            fh.seek(0, os.SEEK_END)
            buf: list[str] = []
            while True:
                line = fh.readline()
                if not line:
                    if buf:
                        self.feed_lines(buf)
                        buf = []
                    if _rotated(fh, path):
                        return
                    time.sleep(poll)
                    continue
                buf.append(line.rstrip("\n"))


def _rotated(fh, path: str) -> bool:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return True
    fst = os.fstat(fh.fileno())
    # new inode = renamed away and recreated; shrunk = truncated in place
    return st.st_ino != fst.st_ino or st.st_size < fh.tell()


def main() -> None:  # pragma: no cover - supervisor loop; pieces unit-tested
    import logging

    import redis

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    logger = logging.getLogger("node_collector")

    redis_client = redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379"),
        decode_responses=True,
    )
    path = os.environ.get("AUDIT_LOG_PATH", "/var/log/audit/audit.log")
    poll = float(os.environ.get("NODE_TAIL_POLL_SECONDS", "0.5"))
    retry = float(os.environ.get("NODE_TAIL_RETRY_SECONDS", "5"))

    collector = NodeCollector(redis_client)
    logger.info("tailing %s onto stream %s", path, collector.stream)
    while True:
        try:
            collector.tail(path, poll=poll)
            logger.info("audit log rotated; reopening %s", path)
        except FileNotFoundError:
            logger.warning("%s not found; retrying in %.0fs", path, retry)
            time.sleep(retry)


if __name__ == "__main__":
    main()
