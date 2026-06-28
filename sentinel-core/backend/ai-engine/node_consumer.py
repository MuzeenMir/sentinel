"""Consume host events from the Redis stream, score them, persist alerts."""
from __future__ import annotations

import json
import logging
import os

import redis

from node_scoring import HostEventScorer

logger = logging.getLogger(__name__)

_INSERT_SQL = """
    INSERT INTO node_alerts
        (event_type, severity, score, pid, uid, comm, exe, hostname,
         source_event_id, summary, detail, status)
    VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
"""


class NodeConsumer:
    def __init__(
        self,
        redis_client,
        scorer: HostEventScorer,
        stream: str = os.environ.get("NODE_EVENT_STREAM", "node:events"),
        group: str = "node-detector",
        consumer: str = os.environ.get("NODE_CONSUMER_NAME", "ai-1"),
    ):
        self.redis = redis_client
        self.scorer = scorer
        self.stream = stream
        self.group = group
        self.consumer = consumer

    def ensure_group(self) -> None:
        try:
            self.redis.xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except redis.exceptions.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    def _insert_alert(self, conn, source_id, event: dict, verdict: dict) -> None:
        with conn.cursor() as cur:
            cur.execute(
                _INSERT_SQL,
                (
                    event.get("event_type", "execve"),
                    verdict["severity"],
                    verdict["score"],
                    event.get("pid"),
                    event.get("uid"),
                    event.get("comm"),
                    event.get("exe"),
                    event.get("hostname"),
                    str(source_id),
                    verdict["summary"],
                    json.dumps(event),
                    "new",
                ),
            )
        conn.commit()

    def process_once(self, conn, block_ms: int = 5000, count: int = 10) -> int:
        resp = self.redis.xreadgroup(
            self.group, self.consumer, {self.stream: ">"},
            count=count, block=block_ms,
        )
        written = 0
        for _stream, entries in resp or []:
            for msg_id, fields in entries:
                try:
                    raw = fields.get("event") or fields.get(b"event")
                    if isinstance(raw, bytes):
                        raw = raw.decode()
                    if raw is None:
                        raise ValueError("missing 'event' field")
                    event = json.loads(raw)
                    verdict = self.scorer.score(event)
                except Exception as exc:
                    logger.warning(
                        "Skipping malformed message %s: %r", msg_id, exc
                    )
                    self.redis.xack(self.stream, self.group, msg_id)
                    continue
                if verdict["is_threat"]:
                    self._insert_alert(conn, msg_id, event, verdict)  # propagates on DB failure -> NOT acked
                    written += 1
                self.redis.xack(self.stream, self.group, msg_id)
        return written

    def run(self, conn) -> None:  # pragma: no cover - long-running loop
        self.ensure_group()
        while True:
            self.process_once(conn)
