"""
Base class for SENTINEL stream processing jobs.

Provides Kafka consumer/producer lifecycle management, offset-based
checkpointing, and graceful shutdown via SIGTERM/SIGINT.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from confluent_kafka import Consumer, KafkaError, Producer

logger = logging.getLogger(__name__)

KAFKA_CONNECT_MAX_RETRIES = 30
KAFKA_CONNECT_DELAY = 5.0
COMMIT_INTERVAL_MESSAGES = 100


class BaseStreamJob(ABC):
    """
    Abstract base for all SENTINEL Kafka stream processing jobs.

    Subclasses must implement ``setup()`` (to create consumer/producer and
    subscribe to topics) and ``process()`` (per-message business logic).
    """

    def __init__(self, job_name: str):
        self.job_name = job_name
        self._shutdown = False
        self._consumer: Optional[Consumer] = None
        self._producer: Optional[Producer] = None

        self.kafka_servers = os.environ.get(
            "KAFKA_BOOTSTRAP_SERVERS",
            "localhost:9092",
        )
        self.parallelism = int(os.environ.get("FLINK_PARALLELISM", "1"))
        self.checkpoint_dir = os.environ.get(
            "CHECKPOINT_DIR",
            f"/tmp/flink-checkpoints/{job_name}",
        )

        self._install_signal_handlers()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def run(self):
        logger.info("Starting job: %s", self.job_name)
        self._wait_for_kafka()
        self.setup()
        try:
            self._main_loop()
        finally:
            self._cleanup()

    @abstractmethod
    def setup(self) -> None:
        """Create consumer/producer and any job-specific state."""

    @abstractmethod
    def process(self, message: Dict[str, Any]) -> None:
        """Handle a single deserialized Kafka message."""

    # ── Signal handling ───────────────────────────────────────────────────

    def _install_signal_handlers(self):
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)

    def _on_signal(self, signum: int, _frame):
        logger.info(
            "Received %s — initiating graceful shutdown",
            signal.Signals(signum).name,
        )
        self._shutdown = True

    # ── Kafka helpers ─────────────────────────────────────────────────────

    def create_consumer(
        self,
        topics: List[str],
        group_id: Optional[str] = None,
    ) -> Consumer:
        config = {
            "bootstrap.servers": self.kafka_servers,
            "group.id": group_id or f"sentinel-{self.job_name}",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            "max.poll.interval.ms": 300000,
            "session.timeout.ms": 45000,
            "heartbeat.interval.ms": 15000,
        }
        self._consumer = Consumer(config)
        self._consumer.subscribe(topics)
        logger.info("Consumer subscribed to %s (group=%s)", topics, config["group.id"])
        return self._consumer

    def create_producer(self) -> Producer:
        config = {
            "bootstrap.servers": self.kafka_servers,
            "acks": "all",
            "retries": 3,
            "retry.backoff.ms": 1000,
            "linger.ms": 10,
            "batch.size": 16384,
            "compression.type": "lz4",
            "enable.idempotence": True,
        }
        self._producer = Producer(config)
        logger.info("Producer created (idempotent, lz4)")
        return self._producer

    def produce(
        self,
        topic: str,
        value: Dict[str, Any],
        key: Optional[str] = None,
    ):
        if self._producer is None:
            raise RuntimeError(
                "Producer not initialised — call create_producer() in setup()"
            )
        self._producer.produce(
            topic=topic,
            value=json.dumps(value).encode("utf-8"),
            key=key.encode("utf-8") if key else None,
            callback=self._on_delivery,
        )
        self._producer.poll(0)

    @staticmethod
    def _on_delivery(err, msg):
        if err is not None:
            logger.error(
                "Delivery failed [%s/%d]: %s", msg.topic(), msg.partition(), err
            )

    def commit_offsets(self):
        if self._consumer is not None:
            self._consumer.commit(asynchronous=False)

    # ── Checkpointing ─────────────────────────────────────────────────────

    def save_checkpoint(self, state: Dict[str, Any]):
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        path = os.path.join(self.checkpoint_dir, "checkpoint.json")
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)

    def load_checkpoint(self) -> Optional[Dict[str, Any]]:
        path = os.path.join(self.checkpoint_dir, "checkpoint.json")
        if not os.path.exists(path):
            return None
        with open(path, "r") as fh:
            return json.load(fh)

    # ── Internal ──────────────────────────────────────────────────────────

    def _wait_for_kafka(self):
        for attempt in range(1, KAFKA_CONNECT_MAX_RETRIES + 1):
            try:
                probe = Producer({"bootstrap.servers": self.kafka_servers})
                probe.list_topics(timeout=5)
                logger.info("Kafka reachable at %s", self.kafka_servers)
                return
            except Exception:
                if attempt < KAFKA_CONNECT_MAX_RETRIES:
                    logger.info(
                        "Waiting for Kafka (%d/%d)…",
                        attempt,
                        KAFKA_CONNECT_MAX_RETRIES,
                    )
                    time.sleep(KAFKA_CONNECT_DELAY)
        raise RuntimeError(
            f"Kafka unreachable at {self.kafka_servers} "
            f"after {KAFKA_CONNECT_MAX_RETRIES} attempts"
        )

    def _main_loop(self):
        if self._consumer is None:
            raise RuntimeError(
                "Consumer not initialised — call create_consumer() in setup()"
            )

        messages_since_commit = 0

        while not self._shutdown:
            msg = self._consumer.poll(timeout=1.0)
            if msg is None:
                continue

            err = msg.error()
            if err:
                if err.code() == KafkaError._PARTITION_EOF:
                    continue
                if err.code() == KafkaError._ALL_BROKERS_DOWN:
                    logger.critical("All brokers down — backing off 10 s")
                    time.sleep(10)
                    continue
                logger.error("Consumer error: %s", err)
                continue

            try:
                value = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning(
                    "Skipping malformed message on %s [%d:%d]",
                    msg.topic(),
                    msg.partition(),
                    msg.offset(),
                )
                continue

            try:
                self.process(value)
            except Exception:
                logger.exception(
                    "Error processing message %s [%d:%d]",
                    msg.topic(),
                    msg.partition(),
                    msg.offset(),
                )
                continue

            messages_since_commit += 1
            if messages_since_commit >= COMMIT_INTERVAL_MESSAGES:
                self.commit_offsets()
                if self._producer is not None:
                    self._producer.flush(timeout=5)
                messages_since_commit = 0

    def _cleanup(self):
        logger.info("Shutting down %s…", self.job_name)
        try:
            if self._consumer is not None:
                self.commit_offsets()
                self._consumer.close()
        except Exception:
            logger.exception("Error closing consumer")
        try:
            if self._producer is not None:
                self._producer.flush(timeout=10)
        except Exception:
            logger.exception("Error flushing producer")
        logger.info("Job %s stopped", self.job_name)
