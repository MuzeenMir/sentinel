"""SENTINEL XDP Collector -- eBPF-powered network flow monitoring.

High-speed packet ingestion using XDP/eBPF on bare-metal Linux.
The eBPF program (from ebpf-lib) runs in the kernel and maintains
per-flow hash maps. Flow summaries are exported via a ring buffer
to this user-space daemon, which normalizes them to CIM format
and publishes to Kafka.

Runtime requirements:
- Linux 5.8+ with BTF
- CAP_BPF + CAP_NET_ADMIN capabilities (or privileged container)
- Compiled eBPF objects in ebpf-lib/compiled/
"""

import json
import logging
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ebpf_lib.schemas.events import (
    EventType,
    NetworkFlowEvent,
    decode_event,
    event_to_json,
)
from ebpf_lib.loader import ProgramLoader, RingBufferReader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("sentinel.xdp-collector")


app = Flask(__name__)
CORS(app)

app.config["XDP_ENABLED"] = os.environ.get("XDP_ENABLED", "true").lower() == "true"
app.config["XDP_INTERFACE"] = os.environ.get("XDP_INTERFACE", "eth0")
app.config["KAFKA_TOPIC"] = os.environ.get("KAFKA_TOPIC", "sentinel-network-events")


@dataclass
class CollectorStats:
    """Runtime statistics for the XDP collector."""
    flows_exported: int = 0
    events_published: int = 0
    events_dropped: int = 0
    packets_blocked: int = 0
    bytes_blocked: int = 0
    start_time: float = field(default_factory=time.time)
    last_event_time: float = 0.0
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        uptime = time.time() - self.start_time
        return {
            "flows_exported": self.flows_exported,
            "events_published": self.events_published,
            "events_dropped": self.events_dropped,
            "packets_blocked": self.packets_blocked,
            "bytes_blocked": self.bytes_blocked,
            "uptime_seconds": round(uptime, 1),
            "events_per_second": round(
                self.events_published / max(uptime, 1), 2
            ),
            "last_event_time": self.last_event_time,
            "last_error": self.last_error,
        }


class KafkaPublisher:
    """Publishes normalized flow events to Kafka."""

    def __init__(self, topic: str):
        self.topic = topic
        self._producer = None
        self._init_producer()

    def _init_producer(self) -> None:
        try:
            from confluent_kafka import Producer
            servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
            self._producer = Producer({
                "bootstrap.servers": servers,
                "client.id": "xdp-collector",
                "acks": "all",
                "retries": 3,
                "retry.backoff.ms": 100,
                "linger.ms": 5,
                "batch.num.messages": 100,
            })
            logger.info("Kafka producer initialized: %s", servers)
        except ImportError:
            logger.warning("confluent_kafka not installed; Kafka publishing disabled")
        except Exception as e:
            logger.error("Failed to init Kafka producer: %s", e)

    def publish(self, event: NetworkFlowEvent) -> bool:
        if not self._producer:
            return False
        try:
            payload = event_to_json(event).encode("utf-8")
            key = event.src_ip.encode("utf-8")
            self._producer.produce(self.topic, key=key, value=payload)
            self._producer.poll(0)
            return True
        except Exception as e:
            logger.error("Kafka publish failed: %s", e)
            return False

    def flush(self, timeout: float = 5.0) -> None:
        if self._producer:
            self._producer.flush(timeout)


class BlocklistManager:
    """Manages the IP blocklist via Redis pub/sub and BPF map updates."""

    def __init__(self) -> None:
        self._redis = None
        self._blocklist: Dict[str, dict] = {}
        self._init_redis()

    def _init_redis(self) -> None:
        try:
            import redis
            url = os.environ.get("REDIS_URL", "redis://localhost:6379")
            self._redis = redis.from_url(url)
            self._redis.ping()
            logger.info("Redis connected for blocklist sync")
        except Exception as e:
            logger.warning("Redis not available for blocklist: %s", e)

    def add_ip(self, ip: str, reason: str = "manual") -> None:
        self._blocklist[ip] = {
            "added_at": time.time(),
            "reason": reason,
        }
        logger.info("Added %s to blocklist (reason: %s)", ip, reason)

    def remove_ip(self, ip: str) -> None:
        self._blocklist.pop(ip, None)
        logger.info("Removed %s from blocklist", ip)

    def get_all(self) -> Dict[str, dict]:
        return dict(self._blocklist)


class XDPCollectorService:
    """Main XDP collector service.

    Manages the eBPF program lifecycle, ring buffer consumption,
    Kafka publishing, and blocklist updates.
    """

    def __init__(self) -> None:
        self.interface = app.config["XDP_INTERFACE"]
        self.enabled = app.config["XDP_ENABLED"]
        self.stats = CollectorStats()
        self.publisher = KafkaPublisher(app.config["KAFKA_TOPIC"])
        self.blocklist = BlocklistManager()
        self._loader: Optional[ProgramLoader] = None
        self._reader: Optional[RingBufferReader] = None
        self._running = False

    def start(self) -> None:
        if not self.enabled:
            logger.info("XDP collector disabled via XDP_ENABLED=false")
            return

        self._running = True
        logger.info("Starting XDP collector on interface %s", self.interface)

        try:
            self._loader = ProgramLoader(
                audit_callback=self._on_audit_event,
            )
            info = self._loader.load(
                name="xdp/xdp_flow",
                prog_type="xdp",
                attach_target=self.interface,
            )
            logger.info(
                "XDP program loaded: %s (sha256=%s)",
                info.name, info.sha256,
            )

            if info.fd >= 0:
                self._reader = RingBufferReader(poll_timeout_ms=100)
                flow_events_fd = info.map_fds.get("flow_events", -1)
                if flow_events_fd >= 0:
                    self._reader.register(
                        "flow_events", flow_events_fd, self._on_flow_event,
                    )
                    self._reader.start()
                    logger.info("Ring buffer reader started")
            else:
                logger.info(
                    "XDP loaded in dry-run mode (no kernel attachment)"
                )

        except FileNotFoundError:
            logger.warning(
                "eBPF objects not compiled; XDP collector running in "
                "stub mode. Run 'make' in ebpf-lib/ to compile."
            )
        except PermissionError as e:
            logger.error("eBPF signature verification failed: %s", e)
            self.stats.last_error = str(e)
        except Exception as e:
            logger.error("Failed to start XDP program: %s", e)
            self.stats.last_error = str(e)

    def stop(self) -> None:
        self._running = False
        if self._reader:
            self._reader.stop()
        if self._loader and self._loader.is_loaded("xdp/xdp_flow"):
            self._loader.unload("xdp/xdp_flow")
        self.publisher.flush()
        logger.info("XDP collector stopped")

    def _on_flow_event(self, event: Any) -> None:
        if not isinstance(event, NetworkFlowEvent):
            return

        self.stats.flows_exported += 1
        self.stats.last_event_time = time.time()

        if self.publisher.publish(event):
            self.stats.events_published += 1
        else:
            self.stats.events_dropped += 1

    def _on_audit_event(self, record: dict) -> None:
        logger.info("eBPF audit: %s", json.dumps(record))


collector = XDPCollectorService()


# ── Flask routes ──────────────────────────────────────────────────────


@app.route("/health", methods=["GET"])
def health():
    loaded = (
        collector._loader is not None
        and collector._loader.is_loaded("xdp/xdp_flow")
    )
    return jsonify({
        "status": "healthy",
        "service": "xdp-collector",
        "xdp_enabled": collector.enabled,
        "xdp_loaded": loaded,
        "interface": collector.interface,
    }), 200


@app.route("/metrics", methods=["GET"])
def metrics():
    return jsonify(collector.stats.to_dict()), 200


@app.route("/config", methods=["GET"])
def get_config():
    return jsonify({
        "interface": collector.interface,
        "enabled": collector.enabled,
        "kafka_topic": app.config["KAFKA_TOPIC"],
        "blocklist_size": len(collector.blocklist.get_all()),
    }), 200


@app.route("/blocklist", methods=["GET"])
def get_blocklist():
    return jsonify(collector.blocklist.get_all()), 200


@app.route("/blocklist", methods=["POST"])
def update_blocklist():
    data = request.get_json()
    if not data or "ip" not in data:
        return jsonify({"error": "ip field required"}), 400

    ip = data["ip"]
    action = data.get("action", "add")
    reason = data.get("reason", "api")

    if action == "add":
        collector.blocklist.add_ip(ip, reason)
    elif action == "remove":
        collector.blocklist.remove_ip(ip)
    else:
        return jsonify({"error": "action must be 'add' or 'remove'"}), 400

    return jsonify({"status": "ok", "ip": ip, "action": action}), 200


# ── Startup ───────────────────────────────────────────────────────────


def start_collector_background() -> None:
    thread = threading.Thread(
        target=collector.start, name="xdp-collector", daemon=True,
    )
    thread.start()


with app.app_context():
    start_collector_background()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5010")),
        debug=False,
    )
