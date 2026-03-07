"""SENTINEL HIDS Agent -- eBPF-powered host intrusion detection.

Continuous host monitoring at the kernel level using eBPF tracepoints
and kprobes for:
- Process execution tracking (sched_process_exec)
- Sensitive file access monitoring (sys_enter_openat)
- Outbound network connections per process (tcp_v4_connect)
- Privilege escalation detection (sys_enter_setuid)
- Kernel module loading (module_load)
- File integrity monitoring (FIM) via hash database

Events are published to Kafka topic 'host-events' for downstream
processing by Flink, AI Engine, and Alert Service.

Runtime requirements:
- Linux 5.8+ with BTF
- CAP_BPF + CAP_PERFMON capabilities (or privileged)
- Compiled eBPF objects in ebpf-lib/compiled/
"""

import hashlib
import json
import logging
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set

from flask import Flask, jsonify, request
from flask_cors import CORS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ebpf_lib.schemas.events import (
    EventType,
    ProcessExecEvent,
    FileAccessEvent,
    NetConnectEvent,
    PrivEscalationEvent,
    ModuleLoadEvent,
    decode_event,
    event_to_json,
)
from ebpf_lib.loader import ProgramLoader, RingBufferReader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("sentinel.hids-agent")


app = Flask(__name__)
CORS(app)


# ── Configuration ─────────────────────────────────────────────────────


DEFAULT_FIM_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ld.so.preload",
    "/root/.ssh/authorized_keys",
    "/root/.bashrc",
]

KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "sentinel-host-events")
FIM_PATHS_ENV = os.environ.get("FIM_PATHS", "")
FIM_PATHS = (
    FIM_PATHS_ENV.split(",") if FIM_PATHS_ENV
    else DEFAULT_FIM_PATHS
)
FIM_CHECK_INTERVAL = int(os.environ.get("FIM_CHECK_INTERVAL", "60"))
MAX_RECENT_EVENTS = 1000
HOST_ROOT = os.environ.get("HOST_ROOT", "/host")


# ── Stats ─────────────────────────────────────────────────────────────


@dataclass
class HIDSStats:
    process_exec_events: int = 0
    file_access_events: int = 0
    net_connect_events: int = 0
    priv_escalation_events: int = 0
    module_load_events: int = 0
    fim_alerts: int = 0
    events_published: int = 0
    events_dropped: int = 0
    start_time: float = field(default_factory=time.time)
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        uptime = time.time() - self.start_time
        total = (
            self.process_exec_events + self.file_access_events
            + self.net_connect_events + self.priv_escalation_events
            + self.module_load_events
        )
        return {
            "process_exec_events": self.process_exec_events,
            "file_access_events": self.file_access_events,
            "net_connect_events": self.net_connect_events,
            "priv_escalation_events": self.priv_escalation_events,
            "module_load_events": self.module_load_events,
            "fim_alerts": self.fim_alerts,
            "total_events": total,
            "events_published": self.events_published,
            "events_dropped": self.events_dropped,
            "uptime_seconds": round(uptime, 1),
            "events_per_second": round(total / max(uptime, 1), 2),
            "last_error": self.last_error,
        }


# ── File Integrity Monitoring ─────────────────────────────────────────


class FileIntegrityMonitor:
    """Maintains SHA-256 hashes of critical files and detects changes."""

    def __init__(self, paths: List[str], host_root: str = ""):
        self._paths = paths
        self._host_root = host_root
        self._baselines: Dict[str, str] = {}
        self._alerts: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def _resolve_path(self, path: str) -> str:
        if self._host_root and not path.startswith(self._host_root):
            resolved = os.path.join(self._host_root, path.lstrip("/"))
            if os.path.exists(resolved):
                return resolved
        return path

    def _hash_file(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    def build_baseline(self) -> Dict[str, str]:
        with self._lock:
            self._baselines.clear()
            for path in self._paths:
                resolved = self._resolve_path(path)
                file_hash = self._hash_file(resolved)
                if file_hash:
                    self._baselines[path] = file_hash
                    logger.info("FIM baseline: %s = %s", path, file_hash[:16])
            return dict(self._baselines)

    def check(self) -> List[Dict[str, Any]]:
        changes = []
        with self._lock:
            for path, baseline_hash in self._baselines.items():
                resolved = self._resolve_path(path)
                current_hash = self._hash_file(resolved)
                if current_hash is None:
                    change = {
                        "path": path,
                        "type": "deleted",
                        "timestamp": time.time(),
                        "baseline_hash": baseline_hash,
                    }
                    changes.append(change)
                elif current_hash != baseline_hash:
                    change = {
                        "path": path,
                        "type": "modified",
                        "timestamp": time.time(),
                        "baseline_hash": baseline_hash,
                        "current_hash": current_hash,
                    }
                    changes.append(change)
                    self._baselines[path] = current_hash

            self._alerts.extend(changes)
        return changes

    def get_baselines(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._baselines)

    def get_alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._alerts)


# ── Allowlist / Baseline Rules ────────────────────────────────────────


class BaselineRuleEngine:
    """Filters noise by maintaining allowlists of known-good activity."""

    def __init__(self) -> None:
        self._allowed_execs: Set[str] = set()
        self._allowed_connects: Set[str] = set()
        self._load_defaults()

    def _load_defaults(self) -> None:
        self._allowed_execs = {
            "/usr/sbin/sshd",
            "/usr/bin/cron",
            "/usr/sbin/cron",
            "/lib/systemd/systemd",
            "/usr/lib/systemd/systemd",
            "/usr/bin/python3",
        }

    def should_alert_exec(self, event: ProcessExecEvent) -> bool:
        return event.filename not in self._allowed_execs

    def should_alert_connect(self, event: NetConnectEvent) -> bool:
        return True

    def should_alert_priv(self, event: PrivEscalationEvent) -> bool:
        return True

    def should_alert_module(self, event: ModuleLoadEvent) -> bool:
        return True

    def add_allowed_exec(self, path: str) -> None:
        self._allowed_execs.add(path)

    def remove_allowed_exec(self, path: str) -> None:
        self._allowed_execs.discard(path)

    def get_allowed_execs(self) -> List[str]:
        return sorted(self._allowed_execs)


# ── Kafka Publisher ───────────────────────────────────────────────────


class KafkaPublisher:
    def __init__(self, topic: str):
        self.topic = topic
        self._producer = None
        self._init()

    def _init(self) -> None:
        try:
            from confluent_kafka import Producer
            servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
            self._producer = Producer({
                "bootstrap.servers": servers,
                "client.id": "hids-agent",
                "acks": "all",
                "retries": 3,
                "linger.ms": 5,
            })
            logger.info("Kafka producer initialized: %s", servers)
        except ImportError:
            logger.warning("confluent_kafka not installed")
        except Exception as e:
            logger.error("Kafka init failed: %s", e)

    def publish(self, event_dict: dict) -> bool:
        if not self._producer:
            return False
        try:
            payload = json.dumps(event_dict).encode("utf-8")
            key = str(event_dict.get("pid", "")).encode("utf-8")
            self._producer.produce(self.topic, key=key, value=payload)
            self._producer.poll(0)
            return True
        except Exception as e:
            logger.error("Kafka publish failed: %s", e)
            return False

    def flush(self) -> None:
        if self._producer:
            self._producer.flush(5.0)


# ── Main HIDS Service ─────────────────────────────────────────────────


class HIDSAgentService:
    """Orchestrates eBPF programs, event processing, FIM, and publishing."""

    def __init__(self) -> None:
        self.stats = HIDSStats()
        self.publisher = KafkaPublisher(KAFKA_TOPIC)
        self.fim = FileIntegrityMonitor(FIM_PATHS, HOST_ROOT)
        self.rules = BaselineRuleEngine()
        self.recent_events: Deque[dict] = deque(maxlen=MAX_RECENT_EVENTS)
        self._loader: Optional[ProgramLoader] = None
        self._reader: Optional[RingBufferReader] = None
        self._running = False
        self._fim_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        logger.info("Starting HIDS Agent")

        self.fim.build_baseline()
        self._start_fim_thread()
        self._start_ebpf_programs()

    def stop(self) -> None:
        self._running = False
        if self._reader:
            self._reader.stop()
        self.publisher.flush()
        logger.info("HIDS Agent stopped")

    def _start_ebpf_programs(self) -> None:
        try:
            self._loader = ProgramLoader(
                audit_callback=lambda r: logger.info("eBPF audit: %s", json.dumps(r)),
            )

            programs = [
                ("tracepoint/process_exec", "tracepoint", "sched/sched_process_exec"),
                ("tracepoint/file_access", "tracepoint", "syscalls/sys_enter_openat"),
                ("tracepoint/net_connect", "kprobe", "tcp_v4_connect"),
                ("tracepoint/priv_escalation", "tracepoint", "syscalls/sys_enter_setuid"),
            ]

            loaded_any = False
            for name, prog_type, target in programs:
                try:
                    info = self._loader.load(name, prog_type, target)
                    logger.info("Loaded eBPF program: %s", name)
                    loaded_any = True
                except FileNotFoundError:
                    logger.warning("eBPF object not found: %s", name)
                except Exception as e:
                    logger.error("Failed to load %s: %s", name, e)

            if not loaded_any:
                logger.warning(
                    "No eBPF programs loaded; HIDS running in FIM-only mode. "
                    "Compile eBPF programs with 'make' in ebpf-lib/."
                )

        except Exception as e:
            logger.error("eBPF initialization failed: %s", e)
            self.stats.last_error = str(e)

    def _start_fim_thread(self) -> None:
        self._fim_thread = threading.Thread(
            target=self._fim_loop,
            name="hids-fim",
            daemon=True,
        )
        self._fim_thread.start()

    def _fim_loop(self) -> None:
        while self._running:
            try:
                changes = self.fim.check()
                for change in changes:
                    self.stats.fim_alerts += 1
                    alert = {
                        "event_type": "fim_alert",
                        "timestamp": change["timestamp"],
                        "path": change["path"],
                        "change_type": change["type"],
                        "severity": "high",
                    }
                    if "current_hash" in change:
                        alert["current_hash"] = change["current_hash"]
                    alert["baseline_hash"] = change["baseline_hash"]

                    self.recent_events.appendleft(alert)
                    if self.publisher.publish(alert):
                        self.stats.events_published += 1
                    else:
                        self.stats.events_dropped += 1

                    logger.warning(
                        "FIM ALERT: %s %s on %s",
                        change["type"], change["path"],
                        change.get("current_hash", "N/A")[:16],
                    )
            except Exception as e:
                logger.error("FIM check error: %s", e)

            time.sleep(FIM_CHECK_INTERVAL)

    def on_event(self, event: Any) -> None:
        """Callback for ring buffer events from eBPF programs."""
        from dataclasses import asdict

        event_dict = asdict(event)
        should_alert = True

        if isinstance(event, ProcessExecEvent):
            self.stats.process_exec_events += 1
            should_alert = self.rules.should_alert_exec(event)
        elif isinstance(event, FileAccessEvent):
            self.stats.file_access_events += 1
        elif isinstance(event, NetConnectEvent):
            self.stats.net_connect_events += 1
            should_alert = self.rules.should_alert_connect(event)
        elif isinstance(event, PrivEscalationEvent):
            self.stats.priv_escalation_events += 1
            event_dict["severity"] = "critical"
            should_alert = self.rules.should_alert_priv(event)
        elif isinstance(event, ModuleLoadEvent):
            self.stats.module_load_events += 1
            event_dict["severity"] = "high"
            should_alert = self.rules.should_alert_module(event)

        if not should_alert:
            return

        self.recent_events.appendleft(event_dict)

        if self.publisher.publish(event_dict):
            self.stats.events_published += 1
        else:
            self.stats.events_dropped += 1


hids = HIDSAgentService()


# ── Flask Routes ──────────────────────────────────────────────────────


@app.route("/health", methods=["GET"])
def health():
    ebpf_loaded = (
        hids._loader is not None
        and len(hids._loader.get_loaded()) > 0
    )
    return jsonify({
        "status": "healthy",
        "service": "hids-agent",
        "ebpf_programs_loaded": ebpf_loaded,
        "fim_paths_monitored": len(FIM_PATHS),
    }), 200


@app.route("/status", methods=["GET"])
def status():
    loaded_progs = (
        {k: {"sha256": v.sha256, "type": v.prog_type}
         for k, v in hids._loader.get_loaded().items()}
        if hids._loader else {}
    )
    return jsonify({
        "stats": hids.stats.to_dict(),
        "ebpf_programs": loaded_progs,
        "fim_paths": FIM_PATHS,
        "recent_events_count": len(hids.recent_events),
    }), 200


@app.route("/events", methods=["GET"])
def get_events():
    limit = request.args.get("limit", 50, type=int)
    event_type = request.args.get("type")
    events = list(hids.recent_events)[:limit]
    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]
    return jsonify(events), 200


@app.route("/baselines", methods=["GET"])
def get_baselines():
    return jsonify({
        "file_hashes": hids.fim.get_baselines(),
        "allowed_execs": hids.rules.get_allowed_execs(),
    }), 200


@app.route("/baselines/rebuild", methods=["POST"])
def rebuild_baselines():
    baselines = hids.fim.build_baseline()
    return jsonify({
        "status": "ok",
        "files_baselined": len(baselines),
    }), 200


@app.route("/baselines/execs", methods=["POST"])
def update_allowed_execs():
    data = request.get_json()
    if not data or "path" not in data:
        return jsonify({"error": "path field required"}), 400
    action = data.get("action", "add")
    if action == "add":
        hids.rules.add_allowed_exec(data["path"])
    elif action == "remove":
        hids.rules.remove_allowed_exec(data["path"])
    return jsonify({"status": "ok"}), 200


@app.route("/fim/alerts", methods=["GET"])
def get_fim_alerts():
    return jsonify(hids.fim.get_alerts()), 200


# ── Startup ───────────────────────────────────────────────────────────


def start_hids_background() -> None:
    thread = threading.Thread(
        target=hids.start, name="hids-agent", daemon=True,
    )
    thread.start()


with app.app_context():
    start_hids_background()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5010")),
        debug=False,
    )
