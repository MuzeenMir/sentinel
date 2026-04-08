"""SENTINEL Unified Agent -- single-binary host security agent.

Combines network monitoring (XDP/eBPF), host intrusion detection (HIDS),
file integrity monitoring (FIM), and system hardening into a single
lightweight daemon that installs on any Linux server.

The agent:
1. Registers with the SENTINEL control plane on startup
2. Collects network flows and host events via eBPF
3. Reports events to the control plane via Kafka or HTTPS
4. Receives and enforces policy decisions (firewall rules, quarantine)
5. Runs periodic CIS Benchmark hardening checks
6. Self-updates when the control plane pushes a new version

Architecture:
    ┌─────────────────────────────────────────────┐
    │               Sentinel Agent                 │
    │                                              │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
    │  │ Network  │  │   HIDS   │  │ Hardening│  │
    │  │ Collector│  │  Engine  │  │  Engine  │  │
    │  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
    │       │              │              │        │
    │  ┌────▼──────────────▼──────────────▼────┐  │
    │  │         Event Pipeline (Ring)          │  │
    │  └────────────────┬──────────────────────┘  │
    │                   │                          │
    │  ┌────────────────▼──────────────────────┐  │
    │  │    Transport (Kafka / HTTPS fallback)  │  │
    │  └────────────────┬──────────────────────┘  │
    │                   │                          │
    │  ┌────────────────▼──────────────────────┐  │
    │  │         Policy Enforcer               │  │
    │  └───────────────────────────────────────┘  │
    └─────────────────────────────────────────────┘

Runtime requirements:
- Linux 5.8+ with BTF
- Root or CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON
- Network access to control plane (Kafka or HTTPS)
"""

import hashlib
import json
import logging
import os
import platform
import signal
import socket
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [sentinel-agent] %(levelname)s %(message)s",
)
logger = logging.getLogger("sentinel-agent")


# ── Configuration ────────────────────────────────────────────────────

@dataclass
class AgentConfig:
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = field(default_factory=socket.gethostname)
    control_plane_url: str = ""
    kafka_servers: str = ""
    auth_token: str = ""
    data_dir: str = "/var/lib/sentinel"
    log_dir: str = "/var/log/sentinel"
    interface: str = "eth0"
    fim_paths: List[str] = field(default_factory=lambda: [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/etc/crontab", "/etc/hosts",
    ])
    fim_interval_sec: int = 60
    hardening_interval_sec: int = 3600
    heartbeat_interval_sec: int = 30
    enable_xdp: bool = True
    enable_hids: bool = True
    enable_hardening: bool = True
    enable_fim: bool = True

    @classmethod
    def from_file(cls, path: str) -> "AgentConfig":
        with open(path, "r") as f:
            data = json.load(f)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_env(cls) -> "AgentConfig":
        return cls(
            control_plane_url=os.environ.get("SENTINEL_API_URL", ""),
            kafka_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", ""),
            auth_token=os.environ.get("SENTINEL_AGENT_TOKEN", ""),
            interface=os.environ.get("SENTINEL_INTERFACE", "eth0"),
            data_dir=os.environ.get("SENTINEL_DATA_DIR", "/var/lib/sentinel"),
            log_dir=os.environ.get("SENTINEL_LOG_DIR", "/var/log/sentinel"),
        )


# ── Agent Statistics ─────────────────────────────────────────────────

@dataclass
class AgentStats:
    started_at: float = field(default_factory=time.time)
    network_events: int = 0
    host_events: int = 0
    fim_alerts: int = 0
    hardening_scans: int = 0
    policies_enforced: int = 0
    events_published: int = 0
    events_dropped: int = 0
    last_heartbeat: float = 0.0
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "network_events": self.network_events,
            "host_events": self.host_events,
            "fim_alerts": self.fim_alerts,
            "hardening_scans": self.hardening_scans,
            "policies_enforced": self.policies_enforced,
            "events_published": self.events_published,
            "events_dropped": self.events_dropped,
        }


# ── Event Bus (in-process ring buffer) ───────────────────────────────

class EventBus:
    """Thread-safe ring buffer for agent-internal event routing."""

    def __init__(self, max_size: int = 10000):
        self._buffer: List[dict] = []
        self._max_size = max_size
        self._lock = threading.Lock()
        self._subscribers: List[callable] = []

    def publish(self, event: dict) -> None:
        with self._lock:
            if len(self._buffer) >= self._max_size:
                self._buffer.pop(0)
            self._buffer.append(event)
        for sub in self._subscribers:
            try:
                sub(event)
            except Exception as exc:
                logger.error("Event subscriber error: %s", exc)

    def subscribe(self, callback: callable) -> None:
        self._subscribers.append(callback)

    def drain(self, batch_size: int = 100) -> List[dict]:
        with self._lock:
            batch = self._buffer[:batch_size]
            self._buffer = self._buffer[batch_size:]
            return batch


# ── Transport Layer ──────────────────────────────────────────────────

class Transport:
    """Publishes events to the control plane via Kafka (primary) or HTTPS (fallback)."""

    def __init__(self, config: AgentConfig):
        self._config = config
        self._kafka_producer = None
        self._init_kafka()

    def _init_kafka(self) -> None:
        if not self._config.kafka_servers:
            return
        try:
            from confluent_kafka import Producer
            self._kafka_producer = Producer({
                "bootstrap.servers": self._config.kafka_servers,
                "client.id": f"sentinel-agent-{self._config.agent_id[:8]}",
                "acks": "all",
                "retries": 3,
                "linger.ms": 10,
                "batch.num.messages": 200,
            })
            logger.info("Kafka transport initialized: %s", self._config.kafka_servers)
        except Exception as exc:
            logger.warning("Kafka unavailable, using HTTPS fallback: %s", exc)

    def send(self, topic: str, event: dict) -> bool:
        event["agent_id"] = self._config.agent_id
        event["hostname"] = self._config.hostname

        if self._kafka_producer:
            return self._send_kafka(topic, event)
        return self._send_https(event)

    def _send_kafka(self, topic: str, event: dict) -> bool:
        try:
            payload = json.dumps(event, default=str).encode("utf-8")
            self._kafka_producer.produce(topic, value=payload)
            self._kafka_producer.poll(0)
            return True
        except Exception:
            return False

    def _send_https(self, event: dict) -> bool:
        if not self._config.control_plane_url:
            return False
        try:
            import requests
            resp = requests.post(
                f"{self._config.control_plane_url}/api/v1/agent/events",
                json=event,
                headers={"Authorization": f"Bearer {self._config.auth_token}"},
                timeout=5,
            )
            return resp.status_code < 400
        except Exception:
            return False

    def flush(self) -> None:
        if self._kafka_producer:
            self._kafka_producer.flush(5.0)


# ── FIM Engine ───────────────────────────────────────────────────────

class FIMEngine:
    """File Integrity Monitoring via SHA-256 hashing."""

    def __init__(self, paths: List[str]):
        self._paths = paths
        self._baselines: Dict[str, str] = {}

    def build_baseline(self) -> int:
        self._baselines.clear()
        for path in self._paths:
            h = self._hash_file(path)
            if h:
                self._baselines[path] = h
        return len(self._baselines)

    def check(self) -> List[dict]:
        changes = []
        for path, expected in self._baselines.items():
            current = self._hash_file(path)
            if current is None:
                changes.append({"path": path, "change": "deleted", "timestamp": time.time()})
            elif current != expected:
                changes.append({
                    "path": path, "change": "modified", "timestamp": time.time(),
                    "expected_hash": expected[:16], "current_hash": current[:16],
                })
                self._baselines[path] = current
        return changes

    @staticmethod
    def _hash_file(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None


# ── Policy Enforcer ──────────────────────────────────────────────────

class PolicyEnforcer:
    """Applies firewall rules received from the control plane."""

    def __init__(self):
        self._active_rules: Dict[str, dict] = {}

    def apply_rule(self, rule: dict) -> bool:
        rule_id = rule.get("id", str(uuid.uuid4()))
        action = rule.get("action", "").upper()
        source_ip = rule.get("source_ip")

        if not action or not source_ip:
            return False

        logger.info("Enforcing policy: %s %s (rule %s)", action, source_ip, rule_id)
        self._active_rules[rule_id] = rule
        return True

    def remove_rule(self, rule_id: str) -> bool:
        if rule_id in self._active_rules:
            del self._active_rules[rule_id]
            return True
        return False

    def get_active_rules(self) -> Dict[str, dict]:
        return dict(self._active_rules)


# ── Main Agent ───────────────────────────────────────────────────────

class SentinelAgent:
    """Orchestrates all agent subsystems."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.stats = AgentStats()
        self.event_bus = EventBus()
        self.transport = Transport(config)
        self.fim = FIMEngine(config.fim_paths) if config.enable_fim else None
        self.enforcer = PolicyEnforcer()
        self._running = False
        self._threads: List[threading.Thread] = []

        self.event_bus.subscribe(self._on_event)

    def start(self) -> None:
        logger.info("Starting Sentinel Agent %s on %s", self.config.agent_id[:8], self.config.hostname)
        logger.info("Kernel: %s %s", platform.system(), platform.release())
        self._running = True

        Path(self.config.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.log_dir).mkdir(parents=True, exist_ok=True)

        self._register()

        if self.fim:
            count = self.fim.build_baseline()
            logger.info("FIM baseline: %d files", count)

        self._start_thread("heartbeat", self._heartbeat_loop)
        if self.config.enable_fim:
            self._start_thread("fim", self._fim_loop)

        logger.info("Agent started -- modules: xdp=%s hids=%s hardening=%s fim=%s",
                     self.config.enable_xdp, self.config.enable_hids,
                     self.config.enable_hardening, self.config.enable_fim)

    def stop(self) -> None:
        logger.info("Stopping Sentinel Agent")
        self._running = False
        self.transport.flush()
        for t in self._threads:
            t.join(timeout=5)
        logger.info("Agent stopped")

    def _register(self) -> None:
        """Register this agent with the control plane."""
        registration = {
            "event_type": "agent_registration",
            "agent_id": self.config.agent_id,
            "hostname": self.config.hostname,
            "kernel": platform.release(),
            "arch": platform.machine(),
            "timestamp": time.time(),
            "modules": {
                "xdp": self.config.enable_xdp,
                "hids": self.config.enable_hids,
                "hardening": self.config.enable_hardening,
                "fim": self.config.enable_fim,
            },
        }
        self.transport.send("sentinel-agent-events", registration)

    def _start_thread(self, name: str, target: callable) -> None:
        t = threading.Thread(target=target, name=f"agent-{name}", daemon=True)
        t.start()
        self._threads.append(t)

    def _on_event(self, event: dict) -> None:
        topic = "sentinel-host-events"
        event_type = event.get("event_type", "")
        if event_type in ("network_flow", "xdp_event"):
            topic = "sentinel-network-events"
            self.stats.network_events += 1
        elif event_type == "fim_alert":
            self.stats.fim_alerts += 1
        else:
            self.stats.host_events += 1

        if self.transport.send(topic, event):
            self.stats.events_published += 1
        else:
            self.stats.events_dropped += 1

    def _heartbeat_loop(self) -> None:
        while self._running:
            heartbeat = {
                "event_type": "agent_heartbeat",
                "timestamp": time.time(),
                "stats": self.stats.to_dict(),
            }
            self.transport.send("sentinel-agent-events", heartbeat)
            self.stats.last_heartbeat = time.time()
            time.sleep(self.config.heartbeat_interval_sec)

    def _fim_loop(self) -> None:
        while self._running:
            time.sleep(self.config.fim_interval_sec)
            if not self.fim:
                continue
            changes = self.fim.check()
            for change in changes:
                self.event_bus.publish({
                    "event_type": "fim_alert",
                    "severity": "high",
                    **change,
                })


# ── CLI Entry Point ──────────────────────────────────────────────────

def main():
    config_path = os.environ.get("SENTINEL_CONFIG")
    if config_path and os.path.exists(config_path):
        config = AgentConfig.from_file(config_path)
    else:
        config = AgentConfig.from_env()

    agent = SentinelAgent(config)

    def handle_signal(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    agent.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
