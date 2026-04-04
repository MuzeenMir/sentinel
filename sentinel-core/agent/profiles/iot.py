"""IoT profile — constrained-device security agent.

Designed for resource-limited devices (Raspberry Pi, industrial gateways,
ARM/MIPS SBCs).  Uses MQTT instead of Kafka, avoids native dependencies,
keeps memory footprint minimal, and never runs local ML inference.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from profiles.base import BaseProfile, ProfileConfig

logger = logging.getLogger("sentinel-agent")

_DEFAULT_MQTT_PORT = 8883
_DEFAULT_HEARTBEAT_SEC = 120
_CERT_RENEWAL_WARN_DAYS = 30


class IoTProfile(BaseProfile):
    """Lightweight profile for IoT / embedded Linux devices."""

    def __init__(self, config: ProfileConfig, event_bus: Any = None):
        super().__init__(config, event_bus)
        self._mqtt_client: Any = None
        self._mqtt_broker = config.extra.get("mqtt_broker", "")
        self._mqtt_port = int(config.extra.get("mqtt_port", _DEFAULT_MQTT_PORT))
        self._mqtt_topic_prefix = config.extra.get("mqtt_topic_prefix", "sentinel/iot")
        self._mqtt_use_tls = config.extra.get("mqtt_use_tls", True)
        self._mqtt_ca_cert = config.extra.get("mqtt_ca_cert", "")
        self._mqtt_client_cert = config.extra.get("mqtt_client_cert", "")
        self._mqtt_client_key = config.extra.get("mqtt_client_key", "")

        self._firmware_paths: List[str] = config.extra.get("firmware_paths", [])
        self._firmware_baselines: Dict[str, str] = {}
        self._cert_paths: List[str] = config.extra.get("cert_paths", [])
        self._monitored_protocols: List[str] = config.extra.get(
            "monitored_protocols", ["mqtt", "coap"],
        )
        self._heartbeat_interval = config.extra.get(
            "heartbeat_interval_sec", _DEFAULT_HEARTBEAT_SEC,
        )
        self._stats = {
            "heartbeats_sent": 0,
            "firmware_checks": 0,
            "firmware_alerts": 0,
            "protocol_events": 0,
            "cert_warnings": 0,
            "mqtt_messages_sent": 0,
        }

    @property
    def name(self) -> str:
        return "iot"

    @property
    def description(self) -> str:
        return "Constrained IoT device security (MQTT transport, firmware integrity, cert lifecycle)"

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._start_time = time.time()
        self._connect_mqtt()
        self._build_firmware_baseline()
        self._start_thread("heartbeat", self._heartbeat_loop)
        self._start_thread("firmware", self._firmware_check_loop)
        self._start_thread("certs", self._cert_lifecycle_loop)
        self._start_thread("protocols", self._protocol_monitor_loop)
        logger.info("[iot] profile started — firmware files: %d, certs: %d",
                     len(self._firmware_baselines), len(self._cert_paths))

    def stop(self) -> None:
        self._running = False
        self._disconnect_mqtt()
        self._join_threads()
        logger.info("[iot] profile stopped")

    # ── collection ────────────────────────────────────────────────────

    def collect_events(self) -> List[dict]:
        events: List[dict] = []
        events.extend(self._check_firmware_integrity())
        events.extend(self._check_certificate_expiry())
        events.extend(self._collect_protocol_activity())
        return events

    def apply_rules(self, rules: List[dict]) -> None:
        for rule in rules:
            action = rule.get("action", "")
            logger.info("[iot] applying rule: %s", action)
            if action == "block_protocol":
                protocol = rule.get("protocol", "")
                logger.info("[iot] blocking protocol: %s", protocol)
            elif action == "update_firmware":
                logger.info("[iot] firmware update signalled via control plane")

    def get_status(self) -> dict:
        return {
            "profile": self.name,
            "running": self._running,
            "uptime": self.uptime_seconds,
            "mqtt_connected": self._mqtt_client is not None,
            "firmware_files": len(self._firmware_baselines),
            "certs_monitored": len(self._cert_paths),
            **self._stats,
        }

    # ── MQTT transport ────────────────────────────────────────────────

    def _connect_mqtt(self) -> None:
        if not self._mqtt_broker:
            logger.info("[iot] no MQTT broker configured; events will use event bus only")
            return
        try:
            import paho.mqtt.client as mqtt
            self._mqtt_client = mqtt.Client(
                client_id=f"sentinel-iot-{self._config.extra.get('device_id', 'unknown')[:12]}",
                protocol=mqtt.MQTTv5,
            )
            if self._mqtt_use_tls:
                tls_ctx = ssl.create_default_context(cafile=self._mqtt_ca_cert or None)
                if self._mqtt_client_cert and self._mqtt_client_key:
                    tls_ctx.load_cert_chain(self._mqtt_client_cert, self._mqtt_client_key)
                self._mqtt_client.tls_set_context(tls_ctx)
            self._mqtt_client.connect(self._mqtt_broker, self._mqtt_port, keepalive=60)
            self._mqtt_client.loop_start()
            logger.info("[iot] MQTT connected to %s:%d", self._mqtt_broker, self._mqtt_port)
        except Exception as exc:
            logger.warning("[iot] MQTT connection failed (events via bus only): %s", exc)
            self._mqtt_client = None

    def _disconnect_mqtt(self) -> None:
        if self._mqtt_client is not None:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except Exception as exc:
                logger.debug("[iot] MQTT disconnect error: %s", exc)
            self._mqtt_client = None

    def _mqtt_publish(self, subtopic: str, payload: dict) -> bool:
        if self._mqtt_client is None:
            return False
        try:
            topic = f"{self._mqtt_topic_prefix}/{subtopic}"
            data = json.dumps(payload, default=str).encode("utf-8")
            result = self._mqtt_client.publish(topic, data, qos=1)
            if result.rc == 0:
                self._stats["mqtt_messages_sent"] += 1
                return True
            return False
        except Exception as exc:
            logger.debug("[iot] MQTT publish error: %s", exc)
            return False

    # ── firmware integrity ────────────────────────────────────────────

    def _build_firmware_baseline(self) -> None:
        self._firmware_baselines.clear()
        for path in self._firmware_paths:
            h = self._hash_file(path)
            if h is not None:
                self._firmware_baselines[path] = h

    def _check_firmware_integrity(self) -> List[dict]:
        alerts: List[dict] = []
        self._stats["firmware_checks"] += 1
        for path, expected in list(self._firmware_baselines.items()):
            current = self._hash_file(path)
            if current is None:
                alerts.append({
                    "event_type": "firmware_integrity_alert",
                    "severity": "critical",
                    "path": path,
                    "change": "missing",
                    "timestamp": time.time(),
                })
                self._stats["firmware_alerts"] += 1
            elif current != expected:
                alerts.append({
                    "event_type": "firmware_integrity_alert",
                    "severity": "critical",
                    "path": path,
                    "change": "modified",
                    "expected_hash": expected[:16],
                    "current_hash": current[:16],
                    "timestamp": time.time(),
                })
                self._firmware_baselines[path] = current
                self._stats["firmware_alerts"] += 1
        return alerts

    @staticmethod
    def _hash_file(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    # ── certificate lifecycle ─────────────────────────────────────────

    def _check_certificate_expiry(self) -> List[dict]:
        events: List[dict] = []
        for cert_path in self._cert_paths:
            days_left = self._cert_days_remaining(cert_path)
            if days_left is None:
                continue
            if days_left <= 0:
                events.append({
                    "event_type": "cert_expired",
                    "severity": "critical",
                    "cert_path": cert_path,
                    "days_remaining": days_left,
                    "timestamp": time.time(),
                })
                self._stats["cert_warnings"] += 1
            elif days_left <= _CERT_RENEWAL_WARN_DAYS:
                events.append({
                    "event_type": "cert_expiry_warning",
                    "severity": "high",
                    "cert_path": cert_path,
                    "days_remaining": days_left,
                    "timestamp": time.time(),
                })
                self._stats["cert_warnings"] += 1
        return events

    @staticmethod
    def _cert_days_remaining(cert_path: str) -> Optional[int]:
        try:
            pem_data = Path(cert_path).read_bytes()
            cert = ssl.PEM_cert_to_DER_cert(pem_data.decode("ascii"))
            x509 = ssl.DER_cert_to_PEM_cert(cert)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_verify_locations(cadata=x509)
            not_after = ctx.get_ca_certs()[0].get("notAfter", "")
            if not not_after:
                return None
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            return (expiry - datetime.now(timezone.utc)).days
        except Exception:
            return None

    # ── protocol monitoring ───────────────────────────────────────────

    def _collect_protocol_activity(self) -> List[dict]:
        events: List[dict] = []
        for proto in self._monitored_protocols:
            if proto == "mqtt" and self._mqtt_client is not None:
                events.append({
                    "event_type": "protocol_status",
                    "protocol": "mqtt",
                    "status": "connected",
                    "messages_sent": self._stats["mqtt_messages_sent"],
                    "timestamp": time.time(),
                })
                self._stats["protocol_events"] += 1
            elif proto == "coap":
                events.append({
                    "event_type": "protocol_status",
                    "protocol": "coap",
                    "status": "monitoring",
                    "timestamp": time.time(),
                })
                self._stats["protocol_events"] += 1
        return events

    # ── background loops ──────────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        while self._running:
            heartbeat = {
                "event_type": "iot_heartbeat",
                "device_id": self._config.extra.get("device_id", "unknown"),
                "timestamp": time.time(),
                "uptime": self.uptime_seconds,
                "memory_free": self._free_memory_bytes(),
            }
            self._publish(heartbeat)
            self._mqtt_publish("heartbeat", heartbeat)
            self._stats["heartbeats_sent"] += 1
            time.sleep(self._heartbeat_interval)

    def _firmware_check_loop(self) -> None:
        interval = self._config.extra.get("firmware_check_interval_sec", 300)
        while self._running:
            time.sleep(interval)
            try:
                for alert in self._check_firmware_integrity():
                    self._publish(alert)
                    self._mqtt_publish("alerts", alert)
            except Exception as exc:
                logger.error("[iot] firmware check error: %s", exc)

    def _cert_lifecycle_loop(self) -> None:
        interval = self._config.extra.get("cert_check_interval_sec", 3600)
        while self._running:
            time.sleep(interval)
            try:
                for event in self._check_certificate_expiry():
                    self._publish(event)
                    self._mqtt_publish("alerts", event)
            except Exception as exc:
                logger.error("[iot] cert lifecycle error: %s", exc)

    def _protocol_monitor_loop(self) -> None:
        interval = self._config.extra.get("protocol_check_interval_sec", 60)
        while self._running:
            time.sleep(interval)
            try:
                for event in self._collect_protocol_activity():
                    self._publish(event)
            except Exception as exc:
                logger.error("[iot] protocol monitor error: %s", exc)

    @staticmethod
    def _free_memory_bytes() -> int:
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            pass
        return 0
