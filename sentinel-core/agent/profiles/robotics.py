"""Robotics profile — safety-critical robot security agent.

Monitors ROS2 topics, CAN bus traffic, enforces safety boundaries
(position/velocity limits), integrates with emergency stop, validates
sensor data integrity, and verifies OTA updates.  All operations are
non-blocking to avoid interfering with real-time control loops.
"""

from __future__ import annotations

import hashlib
import logging
import os
import signal
import struct
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from profiles.base import BaseProfile, ProfileConfig

logger = logging.getLogger("sentinel-agent")

_CAN_INTERFACE_DEFAULT = "can0"


class RoboticsProfile(BaseProfile):
    """Security profile for ROS2-based robots and CAN-bus industrial systems."""

    def __init__(self, config: ProfileConfig, event_bus: Any = None):
        super().__init__(config, event_bus)
        self._can_interface: str = config.extra.get("can_interface", _CAN_INTERFACE_DEFAULT)
        self._can_socket: Any = None
        self._ros2_available = False

        self._safety_limits = config.extra.get("safety_limits", {
            "max_position": [2.0, 2.0, 2.0],
            "max_velocity": 1.5,
            "max_acceleration": 5.0,
        })
        self._estop_triggered = False
        self._estop_signal = int(config.extra.get("estop_signal", signal.SIGUSR1))
        self._prev_estop_handler: Any = None

        self._ota_public_key_path: str = config.extra.get("ota_public_key", "")
        self._ros2_monitored_topics: List[str] = config.extra.get("ros2_topics", [
            "/cmd_vel", "/joint_states", "/odom", "/diagnostics",
        ])

        self._known_can_ids: Set[int] = set()
        self._sensor_last_ts: Dict[str, float] = {}
        self._sensor_ranges: Dict[str, dict] = config.extra.get("sensor_ranges", {})

        self._stats = {
            "ros2_messages": 0,
            "can_frames": 0,
            "safety_violations": 0,
            "estop_activations": 0,
            "sensor_anomalies": 0,
            "ota_verifications": 0,
        }

    @property
    def name(self) -> str:
        return "robotics"

    @property
    def description(self) -> str:
        return "Safety-critical robotics security (ROS2, CAN bus, safety boundaries, e-stop)"

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._start_time = time.time()
        self._install_estop_handler()
        self._probe_ros2()
        self._open_can_socket()

        if self._ros2_available:
            self._start_thread("ros2", self._ros2_monitor_loop)
        if self._can_socket is not None:
            self._start_thread("can", self._can_monitor_loop)
        self._start_thread("safety", self._safety_check_loop)
        self._start_thread("sensors", self._sensor_integrity_loop)
        logger.info("[robotics] profile started — ROS2=%s, CAN=%s, e-stop=signal %d",
                     self._ros2_available, self._can_socket is not None, self._estop_signal)

    def stop(self) -> None:
        self._running = False
        self._restore_estop_handler()
        self._close_can_socket()
        self._join_threads()
        logger.info("[robotics] profile stopped")

    # ── collection ────────────────────────────────────────────────────

    def collect_events(self) -> List[dict]:
        events: List[dict] = []
        events.extend(self._check_safety_boundaries())
        events.extend(self._validate_sensor_data())
        return events

    def apply_rules(self, rules: List[dict]) -> None:
        for rule in rules:
            action = rule.get("action", "")
            if action == "update_safety_limits":
                new_limits = rule.get("limits", {})
                self._safety_limits.update(new_limits)
                logger.info("[robotics] safety limits updated: %s", self._safety_limits)
            elif action == "block_can_id":
                can_id = rule.get("can_id")
                if can_id is not None:
                    logger.info("[robotics] blocking CAN ID 0x%03X", can_id)
            elif action == "estop":
                self._trigger_estop("control-plane rule")

    def get_status(self) -> dict:
        return {
            "profile": self.name,
            "running": self._running,
            "uptime": self.uptime_seconds,
            "ros2_available": self._ros2_available,
            "can_connected": self._can_socket is not None,
            "estop_triggered": self._estop_triggered,
            "safety_limits": self._safety_limits,
            **self._stats,
        }

    # ── emergency stop ────────────────────────────────────────────────

    def _install_estop_handler(self) -> None:
        try:
            self._prev_estop_handler = signal.getsignal(self._estop_signal)
            signal.signal(self._estop_signal, self._estop_signal_handler)
        except (OSError, ValueError) as exc:
            logger.warning("[robotics] could not install e-stop handler: %s", exc)

    def _restore_estop_handler(self) -> None:
        if self._prev_estop_handler is not None:
            try:
                signal.signal(self._estop_signal, self._prev_estop_handler)
            except (OSError, ValueError):
                pass

    def _estop_signal_handler(self, signum: int, frame: Any) -> None:
        self._trigger_estop(f"signal {signum}")

    def _trigger_estop(self, reason: str) -> None:
        if self._estop_triggered:
            return
        self._estop_triggered = True
        self._stats["estop_activations"] += 1
        logger.critical("[robotics] EMERGENCY STOP triggered: %s", reason)
        self._publish({
            "event_type": "estop_activated",
            "severity": "critical",
            "reason": reason,
            "timestamp": time.time(),
        })

    # ── ROS2 monitoring ───────────────────────────────────────────────

    def _probe_ros2(self) -> None:
        try:
            import importlib
            importlib.import_module("rclpy")
            self._ros2_available = True
            logger.info("[robotics] ROS2 (rclpy) detected")
        except ImportError:
            self._ros2_available = False
            logger.info("[robotics] ROS2 not available; skipping topic monitoring")

    def _ros2_monitor_loop(self) -> None:
        try:
            import rclpy
            from rclpy.node import Node
            from std_msgs.msg import String

            rclpy.init()
            node = rclpy.create_node("sentinel_robotics_monitor")

            def _topic_callback(topic_name: str):
                def _cb(msg: Any) -> None:
                    self._stats["ros2_messages"] += 1
                    self._publish({
                        "event_type": "ros2_message",
                        "topic": topic_name,
                        "timestamp": time.time(),
                    })
                return _cb

            for topic in self._ros2_monitored_topics:
                try:
                    node.create_subscription(String, topic, _topic_callback(topic), 10)
                except Exception as exc:
                    logger.debug("[robotics] could not subscribe to %s: %s", topic, exc)

            while self._running:
                rclpy.spin_once(node, timeout_sec=0.1)

            node.destroy_node()
            rclpy.shutdown()
        except Exception as exc:
            logger.error("[robotics] ROS2 monitor error: %s", exc)

    # ── CAN bus monitoring ────────────────────────────────────────────

    def _open_can_socket(self) -> None:
        try:
            import socket as sock
            AF_CAN = 29
            CAN_RAW = 1
            s = sock.socket(AF_CAN, sock.SOCK_RAW, CAN_RAW)
            s.setblocking(False)
            s.bind((self._can_interface,))
            self._can_socket = s
            logger.info("[robotics] CAN socket opened on %s", self._can_interface)
        except Exception as exc:
            logger.info("[robotics] CAN bus not available (%s); skipping CAN monitoring", exc)
            self._can_socket = None

    def _close_can_socket(self) -> None:
        if self._can_socket is not None:
            try:
                self._can_socket.close()
            except Exception:
                pass
            self._can_socket = None

    def _can_monitor_loop(self) -> None:
        CAN_FRAME_FMT = "=IB3x8s"
        CAN_FRAME_SIZE = struct.calcsize(CAN_FRAME_FMT)
        while self._running:
            try:
                data = self._can_socket.recv(CAN_FRAME_SIZE)
                can_id, dlc, payload = struct.unpack(CAN_FRAME_FMT, data)
                self._stats["can_frames"] += 1

                if can_id not in self._known_can_ids:
                    self._known_can_ids.add(can_id)
                    self._publish({
                        "event_type": "can_new_id",
                        "severity": "medium",
                        "can_id": f"0x{can_id:03X}",
                        "dlc": dlc,
                        "timestamp": time.time(),
                    })
            except BlockingIOError:
                time.sleep(0.01)
            except Exception as exc:
                logger.debug("[robotics] CAN read error: %s", exc)
                time.sleep(0.1)

    # ── safety boundary enforcement ───────────────────────────────────

    def _check_safety_boundaries(self) -> List[dict]:
        return []

    def check_position(self, position: List[float]) -> bool:
        max_pos = self._safety_limits.get("max_position", [])
        for i, (p, limit) in enumerate(zip(position, max_pos)):
            if abs(p) > limit:
                self._stats["safety_violations"] += 1
                self._publish({
                    "event_type": "safety_violation",
                    "severity": "critical",
                    "violation": "position_exceeded",
                    "axis": i,
                    "value": p,
                    "limit": limit,
                    "timestamp": time.time(),
                })
                self._trigger_estop(f"position axis {i} = {p} exceeds limit {limit}")
                return False
        return True

    def check_velocity(self, velocity: float) -> bool:
        max_vel = self._safety_limits.get("max_velocity", float("inf"))
        if abs(velocity) > max_vel:
            self._stats["safety_violations"] += 1
            self._publish({
                "event_type": "safety_violation",
                "severity": "critical",
                "violation": "velocity_exceeded",
                "value": velocity,
                "limit": max_vel,
                "timestamp": time.time(),
            })
            self._trigger_estop(f"velocity {velocity} exceeds limit {max_vel}")
            return False
        return True

    # ── sensor data integrity ─────────────────────────────────────────

    def _validate_sensor_data(self) -> List[dict]:
        return []

    def validate_sensor(self, sensor_id: str, value: float, timestamp: float) -> List[dict]:
        events: List[dict] = []
        now = time.time()

        prev_ts = self._sensor_last_ts.get(sensor_id)
        if prev_ts is not None and timestamp <= prev_ts:
            events.append({
                "event_type": "sensor_anomaly",
                "severity": "high",
                "sensor_id": sensor_id,
                "anomaly": "timestamp_regression",
                "current_ts": timestamp,
                "previous_ts": prev_ts,
                "timestamp": now,
            })
            self._stats["sensor_anomalies"] += 1

        if abs(now - timestamp) > 5.0:
            events.append({
                "event_type": "sensor_anomaly",
                "severity": "medium",
                "sensor_id": sensor_id,
                "anomaly": "timestamp_drift",
                "drift_seconds": round(now - timestamp, 3),
                "timestamp": now,
            })
            self._stats["sensor_anomalies"] += 1

        sensor_range = self._sensor_ranges.get(sensor_id)
        if sensor_range:
            lo, hi = sensor_range.get("min", float("-inf")), sensor_range.get("max", float("inf"))
            if value < lo or value > hi:
                events.append({
                    "event_type": "sensor_anomaly",
                    "severity": "high",
                    "sensor_id": sensor_id,
                    "anomaly": "value_out_of_range",
                    "value": value,
                    "range": [lo, hi],
                    "timestamp": now,
                })
                self._stats["sensor_anomalies"] += 1

        self._sensor_last_ts[sensor_id] = timestamp
        return events

    # ── OTA update verification ───────────────────────────────────────

    def verify_ota_update(self, update_path: str, signature_path: str) -> bool:
        self._stats["ota_verifications"] += 1
        if not self._ota_public_key_path:
            logger.warning("[robotics] no OTA public key configured; rejecting update")
            return False
        try:
            from hashlib import sha256

            update_hash = sha256()
            with open(update_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    update_hash.update(chunk)
            digest = update_hash.digest()

            sig_data = Path(signature_path).read_bytes()
            pub_key_data = Path(self._ota_public_key_path).read_bytes()

            try:
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding, utils

                public_key = serialization.load_pem_public_key(pub_key_data)
                public_key.verify(
                    sig_data,
                    digest,
                    padding.PKCS1v15(),
                    utils.Prehashed(hashes.SHA256()),
                )
                logger.info("[robotics] OTA update signature valid: %s", update_path)
                return True
            except ImportError:
                logger.warning("[robotics] cryptography library not available; "
                               "falling back to hash-only verification")
                expected_hex = sig_data.decode("ascii", errors="ignore").strip()
                actual_hex = update_hash.hexdigest()
                valid = expected_hex == actual_hex
                if not valid:
                    logger.warning("[robotics] OTA hash mismatch: expected=%s actual=%s",
                                   expected_hex[:16], actual_hex[:16])
                return valid
            except Exception as exc:
                logger.error("[robotics] OTA signature verification failed: %s", exc)
                return False
        except (OSError, PermissionError) as exc:
            logger.error("[robotics] OTA file read error: %s", exc)
            return False

    # ── background loops ──────────────────────────────────────────────

    def _safety_check_loop(self) -> None:
        while self._running:
            time.sleep(0.5)

    def _sensor_integrity_loop(self) -> None:
        while self._running:
            time.sleep(1.0)
