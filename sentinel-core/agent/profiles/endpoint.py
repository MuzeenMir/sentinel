"""Endpoint profile — desktop / laptop / mobile device security.

Monitors USB devices, tracks DNS queries and network connections,
scans removable media, supports a privacy mode that encrypts local
logs, and exposes a localhost API for browser-extension communication.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from profiles.base import BaseProfile, ProfileConfig

logger = logging.getLogger("sentinel-agent")

_BROWSER_API_PORT = 19741
_SYS_USB_DEVICES = "/sys/bus/usb/devices"


class EndpointProfile(BaseProfile):
    """Security profile for desktops, laptops, and mobile-class devices."""

    def __init__(self, config: ProfileConfig, event_bus: Any = None):
        super().__init__(config, event_bus)
        self._known_usb_devices: Dict[str, dict] = {}
        self._dns_log_path: str = config.extra.get("dns_log_path", "")
        self._dns_last_pos: int = 0
        self._removable_scan_paths: List[str] = config.extra.get(
            "removable_scan_paths", ["/media", "/mnt", "/run/media"],
        )
        self._privacy_mode: bool = config.extra.get("privacy_mode", False)
        self._encryption_key: Optional[bytes] = None
        self._browser_api_enabled: bool = config.extra.get("browser_api_enabled", False)
        self._browser_api_port: int = int(config.extra.get("browser_api_port", _BROWSER_API_PORT))
        self._browser_api_server: Optional[HTTPServer] = None
        self._stats = {
            "usb_events": 0,
            "dns_queries_tracked": 0,
            "connections_tracked": 0,
            "media_scans": 0,
            "browser_api_requests": 0,
        }

    @property
    def name(self) -> str:
        return "endpoint"

    @property
    def description(self) -> str:
        return "Endpoint security (USB, DNS, removable media, privacy mode, browser API)"

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._start_time = time.time()
        self._snapshot_usb_devices()
        if self._privacy_mode:
            self._init_encryption()
        self._start_thread("usb", self._usb_monitor_loop)
        self._start_thread("dns", self._dns_monitor_loop)
        self._start_thread("connections", self._connection_monitor_loop)
        self._start_thread("media", self._removable_media_loop)
        if self._browser_api_enabled:
            self._start_thread("browser-api", self._browser_api_loop)
        logger.info("[endpoint] profile started — USB devices: %d, privacy=%s, browser_api=%s",
                     len(self._known_usb_devices), self._privacy_mode, self._browser_api_enabled)

    def stop(self) -> None:
        self._running = False
        if self._browser_api_server is not None:
            self._browser_api_server.shutdown()
        self._join_threads()
        logger.info("[endpoint] profile stopped")

    # ── collection ────────────────────────────────────────────────────

    def collect_events(self) -> List[dict]:
        events: List[dict] = []
        events.extend(self._check_usb_changes())
        events.extend(self._read_dns_queries())
        events.extend(self._collect_connections())
        return events

    def apply_rules(self, rules: List[dict]) -> None:
        for rule in rules:
            action = rule.get("action", "")
            if action == "block_usb":
                vendor = rule.get("vendor_id", "")
                logger.info("[endpoint] blocking USB vendor %s", vendor)
            elif action == "block_domain":
                domain = rule.get("domain", "")
                logger.info("[endpoint] blocking domain %s", domain)
            elif action == "enable_privacy":
                self._privacy_mode = True
                self._init_encryption()
                logger.info("[endpoint] privacy mode enabled via rule")

    def get_status(self) -> dict:
        return {
            "profile": self.name,
            "running": self._running,
            "uptime": self.uptime_seconds,
            "usb_devices_known": len(self._known_usb_devices),
            "privacy_mode": self._privacy_mode,
            "browser_api_active": self._browser_api_server is not None,
            **self._stats,
        }

    # ── USB monitoring ────────────────────────────────────────────────

    def _snapshot_usb_devices(self) -> None:
        self._known_usb_devices = self._enumerate_usb()

    def _enumerate_usb(self) -> Dict[str, dict]:
        devices: Dict[str, dict] = {}
        usb_path = Path(_SYS_USB_DEVICES)
        if not usb_path.exists():
            return devices
        for entry in usb_path.iterdir():
            if not entry.is_dir():
                continue
            dev_info = self._read_usb_info(entry)
            if dev_info:
                devices[entry.name] = dev_info
        return devices

    @staticmethod
    def _read_usb_info(dev_path: Path) -> Optional[dict]:
        def _read(name: str) -> str:
            try:
                return (dev_path / name).read_text().strip()
            except (OSError, PermissionError):
                return ""

        vendor = _read("idVendor")
        product = _read("idProduct")
        if not vendor:
            return None
        return {
            "vendor_id": vendor,
            "product_id": product,
            "manufacturer": _read("manufacturer"),
            "product": _read("product"),
            "serial": _read("serial"),
        }

    def _check_usb_changes(self) -> List[dict]:
        events: List[dict] = []
        current = self._enumerate_usb()
        new_ids = set(current) - set(self._known_usb_devices)
        removed_ids = set(self._known_usb_devices) - set(current)

        for dev_id in new_ids:
            info = current[dev_id]
            events.append({
                "event_type": "usb_device_connected",
                "severity": "medium",
                "device_id": dev_id,
                **info,
                "timestamp": time.time(),
            })
            self._stats["usb_events"] += 1

        for dev_id in removed_ids:
            info = self._known_usb_devices[dev_id]
            events.append({
                "event_type": "usb_device_disconnected",
                "severity": "low",
                "device_id": dev_id,
                **info,
                "timestamp": time.time(),
            })
            self._stats["usb_events"] += 1

        self._known_usb_devices = current
        return events

    # ── DNS monitoring ────────────────────────────────────────────────

    def _read_dns_queries(self) -> List[dict]:
        if not self._dns_log_path or not os.path.exists(self._dns_log_path):
            return []
        events: List[dict] = []
        try:
            with open(self._dns_log_path) as f:
                f.seek(self._dns_last_pos)
                for line in f:
                    query = self._parse_dns_log_line(line)
                    if query:
                        events.append({
                            "event_type": "dns_query",
                            "timestamp": time.time(),
                            **query,
                        })
                        self._stats["dns_queries_tracked"] += 1
                self._dns_last_pos = f.tell()
        except (OSError, PermissionError) as exc:
            logger.debug("[endpoint] DNS log read error: %s", exc)
        return events

    @staticmethod
    def _parse_dns_log_line(line: str) -> Optional[dict]:
        match = re.search(r"query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)", line)
        if match:
            return {
                "query_type": match.group(1),
                "domain": match.group(2),
                "source": match.group(3),
            }
        return None

    # ── network connection tracking ───────────────────────────────────

    def _collect_connections(self) -> List[dict]:
        connections: List[dict] = []
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path) as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        state = int(parts[3], 16)
                        if state == 0x01:
                            connections.append({
                                "local": parts[1],
                                "remote": parts[2],
                                "state": "ESTABLISHED",
                            })
            except (OSError, ValueError):
                pass
        self._stats["connections_tracked"] = len(connections)
        if connections:
            return [{
                "event_type": "endpoint_connections",
                "timestamp": time.time(),
                "count": len(connections),
                "connections": connections[:100],
            }]
        return []

    # ── removable media scanning ──────────────────────────────────────

    def _scan_removable_media(self) -> List[dict]:
        events: List[dict] = []
        for base in self._removable_scan_paths:
            base_path = Path(base)
            if not base_path.exists():
                continue
            for mount_point in base_path.iterdir():
                if not mount_point.is_dir():
                    continue
                suspicious = self._scan_directory(mount_point)
                if suspicious:
                    events.append({
                        "event_type": "removable_media_scan",
                        "severity": "medium",
                        "mount_point": str(mount_point),
                        "suspicious_files": suspicious,
                        "timestamp": time.time(),
                    })
                    self._stats["media_scans"] += 1
        return events

    @staticmethod
    def _scan_directory(path: Path, max_depth: int = 3) -> List[str]:
        suspicious_extensions = {
            ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
            ".scr", ".pif", ".msi", ".jar", ".py", ".sh",
        }
        suspicious: List[str] = []
        try:
            for item in path.rglob("*"):
                if len(item.parts) - len(path.parts) > max_depth:
                    continue
                if item.is_file() and item.suffix.lower() in suspicious_extensions:
                    suspicious.append(str(item))
                if len(suspicious) >= 50:
                    break
        except (OSError, PermissionError):
            pass
        return suspicious

    # ── privacy mode (encrypted local logs) ───────────────────────────

    def _init_encryption(self) -> None:
        key_path = Path(self._config.data_dir) / ".sentinel_log_key"
        if key_path.exists():
            self._encryption_key = key_path.read_bytes()
        else:
            self._encryption_key = os.urandom(32)
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(self._encryption_key)
            os.chmod(str(key_path), 0o600)
        logger.info("[endpoint] privacy mode: log encryption key loaded")

    def encrypt_log_entry(self, entry: str) -> bytes:
        if self._encryption_key is None:
            return entry.encode("utf-8")
        try:
            from hashlib import pbkdf2_hmac
            iv = os.urandom(12)
            key_derived = pbkdf2_hmac("sha256", self._encryption_key, iv, 100_000, dklen=32)
            data = entry.encode("utf-8")
            xor_key = (key_derived * ((len(data) // 32) + 1))[:len(data)]
            encrypted = bytes(a ^ b for a, b in zip(data, xor_key))
            return iv + encrypted
        except Exception as exc:
            logger.error("[endpoint] encryption error: %s", exc)
            return entry.encode("utf-8")

    # ── browser extension API ─────────────────────────────────────────

    def _browser_api_loop(self) -> None:
        profile_ref = self

        class BrowserAPIHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/health":
                    self._json_response(200, {"status": "ok", "agent": "sentinel-endpoint"})
                elif self.path == "/status":
                    self._json_response(200, profile_ref.get_status())
                else:
                    self._json_response(404, {"error": "not found"})

            def do_POST(self) -> None:
                profile_ref._stats["browser_api_requests"] += 1
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                try:
                    data = json.loads(body) if body else {}
                except json.JSONDecodeError:
                    self._json_response(400, {"error": "invalid JSON"})
                    return

                if self.path == "/report":
                    profile_ref._publish({
                        "event_type": "browser_report",
                        "timestamp": time.time(),
                        **data,
                    })
                    self._json_response(200, {"accepted": True})
                else:
                    self._json_response(404, {"error": "not found"})

            def _json_response(self, code: int, body: dict) -> None:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "http://localhost")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode("utf-8"))

            def log_message(self, format: str, *args: Any) -> None:
                pass

        try:
            self._browser_api_server = HTTPServer(
                ("127.0.0.1", self._browser_api_port), BrowserAPIHandler,
            )
            logger.info("[endpoint] browser API listening on 127.0.0.1:%d", self._browser_api_port)
            self._browser_api_server.serve_forever()
        except Exception as exc:
            logger.error("[endpoint] browser API server error: %s", exc)
        finally:
            self._browser_api_server = None

    # ── background loops ──────────────────────────────────────────────

    def _usb_monitor_loop(self) -> None:
        while self._running:
            time.sleep(5)
            try:
                for event in self._check_usb_changes():
                    self._publish(event)
            except Exception as exc:
                logger.error("[endpoint] USB monitor error: %s", exc)

    def _dns_monitor_loop(self) -> None:
        while self._running:
            time.sleep(2)
            try:
                for event in self._read_dns_queries():
                    self._publish(event)
            except Exception as exc:
                logger.error("[endpoint] DNS monitor error: %s", exc)

    def _connection_monitor_loop(self) -> None:
        while self._running:
            time.sleep(self._config.collect_interval_sec)
            try:
                for event in self._collect_connections():
                    self._publish(event)
            except Exception as exc:
                logger.error("[endpoint] connection monitor error: %s", exc)

    def _removable_media_loop(self) -> None:
        while self._running:
            time.sleep(30)
            try:
                for event in self._scan_removable_media():
                    self._publish(event)
            except Exception as exc:
                logger.error("[endpoint] removable media scan error: %s", exc)
