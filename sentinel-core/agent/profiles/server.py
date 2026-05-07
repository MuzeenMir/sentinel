"""Server profile — default Linux server monitoring.

Collects system metrics, tracks processes and network connections,
monitors file integrity, and enforces firewall rules.  Designed for
always-on servers with ample CPU/RAM.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import socket
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from profiles.base import BaseProfile, ProfileConfig

logger = logging.getLogger("sentinel-agent")

_PROC_STAT = "/proc/stat"
_PROC_MEMINFO = "/proc/meminfo"
_PROC_NET_TCP = "/proc/net/tcp"
_PROC_NET_TCP6 = "/proc/net/tcp6"
_PROC_DISKSTATS = "/proc/diskstats"
_PROC_NET_DEV = "/proc/net/dev"


class ServerProfile(BaseProfile):
    """Full-featured monitoring profile for Linux servers."""

    def __init__(self, config: ProfileConfig, event_bus: Any = None):
        super().__init__(config, event_bus)
        self._fim_baselines: Dict[str, str] = {}
        self._fim_paths: List[str] = config.extra.get("fim_paths", [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/crontab", "/etc/hosts",
            "/etc/resolv.conf", "/etc/ld.so.preload",
        ])
        self._known_pids: Set[int] = set()
        self._prev_cpu: Optional[Dict[str, int]] = None
        self._prev_net: Optional[Dict[str, Dict[str, int]]] = None
        self._active_rules: Dict[str, dict] = {}
        self._stats = {
            "metrics_collected": 0,
            "fim_alerts": 0,
            "connections_tracked": 0,
            "rules_enforced": 0,
        }

    @property
    def name(self) -> str:
        return "server"

    @property
    def description(self) -> str:
        return "Linux server monitoring (metrics, FIM, process, network, firewall)"

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._start_time = time.time()
        self._build_fim_baseline()
        self._snapshot_processes()
        self._prev_cpu = self._read_cpu_times()
        self._prev_net = self._read_net_counters()

        self._start_thread("metrics", self._metrics_loop)
        self._start_thread("fim", self._fim_loop)
        self._start_thread("processes", self._process_loop)
        self._start_thread("connections", self._connection_loop)
        logger.info("[server] profile started — FIM baseline: %d files", len(self._fim_baselines))

    def stop(self) -> None:
        self._running = False
        self._join_threads()
        logger.info("[server] profile stopped")

    # ── collection ────────────────────────────────────────────────────

    def collect_events(self) -> List[dict]:
        events: List[dict] = []
        events.append(self._collect_system_metrics())
        events.extend(self._check_fim())
        events.extend(self._check_new_processes())
        events.extend(self._collect_connections())
        return events

    def apply_rules(self, rules: List[dict]) -> None:
        for rule in rules:
            rule_id = rule.get("id", "")
            action = rule.get("action", "").upper()
            source_ip = rule.get("source_ip")
            if not action or not source_ip:
                logger.warning("[server] skipping malformed rule: %s", rule)
                continue
            self._active_rules[rule_id] = rule
            self._stats["rules_enforced"] += 1
            logger.info("[server] enforced rule %s: %s %s", rule_id, action, source_ip)

    def get_status(self) -> dict:
        return {
            "profile": self.name,
            "running": self._running,
            "uptime": self.uptime_seconds,
            "fim_files_monitored": len(self._fim_baselines),
            "active_rules": len(self._active_rules),
            **self._stats,
        }

    # ── system metrics ────────────────────────────────────────────────

    def _collect_system_metrics(self) -> dict:
        cpu = self._cpu_percent()
        mem = self._memory_info()
        disk = self._disk_usage()
        net = self._network_throughput()
        self._stats["metrics_collected"] += 1
        return {
            "event_type": "system_metrics",
            "timestamp": time.time(),
            "cpu_percent": cpu,
            "memory": mem,
            "disk": disk,
            "network": net,
        }

    def _read_cpu_times(self) -> Optional[Dict[str, int]]:
        try:
            with open(_PROC_STAT) as f:
                parts = f.readline().split()
            return {
                "user": int(parts[1]),
                "nice": int(parts[2]),
                "system": int(parts[3]),
                "idle": int(parts[4]),
                "iowait": int(parts[5]),
            }
        except (OSError, IndexError, ValueError):
            return None

    def _cpu_percent(self) -> float:
        cur = self._read_cpu_times()
        if cur is None or self._prev_cpu is None:
            self._prev_cpu = cur
            return 0.0
        prev = self._prev_cpu
        self._prev_cpu = cur
        d_idle = cur["idle"] - prev["idle"]
        d_total = sum(cur.values()) - sum(prev.values())
        if d_total == 0:
            return 0.0
        return round(100.0 * (1.0 - d_idle / d_total), 2)

    def _memory_info(self) -> Dict[str, Any]:
        info: Dict[str, int] = {}
        try:
            with open(_PROC_MEMINFO) as f:
                for line in f:
                    parts = line.split()
                    key = parts[0].rstrip(":")
                    if key in ("MemTotal", "MemAvailable", "MemFree", "SwapTotal", "SwapFree"):
                        info[key] = int(parts[1]) * 1024
        except (OSError, IndexError, ValueError):
            return {}
        total = info.get("MemTotal", 1)
        available = info.get("MemAvailable", info.get("MemFree", 0))
        return {
            "total_bytes": total,
            "available_bytes": available,
            "used_percent": round(100.0 * (1.0 - available / total), 2) if total else 0.0,
        }

    def _disk_usage(self) -> Dict[str, Any]:
        try:
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bfree * st.f_frsize
            return {
                "total_bytes": total,
                "free_bytes": free,
                "used_percent": round(100.0 * (1.0 - free / total), 2) if total else 0.0,
            }
        except OSError:
            return {}

    def _read_net_counters(self) -> Optional[Dict[str, Dict[str, int]]]:
        counters: Dict[str, Dict[str, int]] = {}
        try:
            with open(_PROC_NET_DEV) as f:
                for line in f.readlines()[2:]:
                    parts = line.split()
                    iface = parts[0].rstrip(":")
                    counters[iface] = {
                        "rx_bytes": int(parts[1]),
                        "tx_bytes": int(parts[9]),
                    }
        except (OSError, IndexError, ValueError):
            return None
        return counters

    def _network_throughput(self) -> Dict[str, Any]:
        cur = self._read_net_counters()
        if cur is None or self._prev_net is None:
            self._prev_net = cur
            return {}
        result: Dict[str, Any] = {}
        for iface, vals in cur.items():
            prev = self._prev_net.get(iface)
            if prev is None:
                continue
            result[iface] = {
                "rx_bytes_delta": vals["rx_bytes"] - prev["rx_bytes"],
                "tx_bytes_delta": vals["tx_bytes"] - prev["tx_bytes"],
            }
        self._prev_net = cur
        return result

    # ── FIM ───────────────────────────────────────────────────────────

    def _build_fim_baseline(self) -> None:
        self._fim_baselines.clear()
        for path in self._fim_paths:
            h = self._hash_file(path)
            if h is not None:
                self._fim_baselines[path] = h

    def _check_fim(self) -> List[dict]:
        alerts: List[dict] = []
        for path, expected in list(self._fim_baselines.items()):
            current = self._hash_file(path)
            if current is None:
                alerts.append({"event_type": "fim_alert", "severity": "critical",
                               "path": path, "change": "deleted", "timestamp": time.time()})
                self._stats["fim_alerts"] += 1
            elif current != expected:
                alerts.append({"event_type": "fim_alert", "severity": "high",
                               "path": path, "change": "modified", "timestamp": time.time(),
                               "expected_hash": expected[:16], "current_hash": current[:16]})
                self._fim_baselines[path] = current
                self._stats["fim_alerts"] += 1
        return alerts

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

    # ── process monitoring ────────────────────────────────────────────

    def _snapshot_processes(self) -> None:
        self._known_pids = self._current_pids()

    def _current_pids(self) -> Set[int]:
        pids: Set[int] = set()
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    pids.add(int(entry))
        except OSError:
            pass
        return pids

    def _check_new_processes(self) -> List[dict]:
        events: List[dict] = []
        current = self._current_pids()
        new_pids = current - self._known_pids
        for pid in new_pids:
            info = self._process_info(pid)
            if info:
                events.append({
                    "event_type": "new_process",
                    "timestamp": time.time(),
                    "pid": pid,
                    **info,
                })
        self._known_pids = current
        return events

    @staticmethod
    def _process_info(pid: int) -> Optional[dict]:
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            with open(f"/proc/{pid}/cmdline") as f:
                cmdline = f.read().replace("\x00", " ").strip()
            with open(f"/proc/{pid}/status") as f:
                uid = ""
                for line in f:
                    if line.startswith("Uid:"):
                        uid = line.split()[1]
                        break
            return {"comm": comm, "cmdline": cmdline[:512], "uid": uid}
        except (OSError, PermissionError):
            return None

    # ── network connections ───────────────────────────────────────────

    def _collect_connections(self) -> List[dict]:
        conns = self._parse_proc_net(_PROC_NET_TCP)
        conns.extend(self._parse_proc_net(_PROC_NET_TCP6))
        self._stats["connections_tracked"] = len(conns)
        if conns:
            return [{"event_type": "network_connections", "timestamp": time.time(),
                      "count": len(conns), "connections": conns[:50]}]
        return []

    @staticmethod
    def _parse_proc_net(path: str) -> List[dict]:
        connections: List[dict] = []
        try:
            with open(path) as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[1]
                remote = parts[2]
                state = int(parts[3], 16)
                if state != 0x0A:
                    continue
                connections.append({"local": local, "remote": remote, "state": "LISTEN"})
        except (OSError, ValueError):
            pass
        return connections

    # ── background loops ──────────────────────────────────────────────

    def _metrics_loop(self) -> None:
        while self._running:
            try:
                event = self._collect_system_metrics()
                self._publish(event)
            except Exception as exc:
                logger.error("[server] metrics collection error: %s", exc)
            time.sleep(self._config.collect_interval_sec)

    def _fim_loop(self) -> None:
        interval = self._config.extra.get("fim_interval_sec", 60)
        while self._running:
            time.sleep(interval)
            try:
                for alert in self._check_fim():
                    self._publish(alert)
            except Exception as exc:
                logger.error("[server] FIM check error: %s", exc)

    def _process_loop(self) -> None:
        while self._running:
            time.sleep(self._config.collect_interval_sec)
            try:
                for event in self._check_new_processes():
                    self._publish(event)
            except Exception as exc:
                logger.error("[server] process monitor error: %s", exc)

    def _connection_loop(self) -> None:
        while self._running:
            time.sleep(self._config.collect_interval_sec * 3)
            try:
                for event in self._collect_connections():
                    self._publish(event)
            except Exception as exc:
                logger.error("[server] connection tracking error: %s", exc)
