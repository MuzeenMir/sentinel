"""Abstract base class for all SENTINEL agent profiles.

Every deployment target (server, IoT, robotics, endpoint, business-app)
implements this interface so the agent core can treat them uniformly while
each profile tailors collection, enforcement, and transport to its platform.
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinel-agent")


@dataclass
class ProfileConfig:
    """Runtime configuration passed to every profile."""

    profile_name: str = ""
    control_plane_url: str = ""
    kafka_servers: str = ""
    auth_token: str = ""
    data_dir: str = "/var/lib/sentinel"
    log_dir: str = "/var/log/sentinel"
    heartbeat_interval_sec: int = 30
    collect_interval_sec: int = 10
    extra: Dict[str, Any] = field(default_factory=dict)


class BaseProfile(ABC):
    """Abstract profile that every platform-specific profile must implement."""

    def __init__(self, config: ProfileConfig, event_bus: Any = None):
        self._config = config
        self._event_bus = event_bus
        self._running = False
        self._threads: List[threading.Thread] = []
        self._start_time: Optional[float] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Short machine-readable identifier (e.g. ``server``, ``iot``)."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable one-liner for logs and the control-plane UI."""

    @abstractmethod
    def start(self) -> None:
        """Initialise subsystems and begin collection loops."""

    @abstractmethod
    def stop(self) -> None:
        """Gracefully shut down all subsystems and flush pending data."""

    @abstractmethod
    def collect_events(self) -> List[dict]:
        """Run a single collection cycle and return new events."""

    @abstractmethod
    def apply_rules(self, rules: List[dict]) -> None:
        """Apply enforcement rules pushed from the control plane."""

    @abstractmethod
    def get_status(self) -> dict:
        """Return a snapshot of profile-specific health/statistics."""

    def healthcheck(self) -> bool:
        """Return *True* if the profile considers itself healthy."""
        return self._running

    # ── helpers available to all profiles ─────────────────────────────

    def _publish(self, event: dict) -> None:
        """Push an event into the shared agent event bus."""
        if self._event_bus is not None:
            self._event_bus.publish(event)

    def _start_thread(self, name: str, target: callable, daemon: bool = True) -> None:
        t = threading.Thread(target=target, name=f"profile-{self.name}-{name}", daemon=daemon)
        t.start()
        self._threads.append(t)

    def _join_threads(self, timeout: float = 5.0) -> None:
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()

    @property
    def uptime_seconds(self) -> float:
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time
