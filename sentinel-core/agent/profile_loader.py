"""Profile loader — detects platform and instantiates the right profile.

Provides auto-detection heuristics and a manual override via config.
The registry maps short names to profile classes so profiles can be
loaded by name from config files or CLI flags.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
from pathlib import Path
from typing import Any, Dict, Optional, Type

from profiles.base import BaseProfile, ProfileConfig
from profiles.business_app import BusinessAppProfile
from profiles.endpoint import EndpointProfile
from profiles.iot import IoTProfile
from profiles.robotics import RoboticsProfile
from profiles.server import ServerProfile

logger = logging.getLogger("sentinel-agent")

_PROFILE_REGISTRY: Dict[str, Type[BaseProfile]] = {
    "server": ServerProfile,
    "iot": IoTProfile,
    "robotics": RoboticsProfile,
    "endpoint": EndpointProfile,
    "business_app": BusinessAppProfile,
}


class ProfileLoader:
    """Discovers, loads, and manages agent profiles."""

    def __init__(self) -> None:
        self._registry: Dict[str, Type[BaseProfile]] = dict(_PROFILE_REGISTRY)

    def register(self, name: str, cls: Type[BaseProfile]) -> None:
        self._registry[name] = cls
        logger.info("Registered profile: %s -> %s", name, cls.__name__)

    @property
    def available_profiles(self) -> list[str]:
        return sorted(self._registry.keys())

    # ── loading ───────────────────────────────────────────────────────

    def load_profile(
        self,
        profile_name: str,
        config: ProfileConfig,
        event_bus: Any = None,
    ) -> BaseProfile:
        cls = self._registry.get(profile_name)
        if cls is None:
            raise ValueError(
                f"Unknown profile {profile_name!r}. "
                f"Available: {', '.join(self.available_profiles)}"
            )
        profile = cls(config, event_bus)
        logger.info("Loaded profile: %s (%s)", profile.name, profile.description)
        return profile

    # ── auto-detection ────────────────────────────────────────────────

    def detect_platform(self) -> str:
        if self._is_robotics():
            return "robotics"
        if self._is_iot():
            return "iot"
        if self._is_business_app():
            return "business_app"
        if self._is_endpoint():
            return "endpoint"
        return "server"

    @staticmethod
    def _is_robotics() -> bool:
        if shutil.which("ros2") is not None:
            return True
        for env_var in ("ROS_DISTRO", "AMENT_PREFIX_PATH", "ROS_DOMAIN_ID"):
            if os.environ.get(env_var):
                return True
        can_path = Path("/sys/class/net")
        if can_path.exists():
            for iface in can_path.iterdir():
                if iface.name.startswith("can") or iface.name.startswith("vcan"):
                    return True
        return False

    @staticmethod
    def _is_iot() -> bool:
        arch = platform.machine().lower()
        if arch in ("armv6l", "armv7l", "aarch64", "mips", "mipsel"):
            try:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            mem_kb = int(line.split()[1])
                            if mem_kb < 2_097_152:
                                return True
                            break
            except (OSError, ValueError):
                pass
        for indicator in ("/etc/openwrt_release", "/etc/buildroot-id"):
            if os.path.exists(indicator):
                return True
        if os.environ.get("SENTINEL_PROFILE") == "iot":
            return True
        return False

    @staticmethod
    def _is_business_app() -> bool:
        app_indicators = (
            "FLASK_APP", "DJANGO_SETTINGS_MODULE", "RAILS_ENV",
            "NODE_ENV", "SPRING_PROFILES_ACTIVE", "SENTINEL_APP_SIDECAR",
        )
        return any(os.environ.get(var) for var in app_indicators)

    @staticmethod
    def _is_endpoint() -> bool:
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            return True
        if shutil.which("systemctl"):
            gdm = Path("/etc/systemd/system/display-manager.service")
            if gdm.exists():
                return True
        battery = Path("/sys/class/power_supply/BAT0")
        if battery.exists():
            return True
        return False
