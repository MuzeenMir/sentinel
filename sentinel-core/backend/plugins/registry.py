"""Plugin registry for the SENTINEL backend.

Plugins extend SENTINEL at runtime — custom detectors, new compliance
frameworks, additional hardening checks, etc.  The registry manages
discovery, lifecycle, and health for every loaded plugin.

Usage::

    from plugins.registry import PluginRegistry, Plugin

    registry = PluginRegistry()
    registry.discover_plugins("/opt/sentinel/plugins")
    registry.start_all(config={})

    # — or use the decorator —

    @registry.register
    class MyPlugin(Plugin):
        ...
"""

from __future__ import annotations

import importlib
import logging
import os
import pkgutil
import sys
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger("sentinel-plugins")


class Plugin(ABC):
    """Interface that every SENTINEL plugin must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique short name used as the registry key."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Semver string (e.g. ``1.2.0``)."""

    @property
    def description(self) -> str:
        return ""

    @abstractmethod
    def init(self, config: Dict[str, Any]) -> None:
        """One-time initialisation with runtime config."""

    @abstractmethod
    def start(self) -> None:
        """Begin processing (called after ``init``)."""

    @abstractmethod
    def stop(self) -> None:
        """Gracefully shut down and release resources."""

    def health_check(self) -> bool:
        """Return *True* if the plugin considers itself healthy."""
        return True


class _PluginEntry:
    """Internal bookkeeping for a registered plugin."""

    __slots__ = ("cls", "instance", "started_at", "enabled")

    def __init__(self, cls: Type[Plugin]):
        self.cls = cls
        self.instance: Optional[Plugin] = None
        self.started_at: Optional[float] = None
        self.enabled: bool = True


class PluginRegistry:
    """Central catalogue of available and running plugins."""

    def __init__(self) -> None:
        self._plugins: Dict[str, _PluginEntry] = {}

    # ── registration ──────────────────────────────────────────────────

    def register(self, plugin_class: Type[Plugin]) -> Type[Plugin]:
        """Register a plugin class (also works as a ``@decorator``)."""
        if not (isinstance(plugin_class, type) and issubclass(plugin_class, Plugin)):
            raise TypeError(f"{plugin_class!r} must be a subclass of Plugin")

        try:
            temp = plugin_class.__new__(plugin_class)
            name = temp.name
        except Exception as exc:
            raise TypeError(
                f"Could not read .name from {plugin_class!r}: {exc}"
            ) from exc

        if name in self._plugins:
            logger.warning(
                "Plugin %r already registered; replacing with %s",
                name,
                plugin_class.__name__,
            )
        self._plugins[name] = _PluginEntry(plugin_class)
        logger.info("Plugin registered: %s (%s)", name, plugin_class.__name__)
        return plugin_class

    # ── discovery ─────────────────────────────────────────────────────

    def discover_plugins(self, plugin_dir: str) -> int:
        """Import every ``.py`` file in *plugin_dir* and register any ``Plugin`` subclasses found."""
        loaded = 0
        if not os.path.isdir(plugin_dir):
            logger.warning("Plugin directory does not exist: %s", plugin_dir)
            return loaded

        if plugin_dir not in sys.path:
            sys.path.insert(0, plugin_dir)

        for finder, module_name, is_pkg in pkgutil.iter_modules([plugin_dir]):
            try:
                mod = importlib.import_module(module_name)
                for attr_name in dir(mod):
                    obj = getattr(mod, attr_name)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, Plugin)
                        and obj is not Plugin
                    ):
                        self.register(obj)
                        loaded += 1
            except Exception as exc:
                logger.error("Failed to import plugin module %s: %s", module_name, exc)

        logger.info("Plugin discovery complete: %d plugins from %s", loaded, plugin_dir)
        return loaded

    # ── lookup ────────────────────────────────────────────────────────

    def get_plugin(self, name: str) -> Optional[Plugin]:
        entry = self._plugins.get(name)
        if entry is None or entry.instance is None:
            return None
        return entry.instance

    def list_plugins(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for name, entry in self._plugins.items():
            info: Dict[str, Any] = {
                "name": name,
                "class": entry.cls.__name__,
                "enabled": entry.enabled,
                "running": entry.instance is not None,
            }
            if entry.instance is not None:
                info["version"] = entry.instance.version
                info["description"] = entry.instance.description
                info["healthy"] = entry.instance.health_check()
            if entry.started_at is not None:
                info["uptime_seconds"] = round(time.time() - entry.started_at, 1)
            result.append(info)
        return result

    # ── lifecycle ─────────────────────────────────────────────────────

    def init_all(self, config: Dict[str, Any]) -> None:
        for name, entry in self._plugins.items():
            if not entry.enabled:
                continue
            try:
                instance = entry.cls()
                plugin_config = config.get(name, {})
                instance.init(plugin_config)
                entry.instance = instance
                logger.info("Plugin initialised: %s v%s", name, instance.version)
            except Exception as exc:
                logger.error("Plugin %s init failed: %s", name, exc)
                entry.enabled = False

    def start_all(self, config: Optional[Dict[str, Any]] = None) -> None:
        if config is not None:
            self.init_all(config)
        for name, entry in self._plugins.items():
            if entry.instance is None or not entry.enabled:
                continue
            try:
                entry.instance.start()
                entry.started_at = time.time()
                logger.info("Plugin started: %s", name)
            except Exception as exc:
                logger.error("Plugin %s start failed: %s", name, exc)
                entry.enabled = False

    def stop_all(self) -> None:
        for name, entry in reversed(list(self._plugins.items())):
            if entry.instance is None:
                continue
            try:
                entry.instance.stop()
                logger.info("Plugin stopped: %s", name)
            except Exception as exc:
                logger.error("Plugin %s stop failed: %s", name, exc)
            entry.instance = None
            entry.started_at = None

    def health_check_all(self) -> Dict[str, bool]:
        results: Dict[str, bool] = {}
        for name, entry in self._plugins.items():
            if entry.instance is None:
                results[name] = False
            else:
                try:
                    results[name] = entry.instance.health_check()
                except Exception:
                    results[name] = False
        return results
