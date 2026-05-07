"""Plugin loader — imports plugin modules from directories or packages.

Separates the file-system / packaging concerns from the registry so
the registry stays focused on lifecycle management.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any, List, Type

from plugins.registry import Plugin

logger = logging.getLogger("sentinel-plugins")


class PluginLoader:
    """Discovers and imports plugin modules."""

    @staticmethod
    def load_from_directory(path: str) -> List[Type[Plugin]]:
        """Import all ``.py`` files in *path* and return discovered ``Plugin`` subclasses."""
        plugins: List[Type[Plugin]] = []
        dir_path = Path(path)
        if not dir_path.is_dir():
            logger.warning("Plugin directory not found: %s", path)
            return plugins

        if str(dir_path) not in sys.path:
            sys.path.insert(0, str(dir_path))

        for py_file in sorted(dir_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = py_file.stem
            try:
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = mod
                spec.loader.exec_module(mod)

                for attr_name in dir(mod):
                    obj = getattr(mod, attr_name)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, Plugin)
                        and obj is not Plugin
                    ):
                        if PluginLoader.validate_plugin(obj):
                            plugins.append(obj)
                        else:
                            logger.warning(
                                "Plugin %s in %s failed validation",
                                obj.__name__,
                                py_file,
                            )
            except Exception as exc:
                logger.error("Failed to load plugin from %s: %s", py_file, exc)

        logger.info("Loaded %d plugin(s) from %s", len(plugins), path)
        return plugins

    @staticmethod
    def load_from_package(package_name: str) -> List[Type[Plugin]]:
        """Import an installed package and return discovered ``Plugin`` subclasses."""
        plugins: List[Type[Plugin]] = []
        try:
            mod = importlib.import_module(package_name)
        except ImportError as exc:
            logger.error("Could not import plugin package %s: %s", package_name, exc)
            return plugins

        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if isinstance(obj, type) and issubclass(obj, Plugin) and obj is not Plugin:
                if PluginLoader.validate_plugin(obj):
                    plugins.append(obj)

        if hasattr(mod, "__path__"):
            import pkgutil

            for _importer, sub_name, _is_pkg in pkgutil.walk_packages(
                mod.__path__, prefix=f"{package_name}."
            ):
                try:
                    sub_mod = importlib.import_module(sub_name)
                    for attr_name in dir(sub_mod):
                        obj = getattr(sub_mod, attr_name)
                        if (
                            isinstance(obj, type)
                            and issubclass(obj, Plugin)
                            and obj is not Plugin
                        ):
                            if PluginLoader.validate_plugin(obj):
                                plugins.append(obj)
                except Exception as exc:
                    logger.error(
                        "Failed to import plugin sub-module %s: %s", sub_name, exc
                    )

        logger.info("Loaded %d plugin(s) from package %s", len(plugins), package_name)
        return plugins

    @staticmethod
    def validate_plugin(plugin_class: Type[Any]) -> bool:
        """Check that *plugin_class* properly implements the ``Plugin`` interface."""
        if not (isinstance(plugin_class, type) and issubclass(plugin_class, Plugin)):
            return False

        required_attrs = ("name", "version")
        required_methods = ("init", "start", "stop")

        try:
            instance = plugin_class.__new__(plugin_class)
        except Exception:
            logger.debug("Cannot instantiate %s for validation", plugin_class.__name__)
            return False

        for attr in required_attrs:
            prop = getattr(type(instance), attr, None)
            if prop is None:
                logger.debug(
                    "Plugin %s missing property: %s", plugin_class.__name__, attr
                )
                return False

        for method in required_methods:
            fn = getattr(instance, method, None)
            if fn is None or not callable(fn):
                logger.debug(
                    "Plugin %s missing method: %s", plugin_class.__name__, method
                )
                return False

        return True
