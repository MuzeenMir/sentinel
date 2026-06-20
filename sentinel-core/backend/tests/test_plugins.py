"""Smoke tests for the experimental plugin SDK (audit SUB-02 / Wave A6).

The plugin registry is not yet wired into any runtime service, but it is a
real extension SDK and must not ship untested. These tests exercise the full
register -> init -> start -> health -> stop lifecycle via the reference
DNS-tunnel example plugin, plus filesystem discovery.
"""

import os
import sys

import pytest

_backend = os.path.join(os.path.dirname(__file__), "..")
if _backend not in sys.path:
    sys.path.insert(0, _backend)

from plugins.registry import Plugin, PluginRegistry  # noqa: E402
from plugins.examples.example_custom_detector import (  # noqa: E402
    DNSTunnelDetectorPlugin,
)


def test_register_rejects_non_plugin():
    registry = PluginRegistry()
    with pytest.raises(TypeError):
        registry.register(object)


def test_lifecycle_register_init_start_stop():
    registry = PluginRegistry()
    registry.register(DNSTunnelDetectorPlugin)

    # Not running until start_all.
    assert registry.get_plugin("dns_tunnel_detector") is None

    registry.start_all(config={"dns_tunnel_detector": {"entropy_threshold": 3.8}})
    plugin = registry.get_plugin("dns_tunnel_detector")
    assert plugin is not None
    assert plugin.version == "1.0.0"
    assert registry.health_check_all() == {"dns_tunnel_detector": True}

    listing = registry.list_plugins()
    assert listing[0]["name"] == "dns_tunnel_detector"
    assert listing[0]["running"] is True

    registry.stop_all()
    assert registry.health_check_all() == {"dns_tunnel_detector": False}


def test_example_detector_flags_high_entropy_query():
    plugin = DNSTunnelDetectorPlugin()
    plugin.init({"entropy_threshold": 3.0, "min_label_length": 20})
    plugin.start()

    # Benign, low-entropy hostname: no detection.
    assert plugin.analyse_query("www.example.com") is None

    # High-entropy exfil-style label exceeding the min length: flagged.
    tunneled = "a9f3k2m7q1z8x4b6n0w5e2r7t3y1u8.tunnel.evil.test"
    detection = plugin.analyse_query(tunneled, source_ip="10.0.0.9")
    assert detection is not None
    assert detection["event_type"] == "dns_tunnel_suspected"
    assert detection["severity"] == "high"
    assert detection["entropy"] >= 3.0


def test_discovery_from_examples_dir():
    registry = PluginRegistry()
    examples_dir = os.path.join(_backend, "plugins", "examples")
    loaded = registry.discover_plugins(examples_dir)
    assert loaded >= 1
    names = [p["name"] for p in registry.list_plugins()]
    assert "dns_tunnel_detector" in names


class _BrokenPlugin(Plugin):
    @property
    def name(self) -> str:
        return "broken"

    @property
    def version(self) -> str:
        return "0.0.1"

    def init(self, config):
        raise RuntimeError("boom")

    def start(self):  # pragma: no cover - never reached
        pass

    def stop(self):  # pragma: no cover - never reached
        pass


def test_init_failure_disables_plugin_without_raising():
    registry = PluginRegistry()
    registry.register(_BrokenPlugin)
    # A failing init must be contained (logged + disabled), not propagated.
    registry.start_all(config={})
    assert registry.get_plugin("broken") is None
    assert registry.health_check_all() == {"broken": False}
