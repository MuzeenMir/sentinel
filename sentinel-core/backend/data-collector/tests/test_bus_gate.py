import importlib
import os
import sys

# Ensure data-collector/ is on sys.path so `import collector` resolves.
# collector.py itself already inserts backend/ (line 29), so that chain is covered.
_here = os.path.dirname(os.path.abspath(__file__))
_dc_root = os.path.dirname(_here)
if _dc_root not in sys.path:
    sys.path.insert(0, _dc_root)


def test_kafka_disabled_on_node_bus(monkeypatch):
    monkeypatch.setenv("SENTINEL_BUS", "redis")
    import collector
    importlib.reload(collector)
    assert collector.BUS == "redis"
    assert collector.producer is None


def test_kafka_enabled_in_legacy_mode(monkeypatch):
    monkeypatch.setenv("SENTINEL_BUS", "kafka")
    import collector
    importlib.reload(collector)
    assert collector.BUS == "kafka"
