import importlib
import os
import sys
from unittest.mock import patch

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
    # Clear the module from sys.modules to force a fresh import
    if "collector" in sys.modules:
        del sys.modules["collector"]
    mock_producer = object()
    with patch("kafka.KafkaProducer", return_value=mock_producer) as mock_kp:
        import collector

        assert collector.BUS == "kafka"
        assert collector.producer is mock_producer
        mock_kp.assert_called_once()


def test_kafka_disabled_when_bus_unset(monkeypatch):
    monkeypatch.delenv("SENTINEL_BUS", raising=False)
    import collector

    importlib.reload(collector)
    assert collector.BUS == "redis"
    assert collector.producer is None
