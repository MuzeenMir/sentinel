import importlib.util
import os

MIG = os.path.join(
    os.path.dirname(__file__), "..", "versions", "20260627_001_node_alerts.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("node_alerts_mig", MIG)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_revision_chain():
    mod = _load()
    assert mod.revision == "20260627_001_node_alerts"
    assert mod.down_revision == "20260624_001_audit_chain"


def test_has_upgrade_and_downgrade():
    mod = _load()
    assert callable(mod.upgrade)
    assert callable(mod.downgrade)
