"""Unit tests for compliance framework base."""
import sys
from pathlib import Path

# region agent log
import json as _agent_json
from datetime import datetime as _agent_dt
import time as _agent_time


def _agent_log_backend_tests(hypothesis_id, message, data):
    """Lightweight debug logger for backend tests (NDJSON to Cursor debug file)."""
    try:
        payload = {
            "sessionId": "ba9959",
            "id": f"log_{int(_agent_time.time() * 1000)}",
            "timestamp": int(_agent_dt.utcnow().timestamp() * 1000),
            "location": "backend/tests/test_compliance_frameworks.py:module_import",
            "message": message,
            "data": data,
            "runId": "pre-fix",
            "hypothesisId": hypothesis_id,
        }
        with open("/home/mir/sentinel/.cursor/debug-ba9959.log", "a") as _f:
            _f.write(_agent_json.dumps(payload) + "\n")
    except Exception:
        # Never let debug logging break tests
        pass


_agent_log_backend_tests(
    "H2",
    "tests_module_imported",
    {"module_name": __name__, "package": __package__},
)
# endregion


# Add compliance-engine to path
backend = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend / "compliance-engine"))

from frameworks.base import BaseFramework


class ConcreteFramework(BaseFramework):
    """Concrete implementation for testing."""
    @property
    def full_name(self):
        return "Test Framework"

    @property
    def description(self):
        return "Test description"

    def _check_requirement(self, req, policies, configs):
        return req in configs.get("met_requirements", [])


def test_base_framework_controls_summary():
    """get_controls_summary returns control list."""
    f = ConcreteFramework()
    f.controls = {
        "ctrl-1": {"name": "Control 1", "category": "Access"},
        "ctrl-2": {"name": "Control 2", "category": "Encryption"},
    }
    summary = f.get_controls_summary()
    assert len(summary) == 2
    assert summary[0]["id"] == "ctrl-1"
    assert summary[0]["name"] == "Control 1"
    assert summary[0]["category"] == "Access"


def test_base_framework_get_categories():
    """get_categories returns unique categories."""
    f = ConcreteFramework()
    f.controls = {
        "c1": {"category": "A"},
        "c2": {"category": "B"},
        "c3": {"category": "A"},
    }
    cats = f.get_categories()
    assert set(cats) == {"A", "B"}


def test_base_framework_assess():
    """assess returns compliance assessments."""
    f = ConcreteFramework()
    f.controls = {
        "c1": {"name": "Req 1", "requirements": ["r1", "r2"]},
    }
    policies = []
    configs = {"met_requirements": ["r1", "r2"]}
    result = f.assess(policies, configs)
    assert len(result) == 1
    assert result[0]["control_id"] == "c1"
    assert result[0]["status"] == "compliant"
    assert result[0]["score"] == 100
