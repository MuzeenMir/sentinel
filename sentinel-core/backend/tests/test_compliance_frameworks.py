"""Unit tests for compliance framework base."""
import sys
from pathlib import Path

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
