"""Unit tests for firewall adapter base classes."""
import sys
from pathlib import Path

# Add firewall-adapters to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "firewall-adapters"))

from base import FirewallRule, FirewallAction


def test_firewall_rule_defaults():
    """FirewallRule has expected default values."""
    rule = FirewallRule()
    assert rule.direction == "ingress"
    assert rule.protocol == "tcp"
    assert rule.action == FirewallAction.DENY
    assert rule.priority == 100
    assert rule.id is not None
    assert len(rule.id) == 8


def test_firewall_rule_to_dict():
    """FirewallRule.to_dict returns all fields."""
    rule = FirewallRule(
        name="block-malicious",
        source_ip="192.168.1.0/24",
        action=FirewallAction.DENY,
    )
    d = rule.to_dict()
    assert d["name"] == "block-malicious"
    assert d["source_ip"] == "192.168.1.0/24"
    assert d["action"] == "deny"
    assert "id" in d
    assert "created_at" in d


def test_firewall_action_values():
    """FirewallAction has expected values."""
    assert FirewallAction.ALLOW.value == "allow"
    assert FirewallAction.DENY.value == "deny"
    assert FirewallAction.RATE_LIMIT.value == "rate_limit"
