"""Integration test: policy-orchestrator → iptables adapter.

Validates that:
1. The iptables adapter creates the SENTINEL chain when iptables is available.
2. A DENY rule for a given source IP is correctly translated to an iptables
   DROP command.
3. The rule is visible in the SENTINEL chain.
4. The rule can be removed cleanly.

These tests are skipped automatically when:
- iptables is not installed, OR
- The test is not running as root (iptables requires root).

In CI, run inside a privileged container or use `--cap-add NET_ADMIN`.
"""

import subprocess
import sys

import pytest

sys.path.insert(0, __file__.rsplit("/tests", 1)[0])

from firewall_adapters.iptables_adapter import IptablesAdapter  # type: ignore[import]
from firewall_adapters.base import FirewallRule, FirewallAction  # type: ignore[import]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iptables_available() -> bool:
    try:
        return subprocess.run(
            ["iptables", "--version"], capture_output=True
        ).returncode == 0
    except FileNotFoundError:
        return False


def _is_root() -> bool:
    import os
    return os.geteuid() == 0


requires_iptables = pytest.mark.skipif(
    not _iptables_available() or not _is_root(),
    reason="iptables integration tests require root and iptables installed",
)

TEST_SOURCE_IP = "198.51.100.99"  # TEST-NET-3 (RFC 5737) — safe for testing


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def adapter():
    """Create a fresh IptablesAdapter; clean up the test rule after the test."""
    adp = IptablesAdapter()
    yield adp
    # Best-effort cleanup
    subprocess.run(
        ["iptables", "-D", IptablesAdapter.CHAIN_NAME,
         "-s", TEST_SOURCE_IP, "-j", "DROP"],
        capture_output=True,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestIptablesAdapterUnit:
    """Unit tests that do NOT require root or iptables installed."""

    def test_name(self):
        adp = IptablesAdapter.__new__(IptablesAdapter)
        adp._rules_cache = {}
        assert adp.name == "iptables"

    def test_build_deny_rule_command(self):
        adp = IptablesAdapter.__new__(IptablesAdapter)
        adp._rules_cache = {}
        rule = FirewallRule(
            id="test-001",
            action=FirewallAction.DENY,
            source_ip=TEST_SOURCE_IP,
        )
        cmd = adp._build_add_command(rule)
        assert "iptables" in cmd
        assert "-j" in cmd
        assert "DROP" in cmd
        assert TEST_SOURCE_IP in cmd

    def test_build_allow_rule_command(self):
        adp = IptablesAdapter.__new__(IptablesAdapter)
        adp._rules_cache = {}
        rule = FirewallRule(
            id="test-002",
            action=FirewallAction.ALLOW,
            source_ip=TEST_SOURCE_IP,
        )
        cmd = adp._build_add_command(rule)
        assert "ACCEPT" in cmd

    def test_translate_rules_returns_list(self):
        adp = IptablesAdapter.__new__(IptablesAdapter)
        adp._rules_cache = {}
        rules = [
            FirewallRule(id="r1", action=FirewallAction.DENY, source_ip=TEST_SOURCE_IP)
        ]
        translated = adp.translate_rules(rules)
        assert isinstance(translated, list)
        assert len(translated) == 1
        assert TEST_SOURCE_IP in str(translated[0])


@requires_iptables
class TestIptablesAdapterIntegration:
    """Integration tests that apply and remove real iptables rules."""

    def test_chain_exists_after_init(self, adapter):
        result = subprocess.run(
            ["iptables", "-L", IptablesAdapter.CHAIN_NAME, "-n"],
            capture_output=True,
        )
        assert result.returncode == 0, (
            f"SENTINEL chain not found:\n{result.stderr.decode()}"
        )

    def test_add_deny_rule(self, adapter):
        rule = FirewallRule(
            id="integ-001",
            action=FirewallAction.DENY,
            source_ip=TEST_SOURCE_IP,
        )
        result = adapter.add_rule(rule)
        assert result["success"], f"add_rule failed: {result}"

        # Confirm the rule appears in the chain
        check = subprocess.run(
            ["iptables", "-C", IptablesAdapter.CHAIN_NAME,
             "-s", TEST_SOURCE_IP, "-j", "DROP"],
            capture_output=True,
        )
        assert check.returncode == 0, "Rule was not inserted into iptables"

    def test_remove_rule(self, adapter):
        rule = FirewallRule(
            id="integ-002",
            action=FirewallAction.DENY,
            source_ip=TEST_SOURCE_IP,
        )
        adapter.add_rule(rule)
        remove_result = adapter.remove_rule("integ-002")
        assert remove_result["success"], f"remove_rule failed: {remove_result}"

        check = subprocess.run(
            ["iptables", "-C", IptablesAdapter.CHAIN_NAME,
             "-s", TEST_SOURCE_IP, "-j", "DROP"],
            capture_output=True,
        )
        assert check.returncode != 0, "Rule still present after removal"

    def test_rate_limit_rule(self, adapter):
        rule = FirewallRule(
            id="integ-003",
            action=FirewallAction.RATE_LIMIT,
            source_ip=TEST_SOURCE_IP,
        )
        result = adapter.add_rule(rule)
        assert result["success"], f"rate-limit rule failed: {result}"
